"""
formats.py — Formatos en disco: manifiesto, archivo de participación y paquete.

Responsabilidad de este módulo (Persona C):
    - Definir cómo se ve cada archivo del respaldo en disco: manifiesto,
      participación (share) y paquete cifrado.
    - Serializarlos de forma inequívoca y versionada (JSON estricto en UTF-8
      para manifiesto y participaciones; binario para el paquete cifrado).
    - Calcular y validar los checksums (SHA-256) que detectan daño accidental.
    - Decidir qué participaciones son utilizables: dañadas, duplicadas o de
      otro respaldo se descartan ANTES de intentar reconstruir la clave.

Este módulo NO sabe nada sobre:
    - cómo se genera la clave ni cómo se cifra (crypto_core.py),
    - cómo se reparte o reconstruye la clave (shamir.py),
    - cómo se empaqueta el archivo del usuario (packaging_.py).
No importa ninguno de ellos: los valores fijos que necesita (66 bytes, p,
"shamir-zp-m521", 34 bytes de sobrecosto) se declaran aquí como constantes y
se contrastan con los otros módulos en tests/test_formats.py.

IMPORTANTE — el checksum NO es un MAC. Cualquiera puede recalcularlo, así
que solo detecta errores accidentales (transcripción, truncamiento,
corrupción). La aceptación final del respaldo depende siempre de la
verificación AEAD (crypto_core.decrypt_blob).

Convención de archivos dentro de una carpeta de respaldo:
    <backup_id>.manifest.json    manifiesto (sin secretos)
    <backup_id>.evlp             paquete cifrado (blob de crypto_core)
    <backup_id>.share<i>.json    participación i (i = 1..5), una por custodio
donde backup_id son los 16 bytes del UUID en hexadecimal minúscula
(32 caracteres): bytes.fromhex(backup_id) es el `backup_id` crudo que
esperan encrypt_blob/decrypt_blob.

Ningún valor de participación se imprime en repr(), en mensajes de error ni
en el inspector.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

__all__ = [
    "FormatError",
    "Manifest",
    "ShareFile",
    "new_backup_id",
    "backup_id_to_bytes",
    "package_checksum",
    "compute_share_checksum",
    "make_manifest",
    "make_share",
    "write_manifest",
    "read_manifest",
    "write_share",
    "read_share",
    "write_package",
    "read_package",
    "verify_package",
    "validate_share",
    "diagnose_share",
    "find_duplicate_indices",
    "load_shares",
    "infer_backup_id",
    "locate_files",
    "inspect_file",
    "manifest_filename",
    "package_filename",
    "share_filename",
    "REASON_DAMAGED",
    "REASON_DUPLICATE",
    "REASON_OTHER_BACKUP",
]

# --- Constantes del formato (versión 1) -------------------------------------

MANIFEST_FORMAT: str = "EVLP-MANIFEST"
SHARE_FORMAT: str = "EVLP-SHARE"
FORMAT_VERSION: int = 1
ALGORITHM_NAME: str = "ChaCha20-Poly1305"  # = crypto_core.ALGORITHM_NAMES[0x01]
SHARING_SCHEME: str = "shamir-zp-m521"  # = shamir.SHARING_SCHEME

THRESHOLD: int = 3
TOTAL_SHARES: int = 5

SHARE_VALUE_SIZE: int = 66  # = shamir.SHARE_VALUE_SIZE = ceil(521 / 8)
FIELD_PRIME: int = (1 << 521) - 1  # = shamir.P; todo valor de share es < p

BACKUP_ID_SIZE: int = 16
MIN_BLOB_SIZE: int = 34  # = crypto_core.FORMAT_OVERHEAD (payload vacío)
MAX_BLOB_SIZE: int = 200 * 1024 * 1024 + MIN_BLOB_SIZE  # payload ≤ 200 MB + sobrecosto
MAX_JSON_SIZE: int = 64 * 1024  # tope de lectura para manifiesto y participaciones

CHECKSUM_PREFIX: str = "sha256:"
SHARE_CHECKSUM_DOMAIN: bytes = b"EVLP-SHARE-CHK"
_HASH_CHUNK: int = 1024 * 1024  # 1 MiB

# Motivos con los que se informa un rechazo de participación.
REASON_DAMAGED: str = "dañada"
REASON_DUPLICATE: str = "duplicada"
REASON_OTHER_BACKUP: str = "de otro respaldo"

_HEX_ID_RE = re.compile(r"[0-9a-f]{32}")
_HEX_VALUE_RE = re.compile(r"[0-9a-f]{%d}" % (2 * SHARE_VALUE_SIZE))
_CHECKSUM_RE = re.compile(r"sha256:[0-9a-f]{64}")
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

_MANIFEST_FIELDS = (
    "format", "version", "backup_id", "created_at", "algorithm",
    "sharing_scheme", "threshold", "total_shares", "package_size",
    "package_checksum",
)
_SHARE_FIELDS = (
    "format", "version", "backup_id", "index", "threshold", "total_shares",
    "sharing_scheme", "value", "checksum",
)


class FormatError(ValueError):
    """Archivo mal formado, de versión no soportada o con campos inválidos.

    Hereda de ValueError (como los errores de shamir.py y crypto_core.py).
    Los mensajes nunca incluyen el valor de una participación.
    """


# --- Estructuras de datos -----------------------------------------------------


@dataclass
class Manifest:
    """Metadatos NO secretos de un respaldo. No contiene K ni participaciones."""

    backup_id: str  # 32 hex minúsculas (UUID de 16 bytes)
    version: int  # versión del formato (1)
    algorithm: str  # "ChaCha20-Poly1305"
    threshold: int  # 3
    total_shares: int  # 5
    created_at: str  # ISO 8601 UTC, p. ej. "2026-09-14T15:30:00Z" (informativo)
    package_size: int  # bytes del paquete cifrado completo
    package_checksum: str  # "sha256:" + SHA-256 del paquete cifrado
    sharing_scheme: str = SHARING_SCHEME


@dataclass
class ShareFile:
    """Una participación (índice, valor) más los metadatos para validarla."""

    backup_id: str
    version: int
    index: int  # 1..5, nunca 0
    threshold: int
    total_shares: int
    value: bytes = field(repr=False)  # f(i): 66 bytes big-endian; nunca se imprime
    checksum: str  # "sha256:" + SHA-256 de los campos (ver compute_share_checksum)
    sharing_scheme: str = SHARING_SCHEME


# --- Validación de campos -----------------------------------------------------


def _is_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _check_backup_id(v: object) -> None:
    if not isinstance(v, str) or not _HEX_ID_RE.fullmatch(v):
        raise FormatError("backup_id debe ser una cadena hexadecimal minúscula de 32 caracteres.")


def _check_version(v: object) -> None:
    if not _is_int(v) or v != FORMAT_VERSION:
        raise FormatError(f"Versión de formato no soportada (se esperaba {FORMAT_VERSION}).")


def _check_params(threshold: object, total: object, scheme: object) -> None:
    if not _is_int(threshold) or threshold != THRESHOLD:
        raise FormatError(f"threshold debe ser {THRESHOLD} en la versión {FORMAT_VERSION}.")
    if not _is_int(total) or total != TOTAL_SHARES:
        raise FormatError(f"total_shares debe ser {TOTAL_SHARES} en la versión {FORMAT_VERSION}.")
    if scheme != SHARING_SCHEME:
        raise FormatError("sharing_scheme desconocido.")


def _check_index(v: object) -> None:
    if not _is_int(v) or not 1 <= v <= TOTAL_SHARES:
        raise FormatError(f"index debe ser un entero entre 1 y {TOTAL_SHARES} (0 está prohibido).")


def _check_value(v: object) -> None:
    if not isinstance(v, bytes) or len(v) != SHARE_VALUE_SIZE:
        raise FormatError(f"value debe ser bytes de exactamente {SHARE_VALUE_SIZE} bytes.")
    if int.from_bytes(v, "big") >= FIELD_PRIME:
        raise FormatError("value está fuera de Z_p (>= p).")


def _check_checksum(v: object) -> None:
    if not isinstance(v, str) or not _CHECKSUM_RE.fullmatch(v):
        raise FormatError('checksum debe tener la forma "sha256:" + 64 hexadecimales minúsculas.')


def _check_manifest_fields(m: Manifest) -> None:
    _check_backup_id(m.backup_id)
    _check_version(m.version)
    if m.algorithm != ALGORITHM_NAME:
        raise FormatError("algorithm desconocido.")
    _check_params(m.threshold, m.total_shares, m.sharing_scheme)
    if (
        not isinstance(m.created_at, str)
        or not _TIMESTAMP_RE.fullmatch(m.created_at)
    ):
        raise FormatError('created_at debe ser ISO 8601 UTC, p. ej. "2026-09-14T15:30:00Z".')
    try:
        datetime.strptime(m.created_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise FormatError("created_at no es una fecha válida.") from None
    if not _is_int(m.package_size) or not MIN_BLOB_SIZE <= m.package_size <= MAX_BLOB_SIZE:
        raise FormatError(
            f"package_size debe estar entre {MIN_BLOB_SIZE} y {MAX_BLOB_SIZE} bytes."
        )
    _check_checksum(m.package_checksum)


def _check_share_fields(s: ShareFile) -> None:
    _check_backup_id(s.backup_id)
    _check_version(s.version)
    _check_params(s.threshold, s.total_shares, s.sharing_scheme)
    _check_index(s.index)
    _check_value(s.value)
    _check_checksum(s.checksum)


# --- Identificador, checksums y constructores ---------------------------------


def new_backup_id() -> str:
    """Nuevo identificador de respaldo: UUID v4 en hexadecimal (32 caracteres)."""
    return uuid.uuid4().hex


def backup_id_to_bytes(backup_id: str) -> bytes:
    """Los 16 bytes crudos que esperan encrypt_blob/decrypt_blob (AAD)."""
    _check_backup_id(backup_id)
    return bytes.fromhex(backup_id)


def package_checksum(blob: bytes) -> str:
    """'sha256:' + SHA-256 del paquete cifrado completo, leído por bloques de 1 MiB."""
    h = hashlib.sha256()
    view = memoryview(blob)
    for start in range(0, len(view), _HASH_CHUNK):
        h.update(view[start:start + _HASH_CHUNK])
    return CHECKSUM_PREFIX + h.hexdigest()


def compute_share_checksum(
    backup_id: str,
    version: int,
    index: int,
    threshold: int,
    total_shares: int,
    value: bytes,
) -> str:
    """SHA-256(DOMINIO ‖ VERSION ‖ BACKUP_ID ‖ INDEX ‖ THRESHOLD ‖ TOTAL ‖ VALUE).

    Todos los campos son bytes de ancho fijo (1 + 16 + 1 + 1 + 1 + 66), por lo
    que la entrada es inequívoca y no depende del orden de claves ni de los
    espacios del archivo JSON. Solo detecta daño accidental (no es un MAC).
    """
    _check_version(version)
    _check_backup_id(backup_id)
    _check_index(index)
    _check_params(threshold, total_shares, SHARING_SCHEME)
    _check_value(value)
    h = hashlib.sha256()
    h.update(SHARE_CHECKSUM_DOMAIN)
    h.update(bytes([version]))
    h.update(bytes.fromhex(backup_id))
    h.update(bytes([index, threshold, total_shares]))
    h.update(value)
    return CHECKSUM_PREFIX + h.hexdigest()


def make_manifest(
    backup_id: str,
    blob: bytes,
    *,
    created_at: Optional[str] = None,
    algorithm: str = ALGORITHM_NAME,
) -> Manifest:
    """Manifiesto de un respaldo recién cifrado. Calcula tamaño y checksum del blob."""
    if created_at is None:
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = Manifest(
        backup_id=backup_id,
        version=FORMAT_VERSION,
        algorithm=algorithm,
        threshold=THRESHOLD,
        total_shares=TOTAL_SHARES,
        created_at=created_at,
        package_size=len(blob),
        package_checksum=package_checksum(blob),
    )
    _check_manifest_fields(manifest)
    return manifest


def make_share(
    backup_id: str,
    index: int,
    value: bytes,
    *,
    threshold: int = THRESHOLD,
    total_shares: int = TOTAL_SHARES,
) -> ShareFile:
    """Participación lista para escribir. Valida campos y calcula el checksum.

    `index` y `value` son exactamente lo que devuelve shamir.split_secret
    para cada participación: (1..5, 66 bytes).
    """
    if isinstance(value, (bytearray, memoryview)):
        value = bytes(value)
    checksum = compute_share_checksum(backup_id, FORMAT_VERSION, index, threshold, total_shares, value)
    return ShareFile(
        backup_id=backup_id,
        version=FORMAT_VERSION,
        index=index,
        threshold=threshold,
        total_shares=total_shares,
        value=value,
        checksum=checksum,
    )


# --- Nombres de archivo ---------------------------------------------------------


def manifest_filename(backup_id: str) -> str:
    _check_backup_id(backup_id)
    return f"{backup_id}.manifest.json"


def package_filename(backup_id: str) -> str:
    _check_backup_id(backup_id)
    return f"{backup_id}.evlp"


def share_filename(backup_id: str, index: int) -> str:
    _check_backup_id(backup_id)
    _check_index(index)
    return f"{backup_id}.share{index}.json"


# --- Serialización JSON estricta ------------------------------------------------


def _manifest_to_dict(m: Manifest) -> dict:
    return {
        "format": MANIFEST_FORMAT,
        "version": m.version,
        "backup_id": m.backup_id,
        "created_at": m.created_at,
        "algorithm": m.algorithm,
        "sharing_scheme": m.sharing_scheme,
        "threshold": m.threshold,
        "total_shares": m.total_shares,
        "package_size": m.package_size,
        "package_checksum": m.package_checksum,
    }


def _share_to_dict(s: ShareFile) -> dict:
    return {
        "format": SHARE_FORMAT,
        "version": s.version,
        "backup_id": s.backup_id,
        "index": s.index,
        "threshold": s.threshold,
        "total_shares": s.total_shares,
        "sharing_scheme": s.sharing_scheme,
        "value": s.value.hex(),
        "checksum": s.checksum,
    }


def _no_duplicate_keys(pairs: list) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise FormatError("El archivo contiene una clave JSON duplicada.")
        out[key] = value
    return out


def _reject_constant(_name: str):
    raise FormatError("El archivo contiene una constante JSON no permitida.")


def _load_json(path: str) -> dict:
    with open(path, "rb") as f:
        raw = f.read(MAX_JSON_SIZE + 1)
    if len(raw) > MAX_JSON_SIZE:
        raise FormatError(f"El archivo excede {MAX_JSON_SIZE} bytes: no es un manifiesto ni una participación.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise FormatError("El archivo no es UTF-8 válido.") from None
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant)
    except FormatError:
        raise
    except (ValueError, RecursionError):
        raise FormatError("El archivo no es JSON válido.") from None
    if not isinstance(data, dict):
        raise FormatError("El archivo debe contener un objeto JSON.")
    return data


def _expect_fields(data: dict, expected: tuple, what: str) -> None:
    missing = [k for k in expected if k not in data]
    extra = [k for k in data if k not in expected]
    if missing:
        raise FormatError(f"Faltan campos en {what}: {', '.join(missing)}.")
    if extra:
        raise FormatError(f"{what.capitalize()} con {len(extra)} campo(s) desconocido(s).")


def _manifest_from_dict(data: dict) -> Manifest:
    _expect_fields(data, _MANIFEST_FIELDS, "el manifiesto")
    if data["format"] != MANIFEST_FORMAT:
        raise FormatError("El archivo no es un manifiesto EVLP.")
    _check_version(data["version"])
    manifest = Manifest(
        backup_id=data["backup_id"],
        version=data["version"],
        algorithm=data["algorithm"],
        threshold=data["threshold"],
        total_shares=data["total_shares"],
        created_at=data["created_at"],
        package_size=data["package_size"],
        package_checksum=data["package_checksum"],
        sharing_scheme=data["sharing_scheme"],
    )
    _check_manifest_fields(manifest)
    return manifest


def _share_from_dict(data: dict) -> ShareFile:
    _expect_fields(data, _SHARE_FIELDS, "la participación")
    if data["format"] != SHARE_FORMAT:
        raise FormatError("El archivo no es una participación EVLP.")
    _check_version(data["version"])
    hex_value = data["value"]
    if not isinstance(hex_value, str) or not _HEX_VALUE_RE.fullmatch(hex_value):
        raise FormatError(
            f"value debe ser una cadena hexadecimal minúscula de {2 * SHARE_VALUE_SIZE} caracteres."
        )
    share = ShareFile(
        backup_id=data["backup_id"],
        version=data["version"],
        index=data["index"],
        threshold=data["threshold"],
        total_shares=data["total_shares"],
        value=bytes.fromhex(hex_value),
        checksum=data["checksum"],
        sharing_scheme=data["sharing_scheme"],
    )
    _check_share_fields(share)
    return share


def _dump(data: dict) -> bytes:
    return (json.dumps(data, indent=2) + "\n").encode("utf-8")


def _atomic_write(path: str, data: bytes, mode: int) -> None:
    """Escribe en un temporal del mismo directorio y lo renombra (todo o nada)."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --- Lectura y escritura de archivos ----------------------------------------------


def write_manifest(manifest: Manifest, path: str) -> None:
    """Escribe el manifiesto como JSON (permisos 0644 en POSIX). Valida antes de escribir."""
    _check_manifest_fields(manifest)
    _atomic_write(path, _dump(_manifest_to_dict(manifest)), 0o644)


def read_manifest(path: str) -> Manifest:
    """Lee y valida un manifiesto. Lanza FormatError si algo no cumple el formato."""
    return _manifest_from_dict(_load_json(path))


def write_share(share: ShareFile, path: str) -> None:
    """Escribe una participación como JSON con permisos 0600 en POSIX.

    Valida campos y rangos, pero no exige que el checksum coincida: eso lo
    comprueba diagnose_share, y así las pruebas pueden fabricar daño.
    """
    _check_share_fields(share)
    _atomic_write(path, _dump(_share_to_dict(share)), 0o600)


def read_share(path: str) -> ShareFile:
    """Lee una participación validando estructura y rangos (no el checksum).

    Para saber si es utilizable use validate_share/diagnose_share.
    """
    return _share_from_dict(_load_json(path))


def write_package(blob: bytes, path: str) -> None:
    """Escribe el paquete cifrado (binario) de forma atómica."""
    if not MIN_BLOB_SIZE <= len(blob) <= MAX_BLOB_SIZE:
        raise FormatError(f"El paquete debe medir entre {MIN_BLOB_SIZE} y {MAX_BLOB_SIZE} bytes.")
    _atomic_write(path, bytes(blob), 0o644)


def read_package(path: str) -> bytes:
    """Lee el paquete cifrado completo; rechaza archivos de tamaño imposible."""
    size = os.path.getsize(path)
    if not MIN_BLOB_SIZE <= size <= MAX_BLOB_SIZE:
        raise FormatError(f"El paquete debe medir entre {MIN_BLOB_SIZE} y {MAX_BLOB_SIZE} bytes.")
    with open(path, "rb") as f:
        return f.read()


# --- Validación de paquete y participaciones --------------------------------------


def verify_package(blob: bytes, manifest: Manifest) -> bool:
    """True si el tamaño y el SHA-256 del paquete coinciden con el manifiesto.

    Detecta daño accidental. NO verifica autenticidad ni cruza VERSION/ALG_ID
    del encabezado con el manifiesto: eso lo hace el orquestador con
    crypto_core.parse_header(blob) y, sobre todo, la verificación AEAD.
    """
    if len(blob) != manifest.package_size:
        return False
    return hmac.compare_digest(package_checksum(blob), manifest.package_checksum)


def diagnose_share(share: ShareFile, manifest: Manifest) -> Optional[str]:
    """None si la participación es utilizable; si no, el motivo del rechazo.

    Orden de las comprobaciones:
        1. campos y rangos válidos y checksum correcto  -> "dañada"
        2. backup_id igual al del manifiesto            -> "de otro respaldo"
        3. versión/umbral/total/esquema iguales         -> "dañada"
    El checksum va primero porque un backup_id alterado por accidente es daño,
    no una mezcla de respaldos; una participación sana de otro respaldo pasa
    el paso 1 y se rechaza en el 2.
    """
    try:
        _check_share_fields(share)
        expected = compute_share_checksum(
            share.backup_id, share.version, share.index,
            share.threshold, share.total_shares, share.value,
        )
    except (FormatError, AttributeError, TypeError):
        return REASON_DAMAGED
    if not hmac.compare_digest(expected, share.checksum):
        return REASON_DAMAGED
    if share.backup_id != manifest.backup_id:
        return REASON_OTHER_BACKUP
    if (
        share.version != manifest.version
        or share.threshold != manifest.threshold
        or share.total_shares != manifest.total_shares
        or share.sharing_scheme != manifest.sharing_scheme
    ):
        return REASON_DAMAGED
    return None


def validate_share(share: ShareFile, manifest: Manifest) -> bool:
    """True si la participación pertenece a este respaldo y no está dañada."""
    return diagnose_share(share, manifest) is None


def find_duplicate_indices(shares: Iterable[ShareFile]) -> list[int]:
    """Índices que aparecen en más de una participación (ordenados)."""
    counts = Counter(s.index for s in shares)
    return sorted(i for i, n in counts.items() if n > 1)


def load_shares(
    paths: Iterable[str], manifest: Manifest
) -> tuple[list[ShareFile], list[tuple[str, str]]]:
    """Lee participaciones y separa las utilizables de las rechazadas.

    Implementa la "tolerancia ante participaciones no válidas": una dañada,
    repetida o de otro respaldo se descarta con su motivo y se sigue con las
    demás; el orquestador decide si quedan al menos 3.

    Returns:
        (válidas, rechazadas): `válidas` tiene a lo sumo una participación por
        índice (la primera que apareció); `rechazadas` es [(ruta, motivo)]
        con motivo REASON_DAMAGED, REASON_DUPLICATE o REASON_OTHER_BACKUP.
        Los motivos nunca incluyen el contenido del archivo.

    Un archivo inexistente propaga FileNotFoundError (error de uso, no de formato).
    """
    candidates: list[tuple[str, ShareFile]] = []
    rejected: list[tuple[str, str]] = []
    for path in paths:
        path = os.fspath(path)
        try:
            share = read_share(path)
        except FormatError:
            rejected.append((path, REASON_DAMAGED))
            continue
        reason = diagnose_share(share, manifest)
        if reason is not None:
            rejected.append((path, reason))
        else:
            candidates.append((path, share))

    valid: list[ShareFile] = []
    seen: set[int] = set()
    for path, share in candidates:
        if share.index in seen:
            rejected.append((path, REASON_DUPLICATE))
        else:
            seen.add(share.index)
            valid.append(share)
    return valid, rejected


def infer_backup_id(paths: Iterable[str]) -> str:
    """backup_id al que pertenecen la mayoría de las participaciones legibles.

    Sirve para encontrar el manifiesto cuando el usuario solo entrega
    participaciones. Ignora archivos ilegibles y cuenta cada (backup_id, index)
    una sola vez. Falla si no hay ninguna legible o si hay un empate.
    """
    seen: set[tuple[str, int]] = set()
    for path in paths:
        try:
            share = read_share(os.fspath(path))
        except FormatError:
            continue
        seen.add((share.backup_id, share.index))
    if not seen:
        raise FormatError("Ninguna de las participaciones entregadas se pudo leer.")
    ranking = Counter(bid for bid, _ in seen).most_common()
    if len(ranking) > 1 and ranking[0][1] == ranking[1][1]:
        raise FormatError("Las participaciones pertenecen a respaldos distintos y no hay mayoría clara.")
    return ranking[0][0]


def locate_files(directory: str, backup_id: Optional[str] = None) -> tuple[str, str]:
    """Rutas (manifiesto, paquete) de un respaldo dentro de `directory`.

    Si no se da `backup_id`, se usa el único manifiesto de la carpeta; con
    cero o varios falla. Si falta alguno de los dos archivos, el error dice
    cuál.
    """
    if backup_id is None:
        suffix = ".manifest.json"
        found = [
            name[: -len(suffix)]
            for name in sorted(os.listdir(directory))
            if name.endswith(suffix) and _HEX_ID_RE.fullmatch(name[: -len(suffix)])
        ]
        if len(found) != 1:
            raise FormatError(
                f"Se esperaba un único manifiesto en la carpeta y hay {len(found)}; "
                "indique el backup_id."
            )
        backup_id = found[0]
    manifest_path = os.path.join(directory, manifest_filename(backup_id))
    package_path = os.path.join(directory, package_filename(backup_id))
    missing = [
        os.path.basename(p) for p in (manifest_path, package_path) if not os.path.isfile(p)
    ]
    if missing:
        raise FormatError("No se encontró en la carpeta: " + ", ".join(missing) + ".")
    return manifest_path, package_path


def inspect_file(path: str) -> dict:
    """Metadatos NO secretos de un manifiesto o una participación.

    Nunca incluye el valor de la participación. Para una participación añade
    `checksum_ok` (¿el checksum guardado coincide con el recalculado?).

    Raises:
        FormatError: si el archivo no es un manifiesto ni una participación válidos.
    """
    data = _load_json(path)
    kind = data.get("format")
    if kind == MANIFEST_FORMAT:
        info = _manifest_to_dict(_manifest_from_dict(data))
        info["type"] = "manifest"
        return info
    if kind == SHARE_FORMAT:
        share = _share_from_dict(data)
        info = _share_to_dict(share)
        del info["value"]
        info["type"] = "share"
        expected = compute_share_checksum(
            share.backup_id, share.version, share.index,
            share.threshold, share.total_shares, share.value,
        )
        info["checksum_ok"] = hmac.compare_digest(expected, share.checksum)
        return info
    raise FormatError("Tipo de archivo no reconocido.")
