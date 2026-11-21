"""
orchestrator.py — Coordina el flujo completo del respaldo (Persona D).

Este módulo NO hace ninguna operación criptográfica por sí mismo: solo llama
en el orden correcto a los módulos de los demás integrantes.

    Crear:      packaging_ -> crypto_core -> shamir -> formats   (A -> B -> C)
    Restaurar:  formats -> shamir -> crypto_core -> packaging_   (C -> B -> A)

Interfaz pública (Sección 7 del Entregable 1):
    create_backup(input_path, output_dir) -> str
    restore_backup(share_paths, output_path) -> list[tuple[str, str]]
    inspect(path) -> dict

Cambio respecto a la entrega 1: restore_backup devuelve la lista de
participaciones descartadas [(ruta, motivo)] en lugar de None, para que la
CLI pueda informarlas aunque la restauración salga bien (Sección 6.6).

Manejo de la clave: K solo vive en memoria, como bytearray, y se borra con
crypto_core.wipe() apenas se deja de usar. Es una mitigación de mejor
esfuerzo (ver docstring de crypto_core.py): Python puede dejar copias.
"""

from __future__ import annotations

import itertools
import os

import crypto_core as cc
import formats as fm
import packaging_ as pk
import shamir
from exceptions import AuthenticationError, InvalidBlobFormatError


GENERIC_ERROR = (
    "No se pudo verificar el respaldo: el paquete, el manifiesto o las "
    "participaciones están dañados o no corresponden entre sí."
)


class RestoreError(Exception):
    """Clase base de los errores de restauración del orquestador."""


class NotEnoughSharesError(RestoreError):
    """Quedaron menos de 3 participaciones utilizables tras descartar las malas.

    Este error SÍ puede ser detallado: los motivos ("dañada", "duplicada",
    "de otro respaldo") vienen de la capa de formatos, antes de cualquier
    operación criptográfica y sobre datos no secretos.
    """

    def __init__(self, valid_count: int, threshold: int, rejected: list[tuple[str, str]]):
        self.valid_count = valid_count
        self.threshold = threshold
        self.rejected = rejected
        super().__init__(
            f"No hay participaciones suficientes: se necesitan {threshold} "
            f"válidas y solo hay {valid_count}."
        )


class VerificationError(RestoreError):
    """Fallo de verificación. Siempre lleva el mismo mensaje genérico."""

    def __init__(self):
        super().__init__(GENERIC_ERROR)


# --- Crear respaldo -----------------------------------------------------------


def create_backup(input_path: str, output_dir: str) -> str:
    """Crea un respaldo cifrado de `input_path` dentro de `output_dir`.

    Escribe en `output_dir`:
        <backup_id>.evlp             paquete cifrado
        <backup_id>.manifest.json    manifiesto
        <backup_id>.share1..5.json   las cinco participaciones

    Returns:
        El backup_id generado (32 caracteres hexadecimales).

    Raises:
        FileNotFoundError: si `input_path` no existe.
        PayloadTooLargeError: si el contenido supera el límite de 200 MB.
            En ese caso no se escribe nada en disco.
    """
    # 1. Empaquetar (tar+gzip). Aquí se valida el límite de 200 MB, ANTES
    #    de generar la clave o escribir cualquier archivo.
    payload = pk.pack_source(input_path)

    # 2. Cifrar con una clave nueva y repartirla con Shamir 3-de-5.
    backup_id = fm.new_backup_id()
    key = cc.generate_key()
    try:
        blob = cc.encrypt_blob(key, payload, fm.backup_id_to_bytes(backup_id))  # type: ignore[arg-type]
        shares = shamir.split_secret(key, fm.THRESHOLD, fm.TOTAL_SHARES)  # type: ignore[arg-type]
    finally:
        cc.wipe(key)  # la clave ya no hace falta: solo quedan las participaciones
    del payload

    # 3. Escribir los archivos. Si algo falla a mitad de camino, se borran los
    #    que alcanzaron a escribirse para no dejar un respaldo incompleto.
    written: list[str] = []
    try:
        package_path = os.path.join(output_dir, fm.package_filename(backup_id))
        fm.write_package(blob, package_path)
        written.append(package_path)

        manifest_path = os.path.join(output_dir, fm.manifest_filename(backup_id))
        fm.write_manifest(fm.make_manifest(backup_id, blob), manifest_path)
        written.append(manifest_path)

        for index, value in shares:
            share_path = os.path.join(output_dir, fm.share_filename(backup_id, index))
            fm.write_share(fm.make_share(backup_id, index, value), share_path)
            written.append(share_path)
    except BaseException:
        for path in written:
            try:
                os.remove(path)
            except OSError:
                pass
        raise

    return backup_id


# --- Restaurar respaldo -------------------------------------------------------


def restore_backup(share_paths: list[str], output_path: str) -> list[tuple[str, str]]:
    """Restaura un respaldo a partir de las participaciones entregadas.

    El manifiesto y el paquete se buscan automáticamente en la carpeta de las
    participaciones (Sección 6.5). Las participaciones dañadas, repetidas o de
    otro respaldo se descartan y se sigue con las demás (Sección 6.6).

    Returns:
        Lista de participaciones descartadas [(ruta, motivo)]. Vacía si todas
        eran válidas.

    Raises:
        NotEnoughSharesError: si quedan menos de 3 participaciones válidas.
        VerificationError: si el paquete no coincide con el manifiesto o la
            verificación AEAD falla (mensaje genérico).
        FormatError: si el manifiesto está mal formado o no se encuentra.
        ExtractionError: si el contenido no se puede extraer en `output_path`.
    """
    if not share_paths:
        raise NotEnoughSharesError(0, fm.THRESHOLD, [])

    # 1. Formatos (C): identificar el respaldo y leer manifiesto y paquete.
    backup_id = fm.infer_backup_id(share_paths)
    manifest_path, package_path = _locate(share_paths, backup_id)
    manifest = fm.read_manifest(manifest_path)
    blob = fm.read_package(package_path)

    # 2. Coherencia paquete <-> manifiesto, antes de cualquier operación
    #    criptográfica: tamaño, SHA-256 y encabezado del blob.
    if not fm.verify_package(blob, manifest):
        raise VerificationError()
    _check_header(blob, manifest)

    # 3. Descartar participaciones inválidas y comprobar el umbral.
    valid, rejected = fm.load_shares(share_paths, manifest)
    if len(valid) < manifest.threshold:
        raise NotEnoughSharesError(len(valid), manifest.threshold, rejected)

    # 4. Shamir (B) + AEAD (A): reconstruir K y descifrar.
    payload = _reconstruct_and_decrypt(valid, blob, manifest)

    # 5. Extraer solo después de una verificación AEAD exitosa (Sección 4.2).
    pk.unpack_output(payload, output_path)
    return rejected


def _locate(share_paths: list[str], backup_id: str) -> tuple[str, str]:
    """Busca manifiesto y paquete en las carpetas de las participaciones.

    Se prueba cada carpeta en el orden en que aparecen las participaciones;
    se usa la primera que contenga ambos archivos.
    """
    folders: list[str] = []
    for path in share_paths:
        folder = os.path.dirname(os.path.abspath(path))
        if folder not in folders:
            folders.append(folder)

    for folder in folders[:-1]:
        try:
            return fm.locate_files(folder, backup_id)
        except fm.FormatError:
            continue  # probar la siguiente carpeta
    return fm.locate_files(folders[-1], backup_id)


def _check_header(blob: bytes, manifest: fm.Manifest) -> None:
    """La versión y el algoritmo del encabezado deben coincidir con el manifiesto."""
    try:
        header = cc.parse_header(blob)
    except InvalidBlobFormatError:
        raise VerificationError() from None
    if header["version"] != manifest.version or header["algorithm"] != manifest.algorithm:
        raise VerificationError()


def _reconstruct_and_decrypt(valid: list[fm.ShareFile], blob: bytes, manifest: fm.Manifest) -> bytes:
    """Prueba los subconjuntos de 3 participaciones hasta que AEAD verifique.

    Con participaciones sanas el primer intento funciona. Si hay una alterada
    con su checksum recalculado (el checksum no es un MAC), la terna que la
    incluye falla y se prueba la siguiente. Con 5 participaciones son como
    máximo C(5, 3) = 10 intentos.
    """
    aad_id = fm.backup_id_to_bytes(manifest.backup_id)
    for combo in itertools.combinations(valid, manifest.threshold):
        points = [(s.index, s.value) for s in combo]
        try:
            key = bytearray(shamir.reconstruct_secret(points, manifest.threshold))
        except shamir.ShamirError:
            continue  # la terna da una clave imposible: alguna está alterada
        try:
            return cc.decrypt_blob(key, blob, aad_id)  # type: ignore[arg-type]
        except AuthenticationError:
            continue  # clave incorrecta: probar con otra terna
        finally:
            cc.wipe(key)
    raise VerificationError()


# --- Inspector ------------------------------------------------------------------


def inspect(path: str) -> dict:
    """Metadatos NO secretos de una participación, un manifiesto o un paquete.

    Nunca muestra el valor de una participación ni la clave. Para el paquete
    cifrado solo lee el encabezado (no descifra nada).

    Raises:
        FormatError / InvalidBlobFormatError: si el archivo no es reconocido.
    """
    if path.endswith(".evlp"):
        info = cc.parse_header(fm.read_package(path))
        info["type"] = "package"
        return info
    return fm.inspect_file(path)


def check_share_group(paths: list[str]) -> dict:
    """Revisa un grupo de participaciones sin reconstruir la clave.

    Es la parte del inspector que mira las participaciones en conjunto:
    advierte si se mezclan respaldos distintos, si hay índices repetidos y si
    alguna está dañada, y dice si cada respaldo alcanza el umbral. Solo usa
    metadatos no secretos; nunca muestra el valor de una participación.
    Los archivos que no son participaciones (manifiesto, paquete) se ignoran.

    Returns:
        {"resumen": [líneas informativas], "advertencias": [líneas de alerta]}
    """
    shares: list[tuple[str, fm.ShareFile]] = []
    advertencias: list[str] = []
    for path in paths:
        try:
            info = fm.inspect_file(path)
        except (fm.FormatError, OSError):
            continue  # no es una participación legible: ya se informa por archivo
        if info["type"] != "share":
            continue
        if not info["checksum_ok"]:
            advertencias.append(f"Participación dañada (el checksum no coincide): {path}")
            continue
        shares.append((path, fm.read_share(path)))

    backup_ids = sorted({share.backup_id for _, share in shares})
    if len(backup_ids) > 1:
        advertencias.append(
            f"Se mezclan participaciones de {len(backup_ids)} respaldos distintos; "
            "solo las del mismo respaldo sirven juntas."
        )

    resumen: list[str] = []
    for backup_id in backup_ids:
        del_respaldo = [share for _, share in shares if share.backup_id == backup_id]
        for index in fm.find_duplicate_indices(del_respaldo):
            rutas = [p for p, s in shares if s.backup_id == backup_id and s.index == index]
            advertencias.append(f"Índice {index} repetido en {len(rutas)} archivos: {', '.join(rutas)}")
        indices = sorted({share.index for share in del_respaldo})
        alcanza = "alcanza" if len(indices) >= fm.THRESHOLD else "NO alcanza"
        resumen.append(
            f"Respaldo {backup_id}: índices {indices}; "
            f"{alcanza} el umbral de {fm.THRESHOLD}."
        )
    return {"resumen": resumen, "advertencias": advertencias}