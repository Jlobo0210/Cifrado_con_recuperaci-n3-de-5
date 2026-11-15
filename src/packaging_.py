"""
packaging_.py — Empaquetado del contenido a respaldar.

Convierte un archivo o directorio en un único stream de bytes (tar+gzip)
apto para ser pasado a crypto_core.encrypt_blob(), y reconstruye el
árbol de archivos original a partir de ese stream durante la restauración.
"""

from __future__ import annotations

import io
import os
import shutil
import tarfile
import tempfile
import zlib

from exceptions import ExtractionError, PayloadTooLargeError

# --- Límites de tamaño (Sección 6 del Entregable 1) -------------------------

# Límite autoritativo: tamaño máximo del payload YA empaquetado (tar+gzip),
# que es lo que efectivamente se cifra y persiste.
MAX_PACKAGE_SIZE: int = 200 * 1024 * 1024  # 200 MB

# Límite preliminar: rechazo rápido sobre el tamaño en disco del origen,
# antes de gastar tiempo empaquetando algo evidentemente inviable.
PRELIMINARY_SIZE_HINT: int = 400 * 1024 * 1024  # 400 MB


def pack_source(path: str) -> bytes:
    """Empaqueta un archivo o directorio en un único stream tar+gzip.

    Un archivo individual también se envuelve en un tar de un solo
    miembro, para preservar el nombre original y mantener un único
    formato de entrada hacia crypto_core.encrypt_blob().

    Args:
        path: ruta a un archivo o directorio existente.

    Returns:
        Los bytes del stream tar+gzip resultante.

    Raises:
        PayloadTooLargeError: si el tamaño en disco del origen excede
            PRELIMINARY_SIZE_HINT, o si el payload ya empaquetado excede
            MAX_PACKAGE_SIZE. Es también un ValueError.
        FileNotFoundError: si `path` no existe.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"No existe la ruta de origen: {path}")

    on_disk_size = _get_size_recursive(path)
    if on_disk_size > PRELIMINARY_SIZE_HINT:
        raise PayloadTooLargeError(
            f"Entrada demasiado grande ({on_disk_size} bytes): "
            f"excede el umbral preliminar de {PRELIMINARY_SIZE_HINT} bytes."
        )

    arcname = os.path.basename(os.path.abspath(path))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        tar.add(path, arcname=arcname)
    payload = buffer.getvalue()

    if len(payload) > MAX_PACKAGE_SIZE:
        raise PayloadTooLargeError(
            f"Respaldo empaquetado ({len(payload)} bytes) excede el "
            f"límite de {MAX_PACKAGE_SIZE} bytes."
        )

    return payload


def unpack_output(payload: bytes, output_dir: str) -> None:
    """Extrae un stream tar+gzip descifrado hacia `output_dir`.

    Preserva la estructura de directorios, los nombres y los bits de
    ejecución de los archivos originales.

    La extracción es "todo o nada":
        1. Se valida cada entrada del tar ANTES de escribir nada.
        2. Se extrae en un directorio temporal dentro de `output_dir`.
        3. Solo si todo salió bien, se mueven las entradas al destino.
    Si algo falla, se borra el directorio temporal y `output_dir` queda
    exactamente como estaba (nunca hay restauraciones a medias).

    Nota de seguridad: se usa el filtro "data" de tarfile (Python 3.12+ y
    parches de seguridad de 3.8-3.11), que rechaza rutas absolutas, symlinks
    peligrosos y path traversal (p. ej. "../../etc/passwd"). Además, este
    módulo hace su propia validación (_check_member), de modo que la
    protección no depende solo de la versión de Python instalada.

    Args:
        payload: bytes del stream tar+gzip (ya descifrado y autenticado).
        output_dir: directorio donde se extraerá el contenido. Se crea
            si no existe.

    Raises:
        ExtractionError: si el tar/gzip está dañado, contiene entradas
            peligrosas, o alguna entrada ya existe en `output_dir`
            (no se sobrescriben archivos del usuario).
    """
    os.makedirs(output_dir, exist_ok=True)
    staging = tempfile.mkdtemp(prefix=".restaurando-", dir=output_dir)
    try:
        try:
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
                members = tar.getmembers()
                for member in members:
                    _check_member(member)
                if hasattr(tarfile, "data_filter"):
                    tar.extractall(path=staging, members=members, filter="data")
                else:  # pragma: no cover - solo en Python sin el filtro "data"
                    tar.extractall(path=staging, members=members)
        except ExtractionError:
            raise
        except (tarfile.TarError, EOFError, zlib.error, OSError) as exc:
            raise ExtractionError(
                f"No se pudo extraer el contenido restaurado: {exc}"
            ) from exc

        entries = os.listdir(staging)
        conflicts = [e for e in entries if os.path.lexists(os.path.join(output_dir, e))]
        if conflicts:
            raise ExtractionError(
                "El destino ya contiene: " + ", ".join(sorted(conflicts))
                + ". Elija un directorio vacío; no se sobrescriben archivos."
            )
        for entry in entries:
            os.replace(os.path.join(staging, entry), os.path.join(output_dir, entry))
    finally:
        shutil.rmtree(staging, ignore_errors=True)


# --- Helpers internos --------------------------------------------------------

def _get_size_recursive(path: str) -> int:
    """Tamaño en disco de un archivo, o suma recursiva de un directorio."""
    if os.path.isfile(path):
        return os.path.getsize(path)

    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            if os.path.islink(file_path):
                continue
            total += os.path.getsize(file_path)
    return total


def _check_member(member: tarfile.TarInfo) -> None:
    """Rechaza entradas del tar que podrían escribir fuera del destino.

    Es una segunda barrera, independiente del filtro "data" de tarfile,
    para que la extracción sea segura en cualquier versión de Python.
    """
    name = member.name
    parts = name.replace("\\", "/").split("/")
    if name.startswith(("/", "\\")) or os.path.isabs(name) or (len(name) > 1 and name[1] == ":"):
        raise ExtractionError(f"Entrada con ruta absoluta rechazada: {name!r}")
    if ".." in parts:
        raise ExtractionError(f"Entrada con '..' rechazada: {name!r}")
    if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        raise ExtractionError(f"Tipo de entrada no permitido (dispositivo/FIFO): {name!r}")
    if member.issym() or member.islnk():
        target = member.linkname
        if target.startswith(("/", "\\")) or os.path.isabs(target):
            raise ExtractionError(f"Enlace con destino absoluto rechazado: {name!r}")
        base = os.path.dirname(name) if member.issym() else ""
        resolved = os.path.normpath(os.path.join(base, target))
        if resolved == ".." or resolved.startswith(".." + os.sep) or resolved.startswith("../"):
            raise ExtractionError(f"Enlace que sale del destino rechazado: {name!r}")
