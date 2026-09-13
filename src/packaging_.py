"""
packaging_.py — Empaquetado del contenido a respaldar.

Convierte un archivo o directorio en un único stream de bytes (tar+gzip)
apto para ser pasado a crypto_core.encrypt_blob(), y reconstruye el
árbol de archivos original a partir de ese stream durante la restauración.
"""

from __future__ import annotations

import io
import os
import tarfile

from exceptions import PayloadTooLargeError

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

    arcname = os.path.basename(os.path.normpath(path))
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

    Preserva estructura de directorios, nombres y permisos originales.

    Nota de seguridad: se usa el filtro "data" de tarfile (disponible desde
    Python 3.12), que rechaza rutas absolutas, symlinks peligrosos y
    entradas de path traversal (p. ej. "../../etc/passwd"). En versiones
    anteriores de Python, ese filtro no existe y la extracción se realiza
    sin esa protección adicional; el riesgo residual en ese caso se
    considera bajo porque el payload ya fue autenticado por AEAD antes de
    llegar aquí, pero no es una garantía formal (ver Sección 6 del
    Entregable 1).

    Args:
        payload: bytes del stream tar+gzip (ya descifrado).
        output_dir: directorio donde se extraerá el contenido. Se crea
            si no existe.
    """
    os.makedirs(output_dir, exist_ok=True)
    buffer = io.BytesIO(payload)
    with tarfile.open(fileobj=buffer, mode="r:gz") as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(path=output_dir, filter="data")
        else:  # pragma: no cover - solo en Python < 3.12
            tar.extractall(path=output_dir)


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