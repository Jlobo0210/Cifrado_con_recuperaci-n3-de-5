"""
crypto_core.py — Cifrado de envolvente con ChaCha20-Poly1305 (RFC 8439).

Responsabilidad de este módulo:
    - Generar la clave simétrica aleatoria de 256 bits (K).
    - Cifrar un payload en claro con AEAD, produciendo un blob binario
      autodescriptivo y versionado.
    - Descifrar ese blob, verificando su autenticidad.

Este módulo NO sabe nada sobre:
    - cómo se reparte K entre custodios (eso es Shamir),
    - el formato del manifiesto ni de las participaciones,
    - cómo se empaqueta un archivo/directorio en bytes (ver packaging_.py).

Formato del blob producido por encrypt_blob():

    MAGIC (4B) || VERSION (1B) || ALG_ID (1B) || NONCE (12B) || CIPHERTEXT‖TAG (variable)
    └──────────────── header (6B) ───────────┘

    AAD = header || backup_id   (22 bytes, backup_id es un UUID crudo de 16B)

Tamaño mínimo estructural de un blob válido: 6 (header) + 12 (nonce) +
16 (tag) = 34 bytes, que corresponde a un payload vacío. El sobrecosto del
formato es constante: 34 bytes por respaldo, sin importar el tamaño.

Manejo de la clave en memoria (requisito "la clave recuperada permanece
únicamente en memoria"):
    - Este módulo nunca escribe la clave ni el plaintext a disco ni a logs.
    - encrypt_blob/decrypt_blob aceptan la clave como `bytearray`, de modo
      que el orquestador pueda borrarla con wipe() apenas termine de usarla.
    - Python no garantiza que no queden copias internas (p. ej. dentro de
      la biblioteca cryptography), así que wipe() es una mitigación de
      mejor esfuerzo, no una garantía formal.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from exceptions import AuthenticationError, InvalidBlobFormatError

# --- Constantes del formato del contenedor ---------------------------------

MAGIC: bytes = b"EVLP"
VERSION: int = 0x01
ALG_CHACHA20_POLY1305: int = 0x01

NONCE_SIZE: int = 12  # 96 bits, tamaño estándar para ChaCha20-Poly1305
KEY_SIZE: int = 32  # 256 bits
TAG_SIZE: int = 16  # Poly1305 añade 16 bytes de tag al final del ciphertext
BACKUP_ID_SIZE: int = 16  # UUID crudo (uuid.UUID(...).bytes)

HEADER_SIZE: int = len(MAGIC) + 1 + 1  # MAGIC + VERSION + ALG_ID = 6 bytes
MIN_BLOB_SIZE: int = HEADER_SIZE + NONCE_SIZE  # 18 bytes, sin contar ciphertext/tag
# Un blob que pasa el encabezado pero no alcanza a contener el tag no puede
# venir de encrypt_blob(): se rechaza como formato inválido, sin llamar al AEAD.
MIN_VALID_BLOB_SIZE: int = MIN_BLOB_SIZE + TAG_SIZE  # 34 bytes (payload vacío)
FORMAT_OVERHEAD: int = MIN_VALID_BLOB_SIZE  # bytes que el formato añade al payload

# Nombre del algoritmo tal como lo declara el manifiesto (campo "algorithm"),
# para que formats.py / orchestrator.py comparen con el encabezado del blob.
ALGORITHM_NAMES: dict[int, str] = {ALG_CHACHA20_POLY1305: "ChaCha20-Poly1305"}


# --- API pública -------------------------------------------------------------

def generate_key() -> bytearray:
    """Genera una clave aleatoria de 256 bits para un único respaldo.

    La clave debe usarse una sola vez (un respaldo = una clave nueva).
    Se devuelve como `bytearray` (mutable) para poder borrarla con wipe()
    cuando ya no se necesite. Se comporta como bytes en todo lo demás
    (len, comparación, slicing, paso a split_secret).
    """
    return bytearray(os.urandom(KEY_SIZE))


def wipe(buffer: bytearray) -> None:
    """Sobrescribe con ceros un buffer mutable (clave o plaintext).

    Mitigación de mejor esfuerzo: reduce el tiempo que el secreto vive en
    memoria, pero no puede borrar copias que Python o la biblioteca
    cryptography hayan hecho internamente. Si recibe un objeto inmutable
    (bytes) no hace nada, porque no es posible sobrescribirlo.
    """
    if isinstance(buffer, bytearray):
        for i in range(len(buffer)):
            buffer[i] = 0


def parse_header(blob: bytes) -> dict:
    """Lee el encabezado de un blob SIN descifrar ni verificar nada.

    Pensado para el inspector y para la comparación cruzada con el
    manifiesto (versión y algoritmo). No necesita la clave y no expone
    ningún secreto: solo devuelve metadatos públicos del contenedor.

    Returns:
        {"magic", "version", "alg_id", "algorithm", "nonce_size",
         "tag_size", "ciphertext_size", "blob_size"}

    Raises:
        InvalidBlobFormatError: si el blob está truncado o el MAGIC no es válido.
    """
    version, alg_id, _nonce, ciphertext_with_tag, _header = _parse_blob(blob)
    return {
        "magic": MAGIC.decode("ascii"),
        "version": version,
        "alg_id": alg_id,
        "algorithm": ALGORITHM_NAMES.get(alg_id, f"desconocido(0x{alg_id:02x})"),
        "nonce_size": NONCE_SIZE,
        "tag_size": TAG_SIZE,
        "ciphertext_size": len(ciphertext_with_tag) - TAG_SIZE,
        "blob_size": len(blob),
    }


def encrypt_blob(key: bytes, plaintext: bytes, backup_id: bytes) -> bytes:
    """Cifra `plaintext` con ChaCha20-Poly1305 y devuelve el blob completo.

    Args:
        key: clave de 32 bytes (256 bits), de un solo uso.
        plaintext: contenido a proteger (típicamente el payload ya
            empaquetado por packaging_.pack_source()).
        backup_id: identificador del respaldo como 16 bytes crudos de UUID
            (uuid.UUID(...).bytes), NO el string formateado de 36 caracteres.

    Returns:
        El blob binario: MAGIC || VERSION || ALG_ID || NONCE || CIPHERTEXT‖TAG

    Raises:
        ValueError: si `key` o `backup_id` no tienen el tamaño esperado.
        TypeError: si `plaintext` no es un objeto tipo bytes.
    """
    _validate_key(key)
    _validate_backup_id(backup_id)
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext debe ser bytes (no str ni otro tipo).")

    header = _build_header()
    aad = header + bytes(backup_id)
    nonce = os.urandom(NONCE_SIZE)

    aead = ChaCha20Poly1305(key)
    ciphertext_with_tag = aead.encrypt(nonce, plaintext, aad)

    return header + nonce + ciphertext_with_tag


def decrypt_blob(key: bytes, blob: bytes, backup_id: bytes) -> bytes:
    """Descifra y verifica un blob producido por encrypt_blob().

    Args:
        key: la misma clave de 32 bytes usada al cifrar.
        blob: el blob binario completo.
        backup_id: el MISMO backup_id (16 bytes crudos) usado al cifrar.
            Normalmente se obtiene del manifiesto.

    Returns:
        El plaintext original.

    Raises:
        InvalidBlobFormatError: si el blob no tiene el formato esperado
            (MAGIC incorrecto, o blob más corto que encabezado + nonce + tag).
            Es un ValueError.
        AuthenticationError: si la verificación de autenticidad falla.
            No distingue entre clave incorrecta, backup_id incorrecto o
            manipulación del blob — ver docstring de la excepción.
    """
    _validate_key(key)
    _validate_backup_id(backup_id)

    version, alg_id, nonce, ciphertext_with_tag, header = _parse_blob(blob)

    # VERSION y ALG_ID no se rechazan aquí de forma explícita a propósito:
    # ambos forman parte del AAD, así que cualquier alteración hace fallar
    # la verificación con el MISMO error genérico que una clave o un
    # backup_id incorrectos (caso 12 del plan de pruebas). Distinguir
    # "versión desconocida" de "tag inválido" le daría al adversario un
    # oráculo sobre qué byte cambió. Quedan extraídos para una futura v2.
    del version, alg_id

    if len(ciphertext_with_tag) < TAG_SIZE:
        raise InvalidBlobFormatError(
            f"Blob truncado: se esperaban al menos {MIN_VALID_BLOB_SIZE} bytes, "
            f"se recibieron {len(blob)}."
        )

    aad = header + bytes(backup_id)
    aead = ChaCha20Poly1305(key)

    try:
        return aead.decrypt(nonce, ciphertext_with_tag, aad)
    except InvalidTag as exc:
        raise AuthenticationError(
            "Verificación de autenticidad fallida."
        ) from exc


# --- Helpers internos --------------------------------------------------------

def _build_header() -> bytes:
    return MAGIC + bytes([VERSION, ALG_CHACHA20_POLY1305])


def _validate_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
        raise ValueError(f"La clave debe tener exactamente {KEY_SIZE} bytes.")


def _validate_backup_id(backup_id: bytes) -> None:
    if not isinstance(backup_id, (bytes, bytearray)) or len(backup_id) != BACKUP_ID_SIZE:
        raise ValueError(
            f"backup_id debe ser un UUID crudo de {BACKUP_ID_SIZE} bytes "
            "(usar uuid.UUID(...).bytes, no el string formateado)."
        )


def _parse_blob(blob: bytes) -> tuple[int, int, bytes, bytes, bytes]:
    """Valida y separa un blob en sus componentes.

    Returns:
        (version, alg_id, nonce, ciphertext_with_tag, header)
    """
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise InvalidBlobFormatError("El blob debe ser bytes.")
    if isinstance(blob, memoryview):
        blob = blob.tobytes()
    if len(blob) < MIN_BLOB_SIZE:
        raise InvalidBlobFormatError(
            f"Blob truncado: se esperaban al menos {MIN_BLOB_SIZE} bytes "
            f"de encabezado, se recibieron {len(blob)}."
        )

    if blob[: len(MAGIC)] != MAGIC:
        raise InvalidBlobFormatError("Formato de blob no reconocido (MAGIC incorrecto).")

    header = blob[:HEADER_SIZE]
    version = blob[len(MAGIC)]
    alg_id = blob[len(MAGIC) + 1]
    nonce = blob[HEADER_SIZE:HEADER_SIZE + NONCE_SIZE]
    ciphertext_with_tag = blob[HEADER_SIZE + NONCE_SIZE:]

    return version, alg_id, nonce, ciphertext_with_tag, header