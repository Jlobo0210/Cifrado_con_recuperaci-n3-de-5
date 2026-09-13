import os
import sys
import time
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import crypto_core as cc  # noqa: E402
from exceptions import AuthenticationError, InvalidBlobFormatError  # noqa: E402


@pytest.fixture
def key():
    return cc.generate_key()


@pytest.fixture
def backup_id():
    return uuid.uuid4().bytes


# --- Casos positivos (1-6) ---------------------------------------------------

def test_case1_roundtrip_basico(key, backup_id):
    plaintext = b"contenido de prueba"
    blob = cc.encrypt_blob(key, plaintext, backup_id)
    assert cc.decrypt_blob(key, blob, backup_id) == plaintext


def test_case2_payload_vacio(key, backup_id):
    blob = cc.encrypt_blob(key, b"", backup_id)
    assert len(blob) == cc.MIN_BLOB_SIZE + cc.TAG_SIZE  # ciphertext vacío + tag
    assert cc.decrypt_blob(key, blob, backup_id) == b""


def test_case3_contenido_binario_arbitrario(key, backup_id):
    plaintext = bytes(range(256)) * 10
    blob = cc.encrypt_blob(key, plaintext, backup_id)
    assert cc.decrypt_blob(key, blob, backup_id) == plaintext


def test_case6_payload_grande_cercano_al_limite(key, backup_id):
    plaintext = os.urandom(5 * 1024 * 1024)  # 5 MB, suficiente para el smoke test
    start = time.perf_counter()
    blob = cc.encrypt_blob(key, plaintext, backup_id)
    encrypt_time = time.perf_counter() - start

    start = time.perf_counter()
    result = cc.decrypt_blob(key, blob, backup_id)
    decrypt_time = time.perf_counter() - start

    assert result == plaintext
    assert encrypt_time < 5 and decrypt_time < 5


# --- Casos negativos (9-10) ---------------------------------------------------

def test_case9_clave_incorrecta(key, backup_id):
    blob = cc.encrypt_blob(key, b"secreto", backup_id)
    otra_clave = cc.generate_key()
    with pytest.raises(AuthenticationError):
        cc.decrypt_blob(otra_clave, blob, backup_id)


def test_case10_backup_id_incorrecto(key, backup_id):
    blob = cc.encrypt_blob(key, b"secreto", backup_id)
    otro_backup_id = uuid.uuid4().bytes
    with pytest.raises(AuthenticationError):
        cc.decrypt_blob(key, blob, otro_backup_id)


# --- Casos de manipulación (11-13, 16) ----------------------------------------

def test_case11_bit_flip_en_ciphertext(key, backup_id):
    blob = bytearray(cc.encrypt_blob(key, b"contenido secreto", backup_id))
    blob[-1] ^= 0x01  # voltea el último bit (parte del tag)
    with pytest.raises(AuthenticationError):
        cc.decrypt_blob(key, bytes(blob), backup_id)


def test_case12_alg_id_alterado(key, backup_id):
    blob = bytearray(cc.encrypt_blob(key, b"contenido secreto", backup_id))
    blob[5] ^= 0x01  # ALG_ID está en el índice 5 (después de MAGIC[0:4], VERSION[4])
    with pytest.raises(AuthenticationError):
        cc.decrypt_blob(key, bytes(blob), backup_id)


def test_case13_nonce_alterado(key, backup_id):
    blob = bytearray(cc.encrypt_blob(key, b"contenido secreto", backup_id))
    blob[6] ^= 0x01  # primer byte del nonce
    with pytest.raises(AuthenticationError):
        cc.decrypt_blob(key, bytes(blob), backup_id)


def test_case16_reordenar_bytes_ciphertext(key, backup_id):
    plaintext = b"A" * 32 + b"B" * 32  # suficientemente largo para reordenar bloques
    blob = bytearray(cc.encrypt_blob(key, plaintext, backup_id))
    header_nonce_len = cc.HEADER_SIZE + cc.NONCE_SIZE
    ct_start = header_nonce_len
    a = blob[ct_start:ct_start + 16]
    b = blob[ct_start + 16:ct_start + 32]
    blob[ct_start:ct_start + 16] = b
    blob[ct_start + 16:ct_start + 32] = a
    with pytest.raises(AuthenticationError):
        cc.decrypt_blob(key, bytes(blob), backup_id)


# --- Casos de formato (14-15) --------------------------------------------------

def test_case14_blob_truncado(key, backup_id):
    blob = cc.encrypt_blob(key, b"contenido", backup_id)
    truncado = blob[:10]  # menos de los 18 bytes de encabezado fijo
    with pytest.raises(InvalidBlobFormatError):
        cc.decrypt_blob(key, truncado, backup_id)
    with pytest.raises(ValueError):
        cc.decrypt_blob(key, truncado, backup_id)


def test_case15_magic_incorrecto(key, backup_id):
    blob = bytearray(cc.encrypt_blob(key, b"contenido", backup_id))
    blob[0:4] = b"XXXX"
    with pytest.raises(InvalidBlobFormatError):
        cc.decrypt_blob(key, bytes(blob), backup_id)


# --- Sanity check (17) ----------------------------------------------------------

def test_case17_nonces_sin_colision():
    nonces = {os.urandom(cc.NONCE_SIZE) for _ in range(1000)}
    assert len(nonces) == 1000


# --- Mensajes de error indistinguibles ---------------------------------------

def test_mensajes_de_autenticacion_son_identicos(key, backup_id):
    blob = cc.encrypt_blob(key, b"contenido", backup_id)
    mensajes = set()

    otra_clave = cc.generate_key()
    try:
        cc.decrypt_blob(otra_clave, blob, backup_id)
    except AuthenticationError as e:
        mensajes.add(str(e))

    otro_id = uuid.uuid4().bytes
    try:
        cc.decrypt_blob(key, blob, otro_id)
    except AuthenticationError as e:
        mensajes.add(str(e))

    blob_alterado = bytearray(blob)
    blob_alterado[-1] ^= 0x01
    try:
        cc.decrypt_blob(key, bytes(blob_alterado), backup_id)
    except AuthenticationError as e:
        mensajes.add(str(e))

    assert len(mensajes) == 1, "Los mensajes de fallo de autenticidad deben ser idénticos"