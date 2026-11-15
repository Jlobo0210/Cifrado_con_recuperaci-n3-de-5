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


SLOW = pytest.mark.skipif(
    os.environ.get("EVLP_SLOW_TESTS") != "1",
    reason="Prueba lenta (~199 MB). Ejecutar con EVLP_SLOW_TESTS=1.",
)


def test_case6_payload_grande_smoke(key, backup_id):
    plaintext = os.urandom(5 * 1024 * 1024)  # 5 MB, suficiente para el smoke test
    start = time.perf_counter()
    blob = cc.encrypt_blob(key, plaintext, backup_id)
    encrypt_time = time.perf_counter() - start

    start = time.perf_counter()
    result = cc.decrypt_blob(key, blob, backup_id)
    decrypt_time = time.perf_counter() - start

    assert result == plaintext
    assert encrypt_time < 5 and decrypt_time < 5


@SLOW
def test_case6_payload_cercano_a_200mb(key, backup_id):
    """Caso 6 real: ~199 MB, justo por debajo del límite autoritativo."""
    size = 199 * 1024 * 1024
    plaintext = os.urandom(size)
    blob = cc.encrypt_blob(key, plaintext, backup_id)
    assert len(blob) == size + cc.FORMAT_OVERHEAD
    assert cc.decrypt_blob(key, blob, backup_id) == plaintext


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

def test_case17_nonces_sin_colision(key, backup_id):
    # Se extraen los nonces de blobs reales producidos por encrypt_blob(),
    # no de os.urandom() directamente, para probar el código del módulo.
    start = cc.HEADER_SIZE
    nonces = {
        cc.encrypt_blob(key, b"x", backup_id)[start:start + cc.NONCE_SIZE]
        for _ in range(1000)
    }
    assert len(nonces) == 1000


def test_mismo_plaintext_produce_blobs_distintos(key, backup_id):
    """Cifrado probabilístico: el nonce aleatorio cambia todo el ciphertext."""
    assert cc.encrypt_blob(key, b"igual", backup_id) != cc.encrypt_blob(key, b"igual", backup_id)


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


# --- Formato y overhead -----------------------------------------------------------

def test_estructura_del_blob(key, backup_id):
    plaintext = os.urandom(1000)
    blob = cc.encrypt_blob(key, plaintext, backup_id)
    assert blob[:4] == b"EVLP"
    assert blob[4] == cc.VERSION
    assert blob[5] == cc.ALG_CHACHA20_POLY1305
    assert len(blob) == len(plaintext) + cc.FORMAT_OVERHEAD
    assert cc.FORMAT_OVERHEAD == 34


@pytest.mark.parametrize("size", [0, 1, 1024, 1024 * 1024])
def test_case18_overhead_constante(key, backup_id, size):
    blob = cc.encrypt_blob(key, os.urandom(size), backup_id)
    assert len(blob) - size == 34


def test_version_alterada_falla_autenticacion(key, backup_id):
    blob = bytearray(cc.encrypt_blob(key, b"contenido secreto", backup_id))
    blob[4] ^= 0x01  # VERSION
    with pytest.raises(AuthenticationError):
        cc.decrypt_blob(key, bytes(blob), backup_id)


def test_tag_alterado_falla_autenticacion(key, backup_id):
    blob = bytearray(cc.encrypt_blob(key, b"contenido secreto", backup_id))
    blob[cc.HEADER_SIZE + cc.NONCE_SIZE] ^= 0x80  # primer byte del ciphertext
    with pytest.raises(AuthenticationError):
        cc.decrypt_blob(key, bytes(blob), backup_id)


@pytest.mark.parametrize("cut", [18, 20, 33])
def test_blob_sin_espacio_para_tag_es_formato_invalido(key, backup_id, cut):
    blob = cc.encrypt_blob(key, b"", backup_id)[:cut]
    with pytest.raises(InvalidBlobFormatError):
        cc.decrypt_blob(key, blob, backup_id)


def test_blob_truncado_con_tag_incompleto_falla(key, backup_id):
    blob = cc.encrypt_blob(key, b"contenido largo de prueba", backup_id)
    with pytest.raises(AuthenticationError):
        cc.decrypt_blob(key, blob[:-1], backup_id)


def test_bytes_extra_al_final_fallan(key, backup_id):
    blob = cc.encrypt_blob(key, b"contenido", backup_id)
    with pytest.raises(AuthenticationError):
        cc.decrypt_blob(key, blob + b"\x00", backup_id)


# --- Validación de entradas -------------------------------------------------------

@pytest.mark.parametrize("bad_key", [b"", b"\x00" * 16, b"\x00" * 31, b"\x00" * 33, "k" * 32])
def test_clave_de_tamano_invalido(bad_key, backup_id):
    with pytest.raises(ValueError):
        cc.encrypt_blob(bad_key, b"x", backup_id)


@pytest.mark.parametrize("bad_id", [b"", b"\x00" * 15, uuid.uuid4().hex.encode(), str(uuid.uuid4())])
def test_backup_id_invalido(key, bad_id):
    with pytest.raises(ValueError):
        cc.encrypt_blob(key, b"x", bad_id)


def test_plaintext_str_rechazado(key, backup_id):
    with pytest.raises(TypeError):
        cc.encrypt_blob(key, "texto", backup_id)


def test_blob_no_bytes_rechazado(key, backup_id):
    with pytest.raises(InvalidBlobFormatError):
        cc.decrypt_blob(key, "EVLP" * 20, backup_id)


# --- Manejo de la clave en memoria ------------------------------------------------

def test_generate_key_es_aleatoria_y_de_256_bits():
    keys = {bytes(cc.generate_key()) for _ in range(100)}
    assert len(keys) == 100
    assert all(len(k) == 32 for k in keys)


def test_clave_bytes_y_bytearray_son_equivalentes(backup_id):
    k = cc.generate_key()
    blob = cc.encrypt_blob(bytes(k), b"hola", backup_id)
    assert cc.decrypt_blob(bytearray(k), blob, backup_id) == b"hola"


def test_wipe_borra_la_clave(backup_id):
    k = cc.generate_key()
    blob = cc.encrypt_blob(k, b"hola", backup_id)
    cc.wipe(k)
    assert k == bytearray(32)
    with pytest.raises(AuthenticationError):
        cc.decrypt_blob(k, blob, backup_id)


def test_wipe_ignora_bytes_inmutables():
    data = b"inmutable"
    cc.wipe(data)  # no debe lanzar
    assert data == b"inmutable"


# --- parse_header (para inspector / manifiesto) ------------------------------------

def test_parse_header_no_requiere_clave(key, backup_id):
    blob = cc.encrypt_blob(key, b"x" * 100, backup_id)
    info = cc.parse_header(blob)
    assert info == {
        "magic": "EVLP",
        "version": 1,
        "alg_id": 1,
        "algorithm": "ChaCha20-Poly1305",
        "nonce_size": 12,
        "tag_size": 16,
        "ciphertext_size": 100,
        "blob_size": 134,
    }


def test_parse_header_rechaza_magic_incorrecto():
    with pytest.raises(InvalidBlobFormatError):
        cc.parse_header(b"XXXX" + bytes(40))


def test_ningun_secreto_en_mensajes_de_error(key, backup_id):
    plaintext = b"SECRETO-MUY-RECONOCIBLE"
    blob = cc.encrypt_blob(key, plaintext, backup_id)
    otra = cc.generate_key()
    with pytest.raises(AuthenticationError) as exc_info:
        cc.decrypt_blob(otra, blob, backup_id)
    texto = str(exc_info.value)
    assert key.hex() not in texto and otra.hex() not in texto
    assert "SECRETO" not in texto
