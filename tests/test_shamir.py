import itertools
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import shamir as sh  # noqa: E402
from shamir import (  # noqa: E402
    InconsistentSharesError,
    InsufficientSharesError,
    InvalidParametersError,
    InvalidShareError,
    reconstruct_secret,
    split_secret,
)

MAX_K = (1 << 256) - 1


def k_bytes(n: int) -> bytes:
    return n.to_bytes(32, "big")


@pytest.fixture
def key():
    return os.urandom(32)


# --- Constantes del Entregable 1 --------------------------------------------------


def test_parametros_del_esquema():
    assert sh.P == 2**521 - 1
    assert sh.P > 2**256
    assert sh.SHARE_VALUE_SIZE == 66 == (521 + 7) // 8
    assert sh.SECRET_SIZE == 32
    assert sh.SHARING_SCHEME == "shamir-zp-m521"
    # p es primo (Fermat con varias bases; 2^521 − 1 es un primo de Mersenne conocido)
    for base in (2, 3, 5, 7, 11):
        assert pow(base, sh.P - 1, sh.P) == 1


def test_inverso_modular_por_fermat():
    for a in (1, 2, 3, 4, 5, 123456789, sh.P - 1, MAX_K):
        assert (a * sh._inv(a)) % sh.P == 1


# --- Forma de la salida ----------------------------------------------------------------


def test_split_forma_3_de_5(key):
    shares = split_secret(key, 3, 5)
    assert [i for i, _ in shares] == [1, 2, 3, 4, 5]
    for _, v in shares:
        assert isinstance(v, bytes)
        assert len(v) == sh.SHARE_VALUE_SIZE == 66  # ancho fijo
        assert int.from_bytes(v, "big") < sh.P


def test_los_valores_no_son_el_secreto(key):
    for _, v in split_secret(key, 3, 5):
        assert int.from_bytes(v, "big") != int.from_bytes(key, "big")


def test_split_es_aleatorio(key):
    a, b = split_secret(key, 3, 5), split_secret(key, 3, 5)
    assert a != b
    assert reconstruct_secret(a[:3], 3) == reconstruct_secret(b[:3], 3) == key


def test_split_no_modifica_el_secreto():
    ba = bytearray(os.urandom(32))
    copia = bytes(ba)
    split_secret(ba, 3, 5)
    assert bytes(ba) == copia


def test_coeficientes_vienen_de_la_fuente_aleatoria(monkeypatch):
    # a1 = 1 fijo: f(x) = K + x  =>  f(1) = K+1, f(2) = K+2, f(3) = K+3
    monkeypatch.setattr(sh, "_random_bytes", lambda n: b"\x00" * (n - 1) + b"\x01")
    k = 5
    shares = split_secret(k_bytes(k), 2, 3)
    assert [int.from_bytes(v, "big") for _, v in shares] == [6, 7, 8]
    assert reconstruct_secret(shares[1:], 2) == k_bytes(k)


def test_muestreo_uniforme_rechaza_valores_fuera_de_zp(monkeypatch):
    # El primer intento da 2^521 − 1 = p (inválido) y el segundo da 7.
    respuestas = iter([b"\x01" + b"\xff" * 65, b"\x00" * 65 + b"\x07"])
    monkeypatch.setattr(sh, "_random_bytes", lambda n: next(respuestas))
    assert sh._random_zp() == 7


# --- U1 / U2: roundtrip y las 10 combinaciones -------------------------------------------


def test_U1_roundtrip_con_exactamente_3(key):
    shares = split_secret(key, 3, 5)
    assert reconstruct_secret(shares[:3], 3) == key


def test_U2_las_10_combinaciones_de_3_de_5(key):
    shares = split_secret(key, 3, 5)
    combos = list(itertools.combinations(shares, 3))
    assert len(combos) == 10
    for combo in combos:
        assert reconstruct_secret(list(combo), 3) == key


def test_el_orden_no_importa(key):
    shares = split_secret(key, 3, 5)
    for perm in itertools.permutations(shares[:3]):
        assert reconstruct_secret(list(perm), 3) == key


def test_mas_participaciones_que_el_umbral(key):
    shares = split_secret(key, 3, 5)
    assert reconstruct_secret(shares[:4], 3) == key
    assert reconstruct_secret(shares, 3) == key


@pytest.mark.parametrize("t,n", [(2, 2), (2, 3), (3, 3), (4, 7), (5, 5), (10, 20), (3, 255)])
def test_otros_t_de_n(t, n, key):
    shares = split_secret(key, t, n)
    assert [i for i, _ in shares] == list(range(1, n + 1))
    assert reconstruct_secret(shares[-t:], t) == key
    assert reconstruct_secret(shares[:t], t) == key


def test_acepta_bytearray_memoryview_listas_y_tuplas(key):
    shares = split_secret(bytearray(key), 3, 5)
    mixed = [(shares[0][0], bytearray(shares[0][1])), [shares[1][0], memoryview(shares[1][1])], shares[2]]
    assert reconstruct_secret(mixed, 3) == key
    assert reconstruct_secret(tuple(shares[:3]), 3) == key


def test_reconstruct_no_modifica_sus_entradas(key):
    shares = split_secret(key, 3, 5)
    copia = list(shares)
    reconstruct_secret(shares, 3)
    assert shares == copia


# --- U3: menos del umbral -----------------------------------------------------------------


def test_U3_dos_participaciones_no_alcanzan(key):
    shares = split_secret(key, 3, 5)
    for combo in itertools.combinations(shares, 2):
        with pytest.raises(InsufficientSharesError) as exc:
            reconstruct_secret(list(combo), 3)
        assert isinstance(exc.value, ValueError)
        assert "3" in str(exc.value) and "2" in str(exc.value)


def test_cero_y_una_participacion(key):
    shares = split_secret(key, 3, 5)
    for few in ([], shares[:1]):
        with pytest.raises(InsufficientSharesError):
            reconstruct_secret(few, 3)


# --- U4 / U5: bordes del secreto -----------------------------------------------------------


def test_U4_secreto_cero():
    k = k_bytes(0)
    shares = split_secret(k, 3, 5)
    assert reconstruct_secret(shares[1:4], 3) == k


def test_U5_secreto_maximo_de_256_bits():
    k = k_bytes(MAX_K)
    shares = split_secret(k, 3, 5)
    for combo in itertools.combinations(shares, 3):
        assert reconstruct_secret(list(combo), 3) == k


@pytest.mark.parametrize("n", [1, 2**255, 2**255 + 1, 2**128, MAX_K - 1])
def test_otros_bordes_del_secreto(n):
    shares = split_secret(k_bytes(n), 3, 5)
    assert reconstruct_secret(shares[2:], 3) == k_bytes(n)


def test_valores_con_ceros_a_la_izquierda_conservan_66_bytes():
    # Con K = 0 y coeficientes 0, todos los valores son 0 y deben seguir midiendo 66 bytes.
    import shamir

    original = shamir._random_bytes
    shamir._random_bytes = lambda n: bytes(n)
    try:
        shares = split_secret(k_bytes(0), 3, 5)
    finally:
        shamir._random_bytes = original
    assert all(v == bytes(66) for _, v in shares)
    assert reconstruct_secret(shares[:3], 3) == k_bytes(0)


# --- U6 / U7: participaciones inválidas ------------------------------------------------------


@pytest.mark.parametrize("bad_index", [0, 256, -1, 1000])
def test_U6_indice_cero_o_fuera_de_rango(bad_index, key):
    shares = split_secret(key, 3, 5)
    with pytest.raises(InvalidShareError) as exc:
        reconstruct_secret([(bad_index, shares[0][1]), shares[1], shares[2]], 3)
    assert isinstance(exc.value, ValueError)


def test_U7_participacion_repetida_se_rechaza(key):
    shares = split_secret(key, 3, 5)
    with pytest.raises(InvalidShareError, match="repetida"):
        reconstruct_secret([shares[0], shares[1], shares[0]], 3)


def test_U7_mismo_indice_con_valores_distintos(key):
    shares = split_secret(key, 3, 5)
    falsa = (shares[0][0], shares[1][1])
    with pytest.raises(InvalidShareError):
        reconstruct_secret([shares[0], falsa, shares[2]], 3)


def test_U7_dos_shares_repetidos_no_cuentan_como_tres(key):
    shares = split_secret(key, 3, 5)
    with pytest.raises(InvalidShareError):
        reconstruct_secret([shares[0], shares[0], shares[1]], 3)


def test_indice_no_entero(key):
    shares = split_secret(key, 3, 5)
    for bad in ("1", 1.0, None, True):
        with pytest.raises(InvalidShareError):
            reconstruct_secret([(bad, shares[0][1]), shares[1], shares[2]], 3)


def test_valor_de_longitud_o_tipo_incorrecto(key):
    shares = split_secret(key, 3, 5)
    v = shares[0][1]
    for bad in (b"", v[:-1], v + b"\x00", b"\x00" * 32, "texto", 12345):
        with pytest.raises(InvalidShareError):
            reconstruct_secret([(1, bad), shares[1], shares[2]], 3)


def test_valor_mayor_o_igual_a_p(key):
    shares = split_secret(key, 3, 5)
    for fuera in (sh.P, sh.P + 1, 2**528 - 1):
        v = fuera.to_bytes(66, "big")
        with pytest.raises(InvalidShareError, match="Z_p"):
            reconstruct_secret([(1, v), shares[1], shares[2]], 3)


def test_forma_incorrecta_de_participacion(key):
    shares = split_secret(key, 3, 5)
    for bad in (b"abc", (1,), (1, b"x", b"y"), 7, None):
        with pytest.raises(InvalidShareError):
            reconstruct_secret([bad, shares[1], shares[2]], 3)
    with pytest.raises(InvalidShareError):
        reconstruct_secret(None, 3)


# --- Alteración y mezcla ---------------------------------------------------------------------------


def test_alteracion_pequena_con_exactamente_t_cambia_la_clave_en_silencio(key):
    # Shamir no tiene integridad: con exactamente t participaciones, un
    # cambio pequeño (aquí 1 bit del valor) produce otra clave < 2^256 sin
    # error. Eso lo cubren el checksum de formats.py y el tag AEAD.
    shares = split_secret(key, 3, 5)
    i, v = shares[0]
    alterada = (i, (int.from_bytes(v, "big") ^ 1).to_bytes(66, "big"))
    resultado = reconstruct_secret([alterada, shares[1], shares[2]], 3)
    assert resultado != key


def test_alteracion_grande_con_exactamente_t_se_rechaza(key):
    # Un cambio en bits altos (o una participación aleatoria / de otro
    # respaldo) casi seguro lleva a un entero >= 2^256, que no puede ser K.
    shares = split_secret(key, 3, 5)
    i, v = shares[0]
    alterada = (i, (int.from_bytes(v, "big") ^ (1 << 300)).to_bytes(66, "big"))
    with pytest.raises(InconsistentSharesError):
        reconstruct_secret([alterada, shares[1], shares[2]], 3)


def test_participacion_alterada_con_mas_de_t_se_detecta(key):
    shares = split_secret(key, 3, 5)
    i, v = shares[4]
    alterada = (i, (int.from_bytes(v, "big") ^ (1 << 300)).to_bytes(66, "big"))
    for conjunto in (shares[:4] + [alterada], shares[:3] + [alterada]):
        with pytest.raises(InconsistentSharesError):
            reconstruct_secret(conjunto, 3)


def test_mezcla_de_dos_respaldos(key):
    otra = os.urandom(32)
    a, b = split_secret(key, 3, 5), split_secret(otra, 3, 5)
    with pytest.raises(InconsistentSharesError):
        reconstruct_secret([a[0], a[1], b[2]], 3)
    with pytest.raises(InconsistentSharesError):
        reconstruct_secret([a[0], a[1], b[2], a[3]], 3)


def test_umbral_menor_al_real_no_da_la_clave(key):
    shares = split_secret(key, 3, 5)
    try:
        assert reconstruct_secret(shares[:2], 2) != key
    except InconsistentSharesError:
        pass  # lo habitual: el resultado no cabe en 256 bits


# --- U8: "2 shares no revelan nada" -----------------------------------------------------------------


def test_U8_dos_shares_son_consistentes_con_cualquier_secreto(key):
    # Con 2 participaciones reales y CUALQUIER secreto candidato K' existe un
    # polinomio de grado 2 que pasa por (0, K'), (x1, y1) y (x2, y2). Se
    # construye explícitamente y se comprueba que un tercer punto compatible
    # con K' haría que el sistema reconstruyera K' en lugar del secreto real.
    shares = split_secret(key, 3, 5)
    (x1, v1), (x2, v2) = shares[0], shares[1]
    p1, p2 = (x1, int.from_bytes(v1, "big")), (x2, int.from_bytes(v2, "big"))
    for k_alt in (0, 1, MAX_K, int.from_bytes(os.urandom(32), "big")):
        x3 = 3
        y3 = sh._lagrange([(0, k_alt), p1, p2], x3)  # f'(3) del polinomio alterno
        forjada = (x3, y3.to_bytes(66, "big"))
        assert reconstruct_secret([shares[0], shares[1], forjada], 3) == k_bytes(k_alt)


def test_U8_la_matriz_de_las_dos_participaciones_es_invertible_para_todo_par():
    # (c1, c2) -> (f(x1), f(x2)) es lineal con matriz [[x1, x1²], [x2, x2²]],
    # de determinante x1·x2·(x2 − x1) mod p. Si es distinto de 0 para TODO
    # par de índices, la aplicación es una biyección de Z_p² en Z_p² y lo que
    # ven dos custodios es uniforme e independiente de K.
    for x1 in range(1, sh.MAX_SHARES + 1):
        for x2 in range(x1 + 1, sh.MAX_SHARES + 1):
            assert (x1 * x2 * (x2 - x1)) % sh.P != 0


def test_una_participacion_es_uniforme_chi_cuadrado():
    # Secreto FIJO; el byte menos significativo de f(1) debe ser uniforme.
    # gl = 255; el umbral 400 corresponde a p ≈ 1e-8.
    secret = bytes(range(1, 33))
    n = 25600
    counts = [0] * 256
    for _ in range(n):
        counts[split_secret(secret, 3, 5)[0][1][-1]] += 1
    esperado = n / 256
    chi2 = sum((c - esperado) ** 2 / esperado for c in counts)
    assert chi2 < 400


# --- U9: muchas ejecuciones --------------------------------------------------------------------------


def test_U9_1000_roundtrips_con_secretos_aleatorios_y_extremos():
    extremos = [k_bytes(0), k_bytes(1), k_bytes(MAX_K), k_bytes(MAX_K - 1), k_bytes(2**255)]
    secretos = extremos + [os.urandom(32) for _ in range(995)]
    for k in secretos:
        shares = split_secret(k, 3, 5)
        elegidas = random.sample(shares, 3)
        assert reconstruct_secret(elegidas, 3) == k


# --- Validación de parámetros ---------------------------------------------------------------------------


@pytest.mark.parametrize("t,n", [(1, 5), (0, 5), (-1, 5), (6, 5), (3, 2), (3, 256), (256, 256), (2, 0)])
def test_parametros_invalidos(t, n, key):
    with pytest.raises(InvalidParametersError):
        split_secret(key, t, n)


@pytest.mark.parametrize("t,n", [(3.0, 5), (3, 5.0), ("3", 5), (3, None), (True, 5)])
def test_parametros_de_tipo_incorrecto(t, n, key):
    with pytest.raises(InvalidParametersError):
        split_secret(key, t, n)


@pytest.mark.parametrize("secret", [b"", b"x" * 31, b"x" * 33, b"x" * 66, "t" * 32, 12345, None, [1] * 32])
def test_secreto_invalido(secret):
    with pytest.raises(InvalidParametersError):
        split_secret(secret, 3, 5)


@pytest.mark.parametrize("t", [0, 1, -3, 256, 3.5, "3", None, True])
def test_umbral_invalido_al_reconstruir(t, key):
    shares = split_secret(key, 3, 5)
    with pytest.raises(InvalidParametersError):
        reconstruct_secret(shares, t)


def test_todas_las_excepciones_son_value_error():
    for exc in (
        sh.ShamirError,
        InvalidParametersError,
        InvalidShareError,
        InsufficientSharesError,
        InconsistentSharesError,
    ):
        assert issubclass(exc, ValueError)
        assert issubclass(exc, sh.ShamirError)


# --- Integración con crypto_core ---------------------------------


def test_integracion_con_crypto_core():
    cc = pytest.importorskip("crypto_core")
    import uuid

    backup_id = uuid.uuid4().bytes
    key = cc.generate_key()
    blob = cc.encrypt_blob(key, b"contenido secreto", backup_id)

    shares = split_secret(bytes(key), 3, 5)  # tal como lo hará el orquestador
    cc.wipe(key)

    for combo in itertools.combinations(shares, 3):
        k2 = bytearray(reconstruct_secret(list(combo), 3))
        try:
            assert cc.decrypt_blob(k2, blob, backup_id) == b"contenido secreto"
        finally:
            cc.wipe(k2)
