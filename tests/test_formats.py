"""Pruebas de formats.py (casos F1-F16 del plan de pruebas)

Más una prueba de integración A + B + C (cifrado, Shamir y formatos)
"""
from __future__ import annotations

import dataclasses
import itertools
import json
import os
import re
import sys

import pytest  # type: ignore

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import formats as fm  # noqa: E402
from formats import FormatError, Manifest, ShareFile  # noqa: E402

P = fm.FIELD_PRIME


# --- Ayudantes -------------------------------------------------------------------


def _blob(n: int = 200) -> bytes:
    return b"EVLP\x01\x01" + os.urandom(n)


def _value() -> bytes:
    while True:
        v = os.urandom(fm.SHARE_VALUE_SIZE)
        if int.from_bytes(v, "big") < P:
            return v


def _share(bid: str, index: int = 1, value: bytes | None = None) -> ShareFile:
    return fm.make_share(bid, index, value if value is not None else _value())


def _edit_json(path, fn) -> None:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    fn(data)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _write_text(path, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _backup_dir(tmp_path, name="b"):
    """Carpeta con manifiesto, paquete y las 5 participaciones de un respaldo."""
    d = tmp_path / name
    d.mkdir()
    bid = fm.new_backup_id()
    blob = _blob()
    manifest = fm.make_manifest(bid, blob)
    fm.write_manifest(manifest, str(d / fm.manifest_filename(bid)))
    fm.write_package(blob, str(d / fm.package_filename(bid)))
    paths = []
    for i in range(1, 6):
        p = str(d / fm.share_filename(bid, i))
        fm.write_share(_share(bid, i), p)
        paths.append(p)
    return d, bid, blob, manifest, paths


# --- F1: manifiesto ---------------------------------------------------------------


def test_F1_roundtrip_manifiesto(tmp_path):
    bid, blob = fm.new_backup_id(), _blob()
    m = fm.make_manifest(bid, blob)
    path = str(tmp_path / "m.json")
    fm.write_manifest(m, path)
    assert fm.read_manifest(path) == m
    import hashlib
    assert m.package_checksum == "sha256:" + hashlib.sha256(blob).hexdigest()
    assert m.package_size == len(blob)
    assert (m.version, m.threshold, m.total_shares) == (1, 3, 5)
    assert m.algorithm == "ChaCha20-Poly1305"


def test_manifiesto_json_es_legible_y_sin_secretos(tmp_path):
    m = fm.make_manifest(fm.new_backup_id(), _blob())
    path = str(tmp_path / "m.json")
    fm.write_manifest(m, path)
    data = json.loads(open(path, encoding="utf-8").read())
    assert list(data) == [
        "format", "version", "backup_id", "created_at", "algorithm",
        "sharing_scheme", "threshold", "total_shares", "package_size", "package_checksum",
    ]
    assert data["format"] == "EVLP-MANIFEST"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", data["created_at"])


# --- F2 / F3: participación --------------------------------------------------------


def test_F2_roundtrip_participacion(tmp_path):
    s = _share(fm.new_backup_id(), 2)
    path = str(tmp_path / "s.json")
    fm.write_share(s, path)
    assert fm.read_share(path) == s


@pytest.mark.parametrize("value", [
    b"\x00" * 66,
    b"\x00\x00\x07" + b"\xab" * 63,
    (P - 1).to_bytes(66, "big"),
    (1).to_bytes(66, "big"),
])
def test_F3_valores_borde_conservan_66_bytes(tmp_path, value):
    s = _share(fm.new_backup_id(), 1, value)
    path = str(tmp_path / "s.json")
    fm.write_share(s, path)
    back = fm.read_share(path)
    assert back.value == value and len(back.value) == 66


# --- F4: validate_share camino feliz ------------------------------------------------


def test_F4_participacion_valida():
    bid = fm.new_backup_id()
    manifest = fm.make_manifest(bid, _blob())
    s = _share(bid, 3)
    assert fm.validate_share(s, manifest) is True
    assert fm.diagnose_share(s, manifest) is None


# --- F5 / F6 / F7: daño y mezcla -----------------------------------------------------


def test_F5_valor_alterado_sin_recalcular_checksum():
    bid = fm.new_backup_id()
    manifest = fm.make_manifest(bid, _blob())
    s = _share(bid, 1)
    altered = bytearray(s.value)
    altered[-1] ^= 0x01
    bad = dataclasses.replace(s, value=bytes(altered))
    assert fm.validate_share(bad, manifest) is False
    assert fm.diagnose_share(bad, manifest) == fm.REASON_DAMAGED


def test_F6_indice_alterado_sin_recalcular_checksum():
    bid = fm.new_backup_id()
    manifest = fm.make_manifest(bid, _blob())
    bad = dataclasses.replace(_share(bid, 2), index=3)
    assert fm.validate_share(bad, manifest) is False
    assert fm.diagnose_share(bad, manifest) == fm.REASON_DAMAGED


def test_F7_participacion_de_otro_respaldo_con_checksum_correcto():
    manifest = fm.make_manifest(fm.new_backup_id(), _blob())
    foreign = _share(fm.new_backup_id(), 1)  # checksum recalculado correctamente
    assert fm.validate_share(foreign, manifest) is False
    assert fm.diagnose_share(foreign, manifest) == fm.REASON_OTHER_BACKUP


def test_participacion_con_parametros_distintos_al_manifiesto_es_danada():
    bid = fm.new_backup_id()
    manifest = fm.make_manifest(bid, _blob())
    other = dataclasses.replace(manifest, created_at="2020-01-01T00:00:00Z")
    assert fm.validate_share(_share(bid, 1), other) is True  # created_at no interviene
    odd = _share(bid, 1)
    odd.sharing_scheme = "otro-esquema"
    assert fm.diagnose_share(odd, manifest) == fm.REASON_DAMAGED


def test_diagnose_share_con_objeto_roto_no_lanza():
    manifest = fm.make_manifest(fm.new_backup_id(), _blob())
    assert fm.diagnose_share(object(), manifest) == fm.REASON_DAMAGED


# --- F8: índices -----------------------------------------------------------------------


@pytest.mark.parametrize("index", [0, 6, -1, 255, 2.5, "2", True, None])
def test_F8_indice_invalido_en_archivo(tmp_path, index):
    path = str(tmp_path / "s.json")
    fm.write_share(_share(fm.new_backup_id(), 1), path)
    _edit_json(path, lambda d: d.update(index=index))
    with pytest.raises(FormatError):
        fm.read_share(path)


@pytest.mark.parametrize("index", [0, 6, -1, 2.5, True])
def test_F8_indice_invalido_en_make_share(index):
    with pytest.raises(FormatError):
        fm.make_share(fm.new_backup_id(), index, _value())


# --- F9: valor -------------------------------------------------------------------------


@pytest.mark.parametrize("bad_value", [
    "",
    "00" * 65,
    "00" * 67,
    "zz" * 66,
    "AB" * 66,
    P.to_bytes(66, "big").hex(),  # valor == p
    (P + 1).to_bytes(66, "big").hex(),
    12345,
    None,
])
def test_F9_valor_invalido(tmp_path, bad_value):
    path = str(tmp_path / "s.json")
    fm.write_share(_share(fm.new_backup_id(), 1), path)
    _edit_json(path, lambda d: d.update(value=bad_value))
    with pytest.raises(FormatError):
        fm.read_share(path)


@pytest.mark.parametrize("bad_value", [b"", b"\x00" * 65, b"\x00" * 67, P.to_bytes(66, "big"), "x" * 66])
def test_F9_valor_invalido_en_make_share(bad_value):
    with pytest.raises(FormatError):
        fm.make_share(fm.new_backup_id(), 1, bad_value)


# --- F10: lectura estricta ---------------------------------------------------------------


@pytest.mark.parametrize("text", ["", "{", "[]", "null", "42", '"texto"', '{"a": NaN}', "{}"])
def test_F10_json_invalido_o_vacio(tmp_path, text):
    path = str(tmp_path / "x.json")
    _write_text(path, text)
    with pytest.raises(FormatError):
        fm.read_share(path)
    with pytest.raises(FormatError):
        fm.read_manifest(path)


def test_F10_no_es_utf8(tmp_path):
    path = str(tmp_path / "x.json")
    with open(path, "wb") as f:
        f.write(b"\xff\xfe\x00{")
    with pytest.raises(FormatError):
        fm.read_share(path)


def test_F10_archivo_demasiado_grande(tmp_path):
    path = str(tmp_path / "x.json")
    _write_text(path, " " * (fm.MAX_JSON_SIZE + 1))
    with pytest.raises(FormatError):
        fm.read_manifest(path)


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(version=2),
    lambda d: d.update(version="1"),
    lambda d: d.update(version=True),
    lambda d: d.update(format="OTRO"),
    lambda d: d.pop("checksum"),
    lambda d: d.pop("backup_id"),
    lambda d: d.update(extra="x"),
    lambda d: d.update(backup_id="no-es-hex"),
    lambda d: d.update(backup_id="A" * 32),  # mayúsculas
    lambda d: d.update(checksum="sha256:" + "0" * 63),
    lambda d: d.update(checksum="md5:" + "0" * 32),
    lambda d: d.update(sharing_scheme="otro"),
])
def test_F10_campos_invalidos_en_participacion(tmp_path, mutate):
    path = str(tmp_path / "s.json")
    fm.write_share(_share(fm.new_backup_id(), 1), path)
    _edit_json(path, mutate)
    with pytest.raises(FormatError):
        fm.read_share(path)


def test_F10_clave_duplicada(tmp_path):
    path = str(tmp_path / "s.json")
    fm.write_share(_share(fm.new_backup_id(), 1), path)
    text = open(path, encoding="utf-8").read()
    _write_text(path, text.replace('"index": 1', '"index": 1, "index": 2'))
    with pytest.raises(FormatError):
        fm.read_share(path)


def test_F10_un_manifiesto_no_es_participacion_y_viceversa(tmp_path):
    bid = fm.new_backup_id()
    mp, sp = str(tmp_path / "m.json"), str(tmp_path / "s.json")
    fm.write_manifest(fm.make_manifest(bid, _blob()), mp)
    fm.write_share(_share(bid, 1), sp)
    with pytest.raises(FormatError):
        fm.read_share(mp)
    with pytest.raises(FormatError):
        fm.read_manifest(sp)


# --- F11: duplicados ------------------------------------------------------------------------


def test_F11_find_duplicate_indices():
    bid = fm.new_backup_id()
    shares = [_share(bid, i) for i in (1, 2, 2, 3, 3, 3, 5)]
    assert fm.find_duplicate_indices(shares) == [2, 3]
    assert fm.find_duplicate_indices(shares[:1]) == []
    assert fm.find_duplicate_indices([]) == []


def test_F11_duplicados_con_valores_distintos_cuentan_una_sola_vez(tmp_path):
    d, bid, _blob_, manifest, paths = _backup_dir(tmp_path)
    twin = str(d / "copia.json")
    fm.write_share(_share(bid, 1), twin)  # mismo índice 1, otro valor, checksum válido
    valid, rejected = fm.load_shares([paths[0], twin, paths[1]], manifest)
    assert sorted(s.index for s in valid) == [1, 2]
    assert rejected == [(twin, fm.REASON_DUPLICATE)]


def test_load_shares_clasifica_cada_rechazo(tmp_path):
    d, bid, _blob_, manifest, paths = _backup_dir(tmp_path)
    repetida = str(d / "repetida.json")
    with open(paths[0], "rb") as src, open(repetida, "wb") as dst:
        dst.write(src.read())
    alterada = str(d / "alterada.json")
    with open(paths[1], "rb") as src, open(alterada, "wb") as dst:
        dst.write(src.read())
    _edit_json(alterada, lambda x: x.update(value="00" * 65 + "01"))
    ajena = str(d / "ajena.json")
    fm.write_share(_share(fm.new_backup_id(), 4), ajena)
    basura = str(d / "basura.json")
    _write_text(basura, "esto no es json")

    valid, rejected = fm.load_shares([paths[0], repetida, alterada, ajena, basura, paths[2]], manifest)
    assert [s.index for s in valid] == [1, 3]
    assert dict(rejected) == {
        repetida: fm.REASON_DUPLICATE,
        alterada: fm.REASON_DAMAGED,
        ajena: fm.REASON_OTHER_BACKUP,
        basura: fm.REASON_DAMAGED,
    }


def test_load_shares_una_danada_no_tapa_a_la_sana_del_mismo_indice(tmp_path):
    d, bid, _blob_, manifest, paths = _backup_dir(tmp_path)
    mala = str(d / "mala.json")
    with open(paths[0], "rb") as src, open(mala, "wb") as dst:
        dst.write(src.read())
    _edit_json(mala, lambda x: x.update(value="00" + "11" * 65))
    valid, rejected = fm.load_shares([mala, paths[0]], manifest)
    assert [s.index for s in valid] == [1]
    assert rejected == [(mala, fm.REASON_DAMAGED)]


def test_load_shares_archivo_inexistente_propaga(tmp_path):
    d, bid, _blob_, manifest, paths = _backup_dir(tmp_path)
    with pytest.raises(FileNotFoundError):
        fm.load_shares([str(d / "no-existe.json")], manifest)


# --- F12: paquete ----------------------------------------------------------------------------


def test_F12_verify_package_ok_y_alteraciones(tmp_path):
    blob = _blob(5000)
    m = fm.make_manifest(fm.new_backup_id(), blob)
    assert fm.verify_package(blob, m) is True

    flipped = bytearray(blob)
    flipped[len(flipped) // 2] ^= 0x01
    assert fm.verify_package(bytes(flipped), m) is False  # mismo tamaño, otro contenido
    assert fm.verify_package(blob + b"\x00", m) is False  # bytes extra
    assert fm.verify_package(blob[:-1], m) is False  # truncado
    assert fm.verify_package(blob, dataclasses.replace(m, package_checksum="sha256:" + "0" * 64)) is False
    assert fm.verify_package(blob, dataclasses.replace(m, package_size=m.package_size + 1)) is False


def test_F12_roundtrip_del_paquete_en_disco(tmp_path):
    blob = _blob(10_000)
    path = str(tmp_path / "p.evlp")
    fm.write_package(blob, path)
    assert fm.read_package(path) == blob


def test_paquete_fuera_de_rango_se_rechaza(tmp_path):
    with pytest.raises(FormatError):
        fm.write_package(b"x" * (fm.MIN_BLOB_SIZE - 1), str(tmp_path / "p.evlp"))
    small = str(tmp_path / "chico.evlp")
    with open(small, "wb") as f:
        f.write(b"x" * 10)
    with pytest.raises(FormatError):
        fm.read_package(small)
    original = fm.MAX_BLOB_SIZE
    try:
        fm.MAX_BLOB_SIZE = 100
        grande = str(tmp_path / "grande.evlp")
        with open(grande, "wb") as f:
            f.write(b"x" * 101)
        with pytest.raises(FormatError):
            fm.read_package(grande)
    finally:
        fm.MAX_BLOB_SIZE = original


# --- F13: parámetros del manifiesto ------------------------------------------------------------


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(threshold=2),
    lambda d: d.update(threshold=4),
    lambda d: d.update(total_shares=6),
    lambda d: d.update(total_shares="5"),
    lambda d: d.update(algorithm="AES-256-GCM"),
    lambda d: d.update(sharing_scheme="shamir-gf256"),
    lambda d: d.update(package_size=-1),
    lambda d: d.update(package_size=10),
    lambda d: d.update(package_size=2.5),
    lambda d: d.update(package_checksum="sha256:xyz"),
    lambda d: d.update(created_at="ayer"),
    lambda d: d.update(created_at="2026-13-45T25:61:61Z"),
    lambda d: d.update(version=2),
    lambda d: d.update(extra=1),
    lambda d: d.pop("package_size"),
])
def test_F13_manifiesto_invalido(tmp_path, mutate):
    path = str(tmp_path / "m.json")
    fm.write_manifest(fm.make_manifest(fm.new_backup_id(), _blob()), path)
    _edit_json(path, mutate)
    with pytest.raises(FormatError):
        fm.read_manifest(path)


def test_write_no_escribe_archivos_invalidos(tmp_path):
    m = fm.make_manifest(fm.new_backup_id(), _blob())
    path = str(tmp_path / "m.json")
    with pytest.raises(FormatError):
        fm.write_manifest(dataclasses.replace(m, threshold=2), path)
    s = _share(fm.new_backup_id(), 1)
    sp = str(tmp_path / "s.json")
    with pytest.raises(FormatError):
        fm.write_share(dataclasses.replace(s, index=0), sp)
    assert os.listdir(str(tmp_path)) == []  # ni destino ni temporales


# --- F14: el valor no se filtra ------------------------------------------------------------------


def test_F14_repr_y_str_no_contienen_el_valor():
    s = _share(fm.new_backup_id(), 1)
    for text in (repr(s), str(s), f"{s}", repr([s])):
        assert s.value.hex() not in text
        assert "value" not in text


def test_F14_errores_no_contienen_el_valor(tmp_path):
    path = str(tmp_path / "s.json")
    s = _share(fm.new_backup_id(), 1)
    fm.write_share(s, path)
    _edit_json(path, lambda d: d.update(index=0))
    with pytest.raises(FormatError) as exc:
        fm.read_share(path)
    assert s.value.hex() not in str(exc.value)


def test_F14_inspect_file_no_revela_el_valor(tmp_path):
    bid = fm.new_backup_id()
    s = _share(bid, 4)
    sp, mp = str(tmp_path / "s.json"), str(tmp_path / "m.json")
    fm.write_share(s, sp)
    fm.write_manifest(fm.make_manifest(bid, _blob()), mp)

    info = fm.inspect_file(sp)
    assert info["type"] == "share" and info["index"] == 4 and info["backup_id"] == bid
    assert info["checksum_ok"] is True
    assert "value" not in info and s.value.hex() not in json.dumps(info)

    minfo = fm.inspect_file(mp)
    assert minfo["type"] == "manifest" and minfo["threshold"] == 3 and minfo["total_shares"] == 5


def test_inspect_file_detecta_checksum_malo_sin_fallar(tmp_path):
    path = str(tmp_path / "s.json")
    fm.write_share(_share(fm.new_backup_id(), 1), path)
    _edit_json(path, lambda d: d.update(value="00" + "11" * 65))
    assert fm.inspect_file(path)["checksum_ok"] is False


def test_inspect_file_tipo_desconocido(tmp_path):
    path = str(tmp_path / "x.json")
    _write_text(path, '{"format": "OTRO"}')
    with pytest.raises(FormatError):
        fm.inspect_file(path)


# --- F15: búsqueda de archivos ------------------------------------------------------------------------


def test_F15_locate_files_por_backup_id_y_automatico(tmp_path):
    d, bid, _blob_, _m, _paths = _backup_dir(tmp_path)
    mp, pp = fm.locate_files(str(d), bid)
    assert os.path.basename(mp) == f"{bid}.manifest.json"
    assert os.path.basename(pp) == f"{bid}.evlp"
    assert fm.locate_files(str(d)) == (mp, pp)


def test_F15_varios_respaldos_en_la_misma_carpeta(tmp_path):
    d, bid, _blob_, _m, _paths = _backup_dir(tmp_path)
    other = fm.new_backup_id()
    blob2 = _blob()
    fm.write_manifest(fm.make_manifest(other, blob2), str(d / fm.manifest_filename(other)))
    fm.write_package(blob2, str(d / fm.package_filename(other)))
    with pytest.raises(FormatError):  # ambiguo sin backup_id
        fm.locate_files(str(d))
    assert os.path.basename(fm.locate_files(str(d), other)[0]) == f"{other}.manifest.json"
    assert os.path.basename(fm.locate_files(str(d), bid)[1]) == f"{bid}.evlp"


def test_F15_faltantes_dicen_cual_archivo(tmp_path):
    d, bid, _blob_, _m, _paths = _backup_dir(tmp_path)
    os.remove(str(d / fm.package_filename(bid)))
    with pytest.raises(FormatError) as exc:
        fm.locate_files(str(d), bid)
    assert ".evlp" in str(exc.value) and "manifest" not in str(exc.value)
    os.remove(str(d / fm.manifest_filename(bid)))
    with pytest.raises(FormatError) as exc:
        fm.locate_files(str(d), bid)
    assert ".evlp" in str(exc.value) and "manifest" in str(exc.value)
    with pytest.raises(FormatError):  # carpeta sin manifiestos
        fm.locate_files(str(d))


def test_locate_files_rechaza_backup_id_con_ruta():
    with pytest.raises(FormatError):
        fm.locate_files(".", "../../etc/passwd")


def test_infer_backup_id(tmp_path):
    d, bid, _blob_, _m, paths = _backup_dir(tmp_path)
    ajena = str(d / "ajena.json")
    fm.write_share(_share(fm.new_backup_id(), 1), ajena)
    basura = str(d / "basura.json")
    _write_text(basura, "nada")
    assert fm.infer_backup_id(paths[:3] + [ajena, basura]) == bid
    with pytest.raises(FormatError):  # empate 1 a 1 (el mismo índice repetido cuenta una vez)
        fm.infer_backup_id([paths[0], paths[0], ajena])
    with pytest.raises(FormatError):
        fm.infer_backup_id([basura])


# --- F16: tamaños y experimento ------------------------------------------------------------------------


def test_F16_tamano_de_los_archivos(tmp_path):
    bid = fm.new_backup_id()
    sp, mp = str(tmp_path / "s.json"), str(tmp_path / "m.json")
    fm.write_share(_share(bid, 1), sp)
    fm.write_manifest(fm.make_manifest(bid, _blob()), mp)
    assert os.path.getsize(sp) < 600  # ~0,4 KB por participación
    assert os.path.getsize(mp) < 600
    # tamaño constante: no depende del valor
    other = str(tmp_path / "s2.json")
    fm.write_share(_share(bid, 1, b"\x00" * 66), other)
    assert abs(os.path.getsize(sp) - os.path.getsize(other)) == 0


# --- Escritura atómica y permisos -----------------------------------------------------------------------


def test_escritura_atomica_sobrescribe_sin_dejar_temporales(tmp_path):
    bid = fm.new_backup_id()
    path = str(tmp_path / "sub" / "dir" / "s.json")  # crea carpetas intermedias
    fm.write_share(_share(bid, 1), path)
    second = _share(bid, 1)
    fm.write_share(second, path)
    assert fm.read_share(path) == second
    assert os.listdir(os.path.dirname(path)) == ["s.json"]


@pytest.mark.skipif(os.name != "posix", reason="permisos POSIX")
def test_permisos_participacion_0600_y_manifiesto_0644(tmp_path):
    bid = fm.new_backup_id()
    sp, mp = str(tmp_path / "s.json"), str(tmp_path / "m.json")
    fm.write_share(_share(bid, 1), sp)
    fm.write_manifest(fm.make_manifest(bid, _blob()), mp)
    assert os.stat(sp).st_mode & 0o777 == 0o600
    assert os.stat(mp).st_mode & 0o777 == 0o644


# --- Identificador y checksum ----------------------------------------------------------------------------


def test_backup_id_y_bytes_crudos():
    bid = fm.new_backup_id()
    assert re.fullmatch(r"[0-9a-f]{32}", bid)
    assert fm.backup_id_to_bytes(bid) == bytes.fromhex(bid) and len(fm.backup_id_to_bytes(bid)) == 16
    assert fm.new_backup_id() != fm.new_backup_id()
    with pytest.raises(FormatError):
        fm.backup_id_to_bytes("zz")


def test_checksum_de_participacion_cubre_todos_los_campos():
    bid = fm.new_backup_id()
    v = _value()
    base = fm.compute_share_checksum(bid, 1, 1, 3, 5, v)
    assert base == fm.compute_share_checksum(bid, 1, 1, 3, 5, v)  # determinista
    assert base != fm.compute_share_checksum(bid, 1, 2, 3, 5, v)  # índice
    assert base != fm.compute_share_checksum(fm.new_backup_id(), 1, 1, 3, 5, v)  # backup_id
    flipped = bytearray(v)
    flipped[0] ^= 0x80
    if int.from_bytes(flipped, "big") < P:
        assert base != fm.compute_share_checksum(bid, 1, 1, 3, 5, bytes(flipped))  # valor
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", base)


def test_checksum_del_paquete_por_bloques_coincide_con_hashlib():
    import hashlib
    blob = os.urandom(fm._HASH_CHUNK * 2 + 123)
    assert fm.package_checksum(blob) == "sha256:" + hashlib.sha256(blob).hexdigest()
    assert fm.package_checksum(b"") == "sha256:" + hashlib.sha256(b"").hexdigest()


def test_make_share_acepta_bytearray_y_make_manifest_valida_fecha():
    bid = fm.new_backup_id()
    s = fm.make_share(bid, 1, bytearray(_value()))
    assert isinstance(s.value, bytes)
    with pytest.raises(FormatError):
        fm.make_manifest(bid, _blob(), created_at="mañana")
    with pytest.raises(FormatError):
        fm.make_manifest("no-valido", _blob())


# --- Independencia y coherencia con los otros módulos ----------------------------------------------------


def test_formats_no_importa_a_los_demas_modulos():
    source = open(fm.__file__, encoding="utf-8").read()
    for name in ("crypto_core", "shamir", "packaging_", "exceptions"):
        assert not re.search(rf"^\s*(import|from)\s+{name}\b", source, re.MULTILINE), name


def test_constantes_coinciden_con_shamir():
    shamir = pytest.importorskip("shamir")
    assert fm.FIELD_PRIME == shamir.P
    assert fm.SHARE_VALUE_SIZE == shamir.SHARE_VALUE_SIZE
    assert fm.SHARING_SCHEME == shamir.SHARING_SCHEME
    assert fm.TOTAL_SHARES == 5 and fm.THRESHOLD == 3


def test_constantes_coinciden_con_crypto_core():
    cc = pytest.importorskip("crypto_core")
    assert fm.MIN_BLOB_SIZE == cc.FORMAT_OVERHEAD
    assert fm.ALGORITHM_NAME == cc.ALGORITHM_NAMES[cc.ALG_CHACHA20_POLY1305]
    assert fm.BACKUP_ID_SIZE == cc.BACKUP_ID_SIZE
    assert fm.FORMAT_VERSION == cc.VERSION


# --- Integración A + B + C -----------------------------------------------------------------------------------


def _crear(tmp_path):
    """Crea un respaldo como lo hará el orquestador: A -> B -> C."""
    cc = pytest.importorskip("crypto_core")
    pk = pytest.importorskip("packaging_")
    sh = pytest.importorskip("shamir")

    origen = tmp_path / "origen"
    (origen / "a" / "b").mkdir(parents=True)
    (origen / "vacio.bin").write_bytes(b"")
    contenido = os.urandom(3000)
    (origen / "a" / "b" / "datos.bin").write_bytes(contenido)

    salida = tmp_path / "respaldo"
    bid = fm.new_backup_id()
    key = cc.generate_key()
    blob = cc.encrypt_blob(key, pk.pack_source(str(origen)), fm.backup_id_to_bytes(bid))
    shares = sh.split_secret(bytes(key), fm.THRESHOLD, fm.TOTAL_SHARES)
    cc.wipe(key)

    fm.write_package(blob, str(salida / fm.package_filename(bid)))
    fm.write_manifest(fm.make_manifest(bid, blob), str(salida / fm.manifest_filename(bid)))
    paths = []
    for index, value in shares:
        p = str(salida / fm.share_filename(bid, index))
        fm.write_share(fm.make_share(bid, index, value), p)
        paths.append(p)
    return cc, pk, sh, salida, bid, paths, contenido


def _restaurar(tmp_path, cc, pk, sh, salida, share_paths, destino):
    """Restaura como lo hará el orquestador: C -> B -> A."""
    bid = fm.infer_backup_id(share_paths)
    manifest_path, package_path = fm.locate_files(str(salida), bid)
    manifest = fm.read_manifest(manifest_path)
    blob = fm.read_package(package_path)
    assert fm.verify_package(blob, manifest)
    header = cc.parse_header(blob)
    assert header["version"] == manifest.version and header["algorithm"] == manifest.algorithm

    valid, rejected = fm.load_shares(share_paths, manifest)
    key = bytearray(sh.reconstruct_secret([(s.index, s.value) for s in valid], manifest.threshold))
    try:
        payload = cc.decrypt_blob(key, blob, fm.backup_id_to_bytes(manifest.backup_id))
    finally:
        cc.wipe(key)
    pk.unpack_output(payload, str(destino))
    return rejected


def test_integracion_las_diez_combinaciones_restauran(tmp_path):
    cc, pk, sh, salida, bid, paths, contenido = _crear(tmp_path)
    for n, combo in enumerate(itertools.combinations(paths, 3)):
        destino = tmp_path / f"rest{n}"
        rechazadas = _restaurar(tmp_path, cc, pk, sh, salida, list(combo), destino)
        assert rechazadas == []
        assert (destino / "origen" / "a" / "b" / "datos.bin").read_bytes() == contenido
        assert (destino / "origen" / "vacio.bin").read_bytes() == b""


def test_integracion_dos_participaciones_no_alcanzan(tmp_path):
    cc, pk, sh, salida, bid, paths, _c = _crear(tmp_path)
    with pytest.raises(sh.InsufficientSharesError):
        _restaurar(tmp_path, cc, pk, sh, salida, paths[:2], tmp_path / "x")
    assert not (tmp_path / "x").exists()


def test_integracion_repetida_ajena_y_danada_se_descartan(tmp_path):
    cc, pk, sh, salida, bid, paths, contenido = _crear(tmp_path)
    ajena = str(salida / "ajena.json")
    fm.write_share(fm.make_share(fm.new_backup_id(), 2, _value()), ajena)
    danada = str(salida / "danada.json")
    with open(paths[3], "rb") as src, open(danada, "wb") as dst:
        dst.write(src.read())
    _edit_json(danada, lambda d: d.update(value="00" + "22" * 65))

    destino = tmp_path / "rest"
    rechazadas = _restaurar(tmp_path, cc, pk, sh, salida,
                            [paths[0], paths[0], ajena, danada, paths[1], paths[2]], destino)
    assert sorted(reason for _p, reason in rechazadas) == sorted(
        [fm.REASON_DUPLICATE, fm.REASON_OTHER_BACKUP, fm.REASON_DAMAGED])
    assert (destino / "origen" / "a" / "b" / "datos.bin").read_bytes() == contenido


def test_integracion_paquete_alterado_se_detecta_antes_de_descifrar(tmp_path):
    cc, pk, sh, salida, bid, paths, _c = _crear(tmp_path)
    pkg = str(salida / fm.package_filename(bid))
    data = bytearray(open(pkg, "rb").read())
    data[len(data) // 2] ^= 0x01
    with open(pkg, "wb") as f:
        f.write(bytes(data))
    manifest = fm.read_manifest(str(salida / fm.manifest_filename(bid)))
    assert fm.verify_package(fm.read_package(pkg), manifest) is False


def test_integracion_participacion_alterada_con_checksum_recalculado(tmp_path):
    """El checksum no es un MAC: lo atrapan Shamir (valor imposible) o AEAD."""
    cc, pk, sh, salida, bid, paths, _c = _crear(tmp_path)
    original = fm.read_share(paths[0])
    flipped = bytearray(original.value)
    flipped[-1] ^= 0x01
    falsa = fm.make_share(bid, original.index, bytes(flipped))  # checksum "correcto"
    falsa_path = str(salida / "falsa.json")
    fm.write_share(falsa, falsa_path)

    manifest = fm.read_manifest(str(salida / fm.manifest_filename(bid)))
    assert fm.validate_share(falsa, manifest) is True  # el formato no la puede detectar
    with pytest.raises((sh.ShamirError, cc.AuthenticationError)):
        _restaurar(tmp_path, cc, pk, sh, salida, [falsa_path, paths[1], paths[2]], tmp_path / "y")
    assert not (tmp_path / "y").exists()
