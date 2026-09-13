import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import packaging_ as pk  # noqa: E402
from exceptions import PayloadTooLargeError  # noqa: E402


def _make_tree(base):
    """Crea un árbol: base/file1.txt, base/sub/file2.bin, base/sub/deep/file3.txt"""
    os.makedirs(os.path.join(base, "sub", "deep"), exist_ok=True)
    with open(os.path.join(base, "file1.txt"), "w") as f:
        f.write("hola mundo")
    with open(os.path.join(base, "sub", "file2.bin"), "wb") as f:
        f.write(os.urandom(1024))
    with open(os.path.join(base, "sub", "deep", "file3.txt"), "w") as f:
        f.write("archivo anidado")


def test_case4_directorio_anidado(tmp_path):
    source = tmp_path / "origen"
    source.mkdir()
    _make_tree(str(source))

    payload = pk.pack_source(str(source))

    dest = tmp_path / "restaurado"
    pk.unpack_output(payload, str(dest))

    restored_root = dest / "origen"
    assert (restored_root / "file1.txt").read_text() == "hola mundo"
    assert (restored_root / "sub" / "file2.bin").stat().st_size == 1024
    assert (restored_root / "sub" / "deep" / "file3.txt").read_text() == "archivo anidado"


def test_case5_archivo_individual(tmp_path):
    source = tmp_path / "informe.pdf"
    source.write_bytes(b"%PDF-contenido-simulado")

    payload = pk.pack_source(str(source))

    dest = tmp_path / "restaurado"
    pk.unpack_output(payload, str(dest))

    assert (dest / "informe.pdf").read_bytes() == b"%PDF-contenido-simulado"


def test_case7_excede_limite_autoritativo(tmp_path, monkeypatch):
    monkeypatch.setattr(pk, "MAX_PACKAGE_SIZE", 100)
    source = tmp_path / "grande.bin"
    source.write_bytes(os.urandom(10_000))

    with pytest.raises(PayloadTooLargeError):
        pk.pack_source(str(source))


def test_case8_excede_umbral_preliminar(tmp_path, monkeypatch):
    monkeypatch.setattr(pk, "PRELIMINARY_SIZE_HINT", 100)
    source = tmp_path / "grande.bin"
    source.write_bytes(os.urandom(10_000))

    with pytest.raises(PayloadTooLargeError):
        pk.pack_source(str(source))


def test_archivo_vacio(tmp_path):
    source = tmp_path / "vacio.txt"
    source.write_bytes(b"")

    payload = pk.pack_source(str(source))
    dest = tmp_path / "restaurado"
    pk.unpack_output(payload, str(dest))

    assert (dest / "vacio.txt").read_bytes() == b""