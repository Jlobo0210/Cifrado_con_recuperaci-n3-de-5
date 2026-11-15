import io
import os
import stat
import sys
import tarfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import packaging_ as pk  # noqa: E402
from exceptions import ExtractionError, PayloadTooLargeError  # noqa: E402


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

    # Espía: el rechazo preliminar debe ocurrir ANTES de construir el tar.
    llamadas = []
    original_open = tarfile.open

    def spy_open(*args, **kwargs):
        llamadas.append((args, kwargs))
        return original_open(*args, **kwargs)

    monkeypatch.setattr(pk.tarfile, "open", spy_open)

    with pytest.raises(PayloadTooLargeError):
        pk.pack_source(str(source))
    assert llamadas == [], "tarfile.open no debe invocarse si falla el chequeo preliminar"


def test_archivo_vacio(tmp_path):
    source = tmp_path / "vacio.txt"
    source.write_bytes(b"")

    payload = pk.pack_source(str(source))
    dest = tmp_path / "restaurado"
    pk.unpack_output(payload, str(dest))

    assert (dest / "vacio.txt").read_bytes() == b""


# --- Casos adicionales del Entregable 2 -----------------------------------------

def _tar_gz(members):
    """Construye un tar.gz en memoria a partir de [(TarInfo, bytes|None)]."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def _file(name, data=b"x"):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows no tiene bits de permisos POSIX (chmod 0o755 no marca ejecución).",
)
def test_case4_preserva_bit_de_ejecucion(tmp_path):
    source = tmp_path / "origen"
    source.mkdir()
    script = source / "run.sh"
    script.write_text("#!/bin/sh\necho hola\n")
    script.chmod(0o755)
    datos = source / "datos.txt"
    datos.write_text("hola")
    datos.chmod(0o644)

    dest = tmp_path / "restaurado"
    pk.unpack_output(pk.pack_source(str(source)), str(dest))

    assert os.stat(dest / "origen" / "run.sh").st_mode & stat.S_IXUSR
    assert not os.stat(dest / "origen" / "datos.txt").st_mode & stat.S_IXUSR


def test_directorio_vacio_y_nombres_unicode(tmp_path):
    source = tmp_path / "origen"
    (source / "vacío").mkdir(parents=True)
    (source / "año_ñandú.txt").write_text("contenido", encoding="utf-8")

    dest = tmp_path / "restaurado"
    pk.unpack_output(pk.pack_source(str(source)), str(dest))

    assert (dest / "origen" / "vacío").is_dir()
    assert (dest / "origen" / "año_ñandú.txt").read_text(encoding="utf-8") == "contenido"


def test_ruta_relativa_punto(tmp_path, monkeypatch):
    source = tmp_path / "carpeta"
    source.mkdir()
    (source / "a.txt").write_text("a")
    monkeypatch.chdir(source)

    dest = tmp_path / "restaurado"
    pk.unpack_output(pk.pack_source("."), str(dest))
    assert (dest / "carpeta" / "a.txt").read_text() == "a"


def test_compresion_reduce_contenido_repetitivo(tmp_path):
    source = tmp_path / "texto.txt"
    source.write_bytes(b"A" * 1_000_000)
    assert len(pk.pack_source(str(source))) < 10_000


def test_ruta_inexistente(tmp_path):
    with pytest.raises(FileNotFoundError):
        pk.pack_source(str(tmp_path / "no-existe"))


def test_payload_corrupto_lanza_extraction_error(tmp_path):
    dest = tmp_path / "restaurado"
    with pytest.raises(ExtractionError):
        pk.unpack_output(b"esto no es un tar.gz", str(dest))
    assert list(dest.iterdir()) == []  # sin restos del directorio temporal


@pytest.mark.parametrize("nombre", ["../fuera.txt", "a/../../fuera.txt", "/etc/fuera.txt"])
def test_path_traversal_rechazado(tmp_path, nombre):
    payload = _tar_gz([_file(nombre)])
    dest = tmp_path / "restaurado"
    with pytest.raises(ExtractionError):
        pk.unpack_output(payload, str(dest))
    assert not (tmp_path / "fuera.txt").exists()
    assert list(dest.iterdir()) == []


@pytest.mark.parametrize("destino", ["/etc/passwd", "../../fuera", "sub/../../fuera"])
def test_symlink_que_sale_del_destino_rechazado(tmp_path, destino):
    link = tarfile.TarInfo("enlace")
    link.type = tarfile.SYMTYPE
    link.linkname = destino
    with pytest.raises(ExtractionError):
        pk.unpack_output(_tar_gz([(link, None)]), str(tmp_path / "restaurado"))


def test_symlink_interno_permitido(tmp_path):
    link = tarfile.TarInfo("dir/enlace")
    link.type = tarfile.SYMTYPE
    link.linkname = "real.txt"
    payload = _tar_gz([_file("dir/real.txt", b"hola"), (link, None)])
    dest = tmp_path / "restaurado"
    pk.unpack_output(payload, str(dest))
    assert (dest / "dir" / "enlace").read_bytes() == b"hola"


def test_dispositivo_rechazado(tmp_path):
    dev = tarfile.TarInfo("disp")
    dev.type = tarfile.CHRTYPE
    with pytest.raises(ExtractionError):
        pk.unpack_output(_tar_gz([(dev, None)]), str(tmp_path / "restaurado"))


def test_extraccion_todo_o_nada(tmp_path):
    """Si una entrada es peligrosa, no se escribe NINGUNA (ni las válidas)."""
    payload = _tar_gz([_file("valido.txt", b"ok"), _file("../malo.txt")])
    dest = tmp_path / "restaurado"
    with pytest.raises(ExtractionError):
        pk.unpack_output(payload, str(dest))
    assert list(dest.iterdir()) == []


def test_no_sobrescribe_archivos_existentes(tmp_path):
    source = tmp_path / "informe.txt"
    source.write_text("nuevo")
    dest = tmp_path / "restaurado"
    dest.mkdir()
    (dest / "informe.txt").write_text("del usuario")
    otro = dest / "otro.txt"
    otro.write_text("intacto")

    with pytest.raises(ExtractionError):
        pk.unpack_output(pk.pack_source(str(source)), str(dest))

    assert (dest / "informe.txt").read_text() == "del usuario"
    assert sorted(p.name for p in dest.iterdir()) == ["informe.txt", "otro.txt"]


def test_restaurar_en_directorio_con_otros_archivos(tmp_path):
    source = tmp_path / "nuevo.txt"
    source.write_text("nuevo")
    dest = tmp_path / "restaurado"
    dest.mkdir()
    (dest / "previo.txt").write_text("previo")

    pk.unpack_output(pk.pack_source(str(source)), str(dest))
    assert sorted(p.name for p in dest.iterdir()) == ["nuevo.txt", "previo.txt"]
