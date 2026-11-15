"""Flujo completo de la parte de cifrado de envolvente (persona A):

    pack_source -> encrypt_blob -> decrypt_blob -> unpack_output

No usa Shamir ni formatos: la clave se pasa directamente. Verifica que los
dos módulos de A encajan y que la extracción solo ocurre tras AEAD válido.
"""
import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import crypto_core as cc  # noqa: E402
import packaging_ as pk  # noqa: E402
from exceptions import AuthenticationError  # noqa: E402


def _arbol(base):
    os.makedirs(os.path.join(base, "a", "b", "c"))
    with open(os.path.join(base, "vacio.txt"), "wb"):
        pass
    with open(os.path.join(base, "a", "binario.bin"), "wb") as f:
        f.write(os.urandom(4096))
    with open(os.path.join(base, "a", "b", "c", "profundo.txt"), "w") as f:
        f.write("anidado")


def _leer_arbol(base):
    out = {}
    for dirpath, _dirs, files in os.walk(base):
        for name in files:
            full = os.path.join(dirpath, name)
            with open(full, "rb") as f:
                out[os.path.relpath(full, base)] = f.read()
    return out


def test_roundtrip_directorio_completo(tmp_path):
    origen = tmp_path / "origen"
    _arbol(str(origen))
    key, backup_id = cc.generate_key(), uuid.uuid4().bytes

    blob = cc.encrypt_blob(key, pk.pack_source(str(origen)), backup_id)
    payload = cc.decrypt_blob(key, blob, backup_id)
    pk.unpack_output(payload, str(tmp_path / "restaurado"))

    assert _leer_arbol(str(tmp_path / "restaurado" / "origen")) == _leer_arbol(str(origen))


def test_blob_no_contiene_plaintext(tmp_path):
    origen = tmp_path / "secreto.txt"
    marcador = b"MARCADOR-UNICO-" * 50
    origen.write_bytes(marcador)
    blob = cc.encrypt_blob(cc.generate_key(), pk.pack_source(str(origen)), uuid.uuid4().bytes)
    assert b"MARCADOR-UNICO-" not in blob
    assert b"secreto.txt" not in blob  # ni siquiera el nombre del archivo


def test_paquete_alterado_no_llega_a_extraerse(tmp_path):
    origen = tmp_path / "doc.txt"
    origen.write_text("contenido")
    key, backup_id = cc.generate_key(), uuid.uuid4().bytes
    blob = bytearray(cc.encrypt_blob(key, pk.pack_source(str(origen)), backup_id))
    blob[len(blob) // 2] ^= 0x01

    dest = tmp_path / "restaurado"
    with pytest.raises(AuthenticationError):
        pk.unpack_output(cc.decrypt_blob(key, bytes(blob), backup_id), str(dest))
    assert not dest.exists()
