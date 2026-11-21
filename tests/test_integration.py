"""Pruebas de integración del sistema completo (Persona D).

Cubren los casos 19 a 29 del plan de pruebas del Entregable 1 usando la
interfaz pública del orquestador (create_backup / restore_backup / inspect)
y la CLI. El caso 30 (mediciones) está en experiments/bench_integration.py.

Las pruebas lentas (~199 MB y > 200 MB) se omiten por defecto:
    EVLP_SLOW_TESTS=1 python -m pytest tests/test_integration.py
"""
import itertools
import json
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cli  # noqa: E402
import formats as fm  # noqa: E402
import orchestrator as orq  # noqa: E402
import packaging_ as pk  # noqa: E402
from exceptions import ExtractionError, PayloadTooLargeError  # noqa: E402

MB = 1024 * 1024

SLOW = pytest.mark.skipif(
    os.environ.get("EVLP_SLOW_TESTS") != "1",
    reason="Prueba lenta (~200 MB). Ejecutar con EVLP_SLOW_TESTS=1.",
)


# --- Utilidades -----------------------------------------------------------------


def _crear_origen(base):
    """Directorio con subdirectorios anidados, archivo vacío y archivo binario."""
    origen = base / "origen"
    (origen / "a" / "b" / "c").mkdir(parents=True)
    (origen / "vacio.txt").write_bytes(b"")
    (origen / "a" / "binario.bin").write_bytes(os.urandom(4096))
    (origen / "a" / "b" / "c" / "profundo.txt").write_text("anidado", encoding="utf-8")
    return origen


def _leer_arbol(base):
    """{ruta relativa: contenido} de todos los archivos bajo `base`."""
    out = {}
    for dirpath, _dirs, files in os.walk(base):
        for name in files:
            full = os.path.join(dirpath, name)
            with open(full, "rb") as f:
                out[os.path.relpath(full, base)] = f.read()
    return out


def _crear_respaldo(tmp_path, origen, salida="respaldo"):
    """Crea un respaldo y devuelve (carpeta, backup_id, [rutas de las 5 participaciones])."""
    carpeta = tmp_path / salida
    bid = orq.create_backup(str(origen), str(carpeta))
    shares = [str(carpeta / fm.share_filename(bid, i)) for i in range(1, 6)]
    return carpeta, bid, shares


def _editar_json(path, cambio):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    cambio(data)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _voltear_bit(path, posicion):
    with open(path, "rb") as f:
        data = bytearray(f.read())
    data[posicion] ^= 0x01
    with open(path, "wb") as f:
        f.write(bytes(data))


@pytest.fixture(name="respaldo")
def fixture_respaldo(tmp_path):
    origen = _crear_origen(tmp_path)
    carpeta, bid, shares = _crear_respaldo(tmp_path, origen)
    return origen, carpeta, bid, shares


# --- Creación -----------------------------------------------------------------------


def test_crear_genera_los_siete_archivos(respaldo):
    _origen, carpeta, bid, _shares = respaldo
    esperados = {fm.package_filename(bid), fm.manifest_filename(bid)}
    esperados |= {fm.share_filename(bid, i) for i in range(1, 6)}
    assert set(os.listdir(carpeta)) == esperados


def test_crear_devuelve_backup_id_del_manifiesto(respaldo):
    _origen, carpeta, bid, _shares = respaldo
    manifest = fm.read_manifest(str(carpeta / fm.manifest_filename(bid)))
    assert manifest.backup_id == bid
    assert (manifest.threshold, manifest.total_shares) == (3, 5)


def test_dos_respaldos_del_mismo_origen_son_independientes(tmp_path):
    origen = _crear_origen(tmp_path)
    _c1, bid1, _s1 = _crear_respaldo(tmp_path, origen, "r1")
    _c2, bid2, _s2 = _crear_respaldo(tmp_path, origen, "r2")
    assert bid1 != bid2


# --- Caso 19: las diez combinaciones de 3 participaciones -----------------------------


def test_caso19_las_diez_combinaciones_restauran(tmp_path, respaldo):
    origen, _carpeta, _bid, shares = respaldo
    combinaciones = list(itertools.combinations(shares, 3))
    assert len(combinaciones) == 10
    for n, combo in enumerate(combinaciones):
        destino = tmp_path / f"restaurado{n}"
        rechazadas = orq.restore_backup(list(combo), str(destino))
        assert rechazadas == []
        assert _leer_arbol(destino / "origen") == _leer_arbol(origen)


def test_restaurar_con_las_cinco_y_con_cuatro(tmp_path, respaldo):
    origen, _carpeta, _bid, shares = respaldo
    orq.restore_backup(shares, str(tmp_path / "con5"))
    orq.restore_backup(shares[1:], str(tmp_path / "con4"))
    assert _leer_arbol(tmp_path / "con5" / "origen") == _leer_arbol(origen)
    assert _leer_arbol(tmp_path / "con4" / "origen") == _leer_arbol(origen)


# --- Caso 20: dos participaciones no alcanzan --------------------------------------------


def test_caso20_dos_participaciones_no_alcanzan(tmp_path, respaldo):
    _origen, _carpeta, _bid, shares = respaldo
    for combo in itertools.combinations(shares, 2):
        destino = tmp_path / "nunca"
        with pytest.raises(orq.NotEnoughSharesError) as info:
            orq.restore_backup(list(combo), str(destino))
        assert info.value.valid_count == 2
        assert not destino.exists()


def test_restaurar_sin_participaciones(tmp_path):
    with pytest.raises(orq.NotEnoughSharesError):
        orq.restore_backup([], str(tmp_path / "nunca"))


# --- Caso 21: participación repetida -------------------------------------------------------


def test_caso21_repetida_no_cuenta_dos_veces(tmp_path, respaldo):
    _origen, carpeta, _bid, shares = respaldo
    copia = str(carpeta / "copia_de_share1.json")
    shutil.copy(shares[0], copia)
    with pytest.raises(orq.NotEnoughSharesError) as info:
        orq.restore_backup([shares[0], copia, shares[1]], str(tmp_path / "nunca"))
    assert info.value.rejected == [(copia, fm.REASON_DUPLICATE)]


def test_caso21_repetida_se_descarta_si_alcanzan_las_demas(tmp_path, respaldo):
    origen, _carpeta, _bid, shares = respaldo
    destino = tmp_path / "rest"
    rechazadas = orq.restore_backup([shares[0], shares[0], shares[1], shares[2]], str(destino))
    assert rechazadas == [(shares[0], fm.REASON_DUPLICATE)]
    assert _leer_arbol(destino / "origen") == _leer_arbol(origen)


# --- Caso 22: participación alterada ------------------------------------------------------


def test_caso22_alterada_se_descarta_y_se_restaura_igual(tmp_path, respaldo):
    origen, _carpeta, _bid, shares = respaldo
    _editar_json(shares[0], lambda d: d.update(value="00" + "11" * 65))  # sin recalcular checksum
    destino = tmp_path / "rest"
    rechazadas = orq.restore_backup(shares[:4], str(destino))
    assert rechazadas == [(shares[0], fm.REASON_DAMAGED)]
    assert _leer_arbol(destino / "origen") == _leer_arbol(origen)


def test_caso22_archivo_ilegible_se_descarta(tmp_path, respaldo):
    _origen, _carpeta, _bid, shares = respaldo
    with open(shares[4], "w", encoding="utf-8") as f:
        f.write("esto no es JSON")
    rechazadas = orq.restore_backup(shares, str(tmp_path / "rest"))
    assert rechazadas == [(shares[4], fm.REASON_DAMAGED)]


def test_caso22_alterada_con_checksum_recalculado_es_tolerada(tmp_path, respaldo):
    """El checksum no es un MAC: la detecta AEAD y se prueba otra terna."""
    origen, _carpeta, bid, shares = respaldo
    original = fm.read_share(shares[0])
    valor = bytearray(original.value)
    valor[-1] ^= 0x01
    fm.write_share(fm.make_share(bid, original.index, bytes(valor)), shares[0])

    destino = tmp_path / "rest"
    rechazadas = orq.restore_backup(shares[:4], str(destino))
    assert rechazadas == []  # la capa de formatos no la puede distinguir
    assert _leer_arbol(destino / "origen") == _leer_arbol(origen)


def test_caso22_alterada_con_checksum_recalculado_y_solo_tres(tmp_path, respaldo):
    _origen, _carpeta, bid, shares = respaldo
    original = fm.read_share(shares[0])
    valor = bytearray(original.value)
    valor[-1] ^= 0x01
    fm.write_share(fm.make_share(bid, original.index, bytes(valor)), shares[0])

    destino = tmp_path / "nunca"
    with pytest.raises(orq.VerificationError) as info:
        orq.restore_backup(shares[:3], str(destino))
    assert str(info.value) == orq.GENERIC_ERROR
    assert not destino.exists()


# --- Caso 23: participaciones de dos respaldos distintos ---------------------------------


def test_caso23_mezcla_de_respaldos(tmp_path):
    origen = _crear_origen(tmp_path)
    carpeta, _bid_a, shares_a = _crear_respaldo(tmp_path, origen)
    _c, bid_b, _ = _crear_respaldo(tmp_path, origen, "otro")
    # Las participaciones del respaldo B se mezclan en la carpeta del A.
    ajenas = []
    for i in (4, 5):
        destino = str(carpeta / fm.share_filename(bid_b, i))
        shutil.copy(str(tmp_path / "otro" / fm.share_filename(bid_b, i)), destino)
        ajenas.append(destino)

    restaurado = tmp_path / "rest"
    rechazadas = orq.restore_backup(shares_a[:3] + ajenas, str(restaurado))
    assert sorted(rechazadas) == sorted((p, fm.REASON_OTHER_BACKUP) for p in ajenas)
    assert _leer_arbol(restaurado / "origen") == _leer_arbol(origen)


def test_caso23_ajenas_no_completan_el_umbral(tmp_path):
    origen = _crear_origen(tmp_path)
    _ca, _bid_a, shares_a = _crear_respaldo(tmp_path, origen, "a")
    _cb, _bid_b, shares_b = _crear_respaldo(tmp_path, origen, "b")
    with pytest.raises(orq.NotEnoughSharesError) as info:
        orq.restore_backup(shares_a[:2] + shares_b[:1], str(tmp_path / "nunca"))
    assert [r for _p, r in info.value.rejected] == [fm.REASON_OTHER_BACKUP]


# --- Caso 24: paquete cifrado modificado --------------------------------------------------


def test_caso24_paquete_modificado_se_rechaza(tmp_path, respaldo):
    _origen, carpeta, bid, shares = respaldo
    paquete = str(carpeta / fm.package_filename(bid))
    _voltear_bit(paquete, os.path.getsize(paquete) // 2)
    destino = tmp_path / "nunca"
    with pytest.raises(orq.VerificationError) as info:
        orq.restore_backup(shares[:3], str(destino))
    assert str(info.value) == orq.GENERIC_ERROR
    assert not destino.exists()


def test_caso24_paquete_y_manifiesto_modificados_los_detecta_aead(tmp_path, respaldo):
    """Un adversario que actualiza también el checksum del manifiesto no pasa AEAD."""
    _origen, carpeta, bid, shares = respaldo
    paquete = str(carpeta / fm.package_filename(bid))
    _voltear_bit(paquete, os.path.getsize(paquete) - 1)  # último byte del tag
    nuevo_checksum = fm.package_checksum(fm.read_package(paquete))
    _editar_json(str(carpeta / fm.manifest_filename(bid)),
                 lambda d: d.update(package_checksum=nuevo_checksum))
    with pytest.raises(orq.VerificationError) as info:
        orq.restore_backup(shares[:3], str(tmp_path / "nunca"))
    assert str(info.value) == orq.GENERIC_ERROR


def test_caso24_encabezado_modificado_se_rechaza(tmp_path, respaldo):
    _origen, carpeta, bid, shares = respaldo
    paquete = str(carpeta / fm.package_filename(bid))
    _voltear_bit(paquete, 5)  # byte ALG_ID
    nuevo_checksum = fm.package_checksum(fm.read_package(paquete))
    _editar_json(str(carpeta / fm.manifest_filename(bid)),
                 lambda d: d.update(package_checksum=nuevo_checksum))
    with pytest.raises(orq.VerificationError):
        orq.restore_backup(shares[:3], str(tmp_path / "nunca"))


def test_caso24_paquete_truncado_se_rechaza(tmp_path, respaldo):
    _origen, carpeta, bid, shares = respaldo
    paquete = str(carpeta / fm.package_filename(bid))
    with open(paquete, "rb") as f:
        data = f.read()
    with open(paquete, "wb") as f:
        f.write(data[:-10])
    with pytest.raises(orq.VerificationError):
        orq.restore_backup(shares[:3], str(tmp_path / "nunca"))


# --- Caso 25: manifiesto modificado ------------------------------------------------------


def test_caso25_checksum_del_manifiesto_modificado(tmp_path, respaldo):
    _origen, carpeta, bid, shares = respaldo
    _editar_json(str(carpeta / fm.manifest_filename(bid)),
                 lambda d: d.update(package_checksum="sha256:" + "0" * 64))
    with pytest.raises(orq.VerificationError):
        orq.restore_backup(shares[:3], str(tmp_path / "nunca"))


def test_caso25_tamano_del_manifiesto_modificado(tmp_path, respaldo):
    _origen, carpeta, bid, shares = respaldo
    _editar_json(str(carpeta / fm.manifest_filename(bid)),
                 lambda d: d.update(package_size=d["package_size"] + 1))
    with pytest.raises(orq.VerificationError):
        orq.restore_backup(shares[:3], str(tmp_path / "nunca"))


@pytest.mark.parametrize("campo, valor", [
    ("threshold", 2),
    ("total_shares", 6),
    ("algorithm", "AES-256-GCM"),
    ("version", 2),
])
def test_caso25_parametros_del_manifiesto_modificados(tmp_path, respaldo, campo, valor):
    _origen, carpeta, bid, shares = respaldo
    _editar_json(str(carpeta / fm.manifest_filename(bid)), lambda d: d.update({campo: valor}))
    with pytest.raises(fm.FormatError):
        orq.restore_backup(shares[:3], str(tmp_path / "nunca"))
    assert not (tmp_path / "nunca").exists()


def test_caso25_backup_id_del_manifiesto_modificado(tmp_path, respaldo):
    _origen, carpeta, bid, shares = respaldo
    _editar_json(str(carpeta / fm.manifest_filename(bid)),
                 lambda d: d.update(backup_id=fm.new_backup_id()))
    # Las participaciones ya no "pertenecen" al manifiesto: no queda ninguna válida.
    with pytest.raises(orq.NotEnoughSharesError):
        orq.restore_backup(shares[:3], str(tmp_path / "nunca"))


def test_caso25_created_at_no_esta_protegido(tmp_path, respaldo):
    """Limitación documentada (Sección 5.2): created_at es solo informativo."""
    origen, carpeta, bid, shares = respaldo
    _editar_json(str(carpeta / fm.manifest_filename(bid)),
                 lambda d: d.update(created_at="2000-01-01T00:00:00Z"))
    orq.restore_backup(shares[:3], str(tmp_path / "rest"))
    assert _leer_arbol(tmp_path / "rest" / "origen") == _leer_arbol(origen)


def test_manifiesto_ausente(tmp_path, respaldo):
    _origen, carpeta, bid, shares = respaldo
    os.remove(str(carpeta / fm.manifest_filename(bid)))
    with pytest.raises(fm.FormatError, match="manifest"):
        orq.restore_backup(shares[:3], str(tmp_path / "nunca"))


def test_mensaje_generico_identico_en_todos_los_fallos_de_verificacion(tmp_path):
    """Sección 6.3: el mensaje no revela qué parte falló."""
    mensajes = set()
    for caso in ("paquete", "participacion"):
        base = tmp_path / caso
        base.mkdir()
        origen = _crear_origen(base)
        carpeta, bid, shares = _crear_respaldo(base, origen)
        if caso == "paquete":
            paquete = str(carpeta / fm.package_filename(bid))
            _voltear_bit(paquete, 40)
        else:
            original = fm.read_share(shares[0])
            valor = bytearray(original.value)
            valor[-1] ^= 0x01
            fm.write_share(fm.make_share(bid, 1, bytes(valor)), shares[0])
        with pytest.raises(orq.VerificationError) as info:
            orq.restore_backup(shares[:3], str(base / "nunca"))
        mensajes.add(str(info.value))
    assert mensajes == {orq.GENERIC_ERROR}


# --- Casos 26 y 27: archivo vacío y archivo binario ------------------------------------------


def test_caso26_archivo_vacio(tmp_path):
    origen = tmp_path / "vacio.txt"
    origen.write_bytes(b"")
    _carpeta, _bid, shares = _crear_respaldo(tmp_path, origen)
    orq.restore_backup(shares[2:], str(tmp_path / "rest"))
    assert (tmp_path / "rest" / "vacio.txt").read_bytes() == b""


def test_caso26_directorio_vacio(tmp_path):
    origen = tmp_path / "carpeta_vacia"
    origen.mkdir()
    _carpeta, _bid, shares = _crear_respaldo(tmp_path, origen)
    orq.restore_backup(shares[:3], str(tmp_path / "rest"))
    assert (tmp_path / "rest" / "carpeta_vacia").is_dir()
    assert os.listdir(tmp_path / "rest" / "carpeta_vacia") == []


def test_caso27_archivo_binario(tmp_path):
    contenido = bytes(range(256)) * 64 + os.urandom(10_000)
    origen = tmp_path / "datos.bin"
    origen.write_bytes(contenido)
    _carpeta, _bid, shares = _crear_respaldo(tmp_path, origen)
    orq.restore_backup([shares[0], shares[2], shares[4]], str(tmp_path / "rest"))
    assert (tmp_path / "rest" / "datos.bin").read_bytes() == contenido


def test_restaurar_en_destino_ocupado_no_sobrescribe(tmp_path, respaldo):
    _origen, _carpeta, _bid, shares = respaldo
    destino = tmp_path / "ocupado"
    (destino / "origen").mkdir(parents=True)
    (destino / "origen" / "mio.txt").write_text("no tocar", encoding="utf-8")
    with pytest.raises(ExtractionError):
        orq.restore_backup(shares[:3], str(destino))
    assert (destino / "origen" / "mio.txt").read_text(encoding="utf-8") == "no tocar"


# --- Casos 28 y 29: límite de 200 MB ---------------------------------------------------------


@SLOW
def test_caso28_respaldo_cercano_a_200mb(tmp_path):
    origen = tmp_path / "grande.bin"
    contenido = os.urandom(199 * MB)
    origen.write_bytes(contenido)
    _carpeta, _bid, shares = _crear_respaldo(tmp_path, origen)
    orq.restore_backup(shares[:3], str(tmp_path / "rest"))
    assert (tmp_path / "rest" / "grande.bin").read_bytes() == contenido


def test_caso29_limite_se_respeta_desde_la_orquestacion(tmp_path, monkeypatch):
    """Versión rápida: se baja el límite a 1 KB para no crear 200 MB."""
    monkeypatch.setattr(pk, "MAX_PACKAGE_SIZE", 1024)
    origen = tmp_path / "datos.bin"
    origen.write_bytes(os.urandom(5000))
    salida = tmp_path / "respaldo"
    with pytest.raises(PayloadTooLargeError):
        orq.create_backup(str(origen), str(salida))
    assert not salida.exists()  # no se escribió nada


@SLOW
def test_caso29_respaldo_que_supera_200mb(tmp_path):
    origen = tmp_path / "enorme.bin"
    origen.write_bytes(os.urandom(201 * MB))
    salida = tmp_path / "respaldo"
    with pytest.raises(PayloadTooLargeError):
        orq.create_backup(str(origen), str(salida))
    assert not salida.exists()


def test_origen_inexistente(tmp_path):
    with pytest.raises(FileNotFoundError):
        orq.create_backup(str(tmp_path / "no_existe"), str(tmp_path / "respaldo"))


# --- Inspector -----------------------------------------------------------------------------


def test_inspector_participacion_no_revela_el_valor(respaldo):
    _origen, _carpeta, _bid, shares = respaldo
    valor_hex = fm.read_share(shares[0]).value.hex()
    info = orq.inspect(shares[0])
    assert info["type"] == "share"
    assert info["index"] == 1
    assert info["checksum_ok"] is True
    assert "value" not in info
    assert valor_hex not in str(info)


def test_inspector_manifiesto_y_paquete(respaldo):
    _origen, carpeta, bid, _shares = respaldo
    manifiesto = orq.inspect(str(carpeta / fm.manifest_filename(bid)))
    assert manifiesto["type"] == "manifest" and manifiesto["backup_id"] == bid
    paquete = orq.inspect(str(carpeta / fm.package_filename(bid)))
    assert paquete["type"] == "package"
    assert paquete["algorithm"] == "ChaCha20-Poly1305"
    assert paquete["blob_size"] == manifiesto["package_size"]


def test_inspector_detecta_participacion_danada(respaldo):
    _origen, _carpeta, _bid, shares = respaldo
    _editar_json(shares[1], lambda d: d.update(value="00" + "11" * 65))
    assert orq.inspect(shares[1])["checksum_ok"] is False


def test_inspector_archivo_no_reconocido(tmp_path):
    otro = tmp_path / "nota.json"
    otro.write_text('{"hola": 1}', encoding="utf-8")
    with pytest.raises(fm.FormatError):
        orq.inspect(str(otro))


# --- CLI -----------------------------------------------------------------------------------


def test_cli_flujo_completo(tmp_path, capsys):
    origen = _crear_origen(tmp_path)
    salida = tmp_path / "respaldo"
    assert cli.main(["crear", str(origen), "-o", str(salida)]) == 0
    bid = capsys.readouterr().out.split("Respaldo creado: ")[1].split()[0]

    shares = [str(salida / fm.share_filename(bid, i)) for i in (2, 3, 5)]
    destino = tmp_path / "rest"
    assert cli.main(["restaurar", *shares, "-o", str(destino)]) == 0
    assert "Respaldo restaurado" in capsys.readouterr().out
    assert _leer_arbol(destino / "origen") == _leer_arbol(origen)


def test_cli_dos_participaciones_falla_sin_traceback(tmp_path, capsys, respaldo):
    _origen, _carpeta, _bid, shares = respaldo
    assert cli.main(["restaurar", shares[0], shares[0], shares[1], "-o", str(tmp_path / "x")]) == 1
    err = capsys.readouterr().err
    assert "No hay participaciones suficientes" in err
    assert "duplicada" in err
    assert "Traceback" not in err


def test_cli_inspeccionar_no_muestra_el_valor(capsys, respaldo):
    _origen, _carpeta, _bid, shares = respaldo
    valor_hex = fm.read_share(shares[0]).value.hex()
    assert cli.main(["inspeccionar", shares[0]]) == 0
    out = capsys.readouterr().out
    assert "index: 1" in out
    assert valor_hex not in out


def test_cli_origen_inexistente(tmp_path, capsys):
    assert cli.main(["crear", str(tmp_path / "no_existe"), "-o", str(tmp_path / "r")]) == 1
    assert "Error:" in capsys.readouterr().err


# --- Inspector: revisión de un grupo de participaciones ---------------------------


def test_inspector_grupo_sano_alcanza_el_umbral(respaldo):
    _origen, _carpeta, bid, shares = respaldo
    grupo = orq.check_share_group(shares[:3])
    assert grupo["advertencias"] == []
    assert grupo["resumen"] == [
        f"Respaldo {bid}: índices [1, 2, 3]; alcanza el umbral de 3."
    ]


def test_inspector_grupo_detecta_indice_repetido(respaldo):
    _origen, carpeta, _bid, shares = respaldo
    copia = str(carpeta / "copia_share2.json")
    shutil.copy(shares[1], copia)
    grupo = orq.check_share_group([shares[0], shares[1], copia])
    assert len(grupo["advertencias"]) == 1
    assert "Índice 2 repetido en 2 archivos" in grupo["advertencias"][0]
    assert "NO alcanza" in grupo["resumen"][0]  # solo hay 2 índices distintos


def test_inspector_grupo_advierte_mezcla_de_respaldos(tmp_path):
    origen = _crear_origen(tmp_path)
    _ca, bid_a, shares_a = _crear_respaldo(tmp_path, origen, "a")
    _cb, bid_b, shares_b = _crear_respaldo(tmp_path, origen, "b")
    grupo = orq.check_share_group(shares_a[:3] + shares_b[:1])
    assert any("2 respaldos distintos" in a for a in grupo["advertencias"])
    assert len(grupo["resumen"]) == 2
    assert any(bid_a in linea and "alcanza el umbral" in linea for linea in grupo["resumen"])
    assert any(bid_b in linea and "NO alcanza" in linea for linea in grupo["resumen"])


def test_inspector_grupo_advierte_danada_e_ignora_otros_archivos(respaldo):
    _origen, carpeta, bid, shares = respaldo
    _editar_json(shares[0], lambda d: d.update(value="00" + "11" * 65))
    grupo = orq.check_share_group([
        shares[0], shares[1], shares[2],
        str(carpeta / fm.manifest_filename(bid)),
        str(carpeta / fm.package_filename(bid)),
    ])
    assert grupo["advertencias"] == [
        f"Participación dañada (el checksum no coincide): {shares[0]}"
    ]
    assert "NO alcanza" in grupo["resumen"][0]


def test_inspector_grupo_no_revela_valores(respaldo):
    _origen, _carpeta, _bid, shares = respaldo
    grupo = orq.check_share_group(shares)
    texto = str(grupo)
    for path in shares:
        assert fm.read_share(path).value.hex() not in texto


def test_cli_inspeccionar_grupo_muestra_advertencias(capsys, respaldo):
    _origen, carpeta, _bid, shares = respaldo
    copia = str(carpeta / "copia_share1.json")
    shutil.copy(shares[0], copia)
    assert cli.main(["inspeccionar", shares[0], copia, shares[1]]) == 0
    out = capsys.readouterr().out
    assert "== Revisión del grupo de participaciones" in out
    assert "ADVERTENCIA: Índice 1 repetido" in out


def test_cli_inspeccionar_sigue_si_un_archivo_es_invalido(tmp_path, capsys, respaldo):
    _origen, _carpeta, _bid, shares = respaldo
    malo = tmp_path / "malo.json"
    malo.write_text("no es JSON", encoding="utf-8")
    assert cli.main(["inspeccionar", str(malo), shares[0]]) == 1
    out = capsys.readouterr().out
    assert "Error:" in out
    assert "index: 1" in out  # el segundo archivo sí se inspeccionó