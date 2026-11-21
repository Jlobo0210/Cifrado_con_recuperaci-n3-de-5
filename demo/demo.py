"""
demo.py — Guion de demostración del respaldo 3-de-5 con custodios simulados.

Uso (desde la raíz del repositorio):
    python demo/demo.py

Qué hace:
    1. Crea una carpeta de ejemplo y la respalda con la CLI.
    2. Reparte las 5 participaciones entre 5 "custodios" (una carpeta cada uno).
    3. Simula varias restauraciones reuniendo participaciones en una "mesa":
         - las 10 combinaciones posibles de 3 custodios,
         - solo 2 custodios,
         - un custodio que entrega su participación dos veces,
         - un custodio con su participación dañada,
         - un custodio que entrega una participación de otro respaldo,
         - un paquete cifrado manipulado.
    4. Inspecciona una participación sin revelar su valor.

Se usa la CLI real (cli.main), así que la salida es la misma que vería un
usuario en la terminal. Todo se escribe en demo/salida_demo/ (se borra al
empezar cada ejecución).
"""

import contextlib
import filecmp
import io
import itertools
import json
import os
import shutil
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, "..", "src"))

import cli  # noqa: E402
import formats as fm  # noqa: E402

TRABAJO = os.path.join(AQUI, "salida_demo")
ORIGEN = os.path.join(TRABAJO, "documentos")
ALMACEN = os.path.join(TRABAJO, "almacen")  # paquete + manifiesto
CUSTODIOS = os.path.join(TRABAJO, "custodios")


def titulo(texto):
    print()
    print("=" * 70)
    print(texto)
    print("=" * 70)


def ejecutar(*args):
    """Muestra y ejecuta un comando de la CLI. Devuelve su código de salida.

    Las rutas se pasan relativas a salida_demo/ para que la salida sea corta,
    y los errores se muestran en orden junto con el resto del texto.
    """
    args = [os.path.relpath(a, TRABAJO) if os.path.isabs(a) else a for a in args]
    print("$ python src/cli.py " + " ".join(args))
    with contextlib.redirect_stderr(sys.stdout):
        codigo = cli.main(args)
    print(f"(código de salida: {codigo})")
    return codigo


def crear_documentos():
    os.makedirs(os.path.join(ORIGEN, "fotos"))
    with open(os.path.join(ORIGEN, "notas.txt"), "w", encoding="utf-8") as f:
        f.write("Contraseña del wifi: no la pongan aquí.\n")
    with open(os.path.join(ORIGEN, "fotos", "foto.bin"), "wb") as f:
        f.write(os.urandom(20_000))
    open(os.path.join(ORIGEN, "vacio.txt"), "wb").close()


def ruta_custodio(i):
    return os.path.join(CUSTODIOS, f"custodio_{i}")


def share_de(bid, i):
    return os.path.join(ruta_custodio(i), fm.share_filename(bid, i))


def preparar_mesa(nombre, bid, archivos):
    """Carpeta donde se reúnen paquete, manifiesto y las participaciones entregadas.

    Devuelve las rutas de las participaciones copiadas (en el mismo orden).
    """
    mesa = os.path.join(TRABAJO, "mesas", nombre)
    os.makedirs(mesa)
    for nombre_archivo in (fm.package_filename(bid), fm.manifest_filename(bid)):
        shutil.copy(os.path.join(ALMACEN, nombre_archivo), mesa)
    copias = []
    for n, archivo in enumerate(archivos):
        destino = os.path.join(mesa, f"entrega{n + 1}_{os.path.basename(archivo)}")
        shutil.copy(archivo, destino)
        copias.append(destino)
    return mesa, copias


def iguales(dir_a, dir_b):
    comparacion = filecmp.dircmp(dir_a, dir_b)
    if comparacion.left_only or comparacion.right_only or comparacion.diff_files:
        return False
    _ok, distintos, errores = filecmp.cmpfiles(dir_a, dir_b, comparacion.common_files, shallow=False)
    if distintos or errores:
        return False
    return all(iguales(os.path.join(dir_a, d), os.path.join(dir_b, d)) for d in comparacion.common_dirs)


def main():
    shutil.rmtree(TRABAJO, ignore_errors=True)
    os.makedirs(TRABAJO)
    os.chdir(TRABAJO)  # la CLI recibe rutas relativas a esta carpeta
    crear_documentos()

    titulo("1. Crear el respaldo")
    ejecutar("crear", ORIGEN, "-o", ALMACEN)
    bid = [n for n in os.listdir(ALMACEN) if n.endswith(".manifest.json")][0][:32]

    titulo("2. Repartir las participaciones entre 5 custodios")
    for i in range(1, 6):
        os.makedirs(ruta_custodio(i))
        shutil.move(os.path.join(ALMACEN, fm.share_filename(bid, i)), share_de(bid, i))
        print(f"custodio_{i} recibe {fm.share_filename(bid, i)}")
    print("En el almacén solo quedan el paquete cifrado y el manifiesto:", sorted(os.listdir(ALMACEN)))

    titulo("3. Restaurar con las 10 combinaciones de 3 custodios")
    for combo in itertools.combinations(range(1, 6), 3):
        nombre = "combo_" + "".join(map(str, combo))
        _mesa, copias = preparar_mesa(nombre, bid, [share_de(bid, i) for i in combo])
        destino = os.path.join(TRABAJO, "restaurado", nombre)
        codigo = ejecutar("restaurar", *copias, "-o", destino)
        ok = codigo == 0 and iguales(ORIGEN, os.path.join(destino, "documentos"))
        print(f"-> custodios {combo}: {'contenido idéntico al original' if ok else 'FALLÓ'}\n")

    titulo("4. Solo 2 custodios (debe fallar)")
    _mesa, copias = preparar_mesa("solo_dos", bid, [share_de(bid, 1), share_de(bid, 2)])
    ejecutar("restaurar", *copias, "-o", os.path.join(TRABAJO, "restaurado", "solo_dos"))

    titulo("5. El custodio 1 entrega su participación dos veces")
    _mesa, copias = preparar_mesa("repetida", bid, [share_de(bid, 1), share_de(bid, 1), share_de(bid, 2)])
    ejecutar("restaurar", *copias, "-o", os.path.join(TRABAJO, "restaurado", "repetida"))

    titulo("6. La participación del custodio 3 llega dañada (igual alcanzan 1, 4 y 5)")
    entregas = [share_de(bid, i) for i in (1, 3, 4, 5)]
    _mesa, copias = preparar_mesa("danada", bid, entregas)
    with open(copias[1], "r", encoding="utf-8") as f:
        datos = json.load(f)
    datos["value"] = "0" * 132  # se corrompe el valor sin recalcular el checksum
    with open(copias[1], "w", encoding="utf-8") as f:
        json.dump(datos, f)
    ejecutar("restaurar", *copias, "-o", os.path.join(TRABAJO, "restaurado", "danada"))

    titulo("7. El custodio 2 entrega por error una participación de otro respaldo")
    otro = os.path.join(TRABAJO, "otro_respaldo")
    with contextlib.redirect_stdout(io.StringIO()):  # no se muestra este paso auxiliar
        cli.main(["crear", ORIGEN, "-o", otro])
    ajena = [os.path.join(otro, n) for n in sorted(os.listdir(otro)) if ".share2." in n][0]
    _mesa, copias = preparar_mesa("ajena", bid, [share_de(bid, 1), ajena, share_de(bid, 3), share_de(bid, 4)])
    ejecutar("restaurar", *copias, "-o", os.path.join(TRABAJO, "restaurado", "ajena"))

    titulo("8. Alguien modifica un byte del paquete cifrado (debe fallar)")
    mesa, copias = preparar_mesa("paquete_manipulado", bid, [share_de(bid, i) for i in (1, 2, 3)])
    paquete = os.path.join(mesa, fm.package_filename(bid))
    with open(paquete, "r+b") as f:
        f.seek(100)
        byte = f.read(1)
        f.seek(100)
        f.write(bytes([byte[0] ^ 0x01]))
    ejecutar("restaurar", *copias, "-o", os.path.join(TRABAJO, "restaurado", "paquete_manipulado"))

    titulo("9. Inspeccionar una participación (el valor nunca se muestra)")
    ejecutar("inspeccionar", share_de(bid, 4))

    print()
    print(f"Fin de la demostración. Archivos generados en: {TRABAJO}")


if __name__ == "__main__":
    main()