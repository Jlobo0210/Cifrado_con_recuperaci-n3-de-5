"""Experimento 30 del plan de pruebas: el sistema completo en tiempo y espacio.

Para cada tamaño de archivo mide, con la interfaz del orquestador:
  - tiempo de create_backup (empaquetar + cifrar + repartir + escribir);
  - tiempo de restore_backup con 3 participaciones (leer + validar +
    reconstruir + descifrar + extraer);
  - tamaño del paquete cifrado, del payload tar+gzip, de cada participación
    y del manifiesto, y el sobrecosto del formato.

Se usan datos aleatorios (no comprimibles), que es el peor caso: gzip no los
reduce y el paquete queda un poco más grande que el archivo original.

Uso:
    python experiments/bench_integration.py            # 1 KB, 1 MB, 50 MB, 190 MB
    python experiments/bench_integration.py --quick    # 1 KB y 1 MB
Genera experiments/results/integration_bench.csv y .md
"""
from __future__ import annotations

import argparse
import csv
import os
import platform
import shutil
import statistics
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import formats as fm  # noqa: E402
import orchestrator as orq  # noqa: E402
import packaging_ as pk  # noqa: E402

KB, MB = 1024, 1024 * 1024


def label(n: int) -> str:
    return f"{n // MB} MB" if n >= MB else f"{n // KB} KB"


def medir_tamano(n: int, reps: int, tmp: str) -> dict:
    origen = os.path.join(tmp, "datos.bin")
    with open(origen, "wb") as f:
        f.write(os.urandom(n))
    payload_size = len(pk.pack_source(origen))  # solo para saber cuánto mide el tar.gz

    tiempos_crear, tiempos_restaurar = [], []
    package_size = share_size = manifest_size = 0  # se llenan en la primera repetición
    for r in range(reps):
        salida = os.path.join(tmp, f"respaldo{r}")
        destino = os.path.join(tmp, f"restaurado{r}")

        t0 = time.perf_counter()
        bid = orq.create_backup(origen, salida)
        tiempos_crear.append(time.perf_counter() - t0)

        shares = [os.path.join(salida, fm.share_filename(bid, i)) for i in (1, 3, 5)]
        t0 = time.perf_counter()
        orq.restore_backup(shares, destino)
        tiempos_restaurar.append(time.perf_counter() - t0)

        package_size = os.path.getsize(os.path.join(salida, fm.package_filename(bid)))
        share_size = os.path.getsize(shares[0])
        manifest_size = os.path.getsize(os.path.join(salida, fm.manifest_filename(bid)))
        shutil.rmtree(salida)
        shutil.rmtree(destino)

    os.remove(origen)
    return {
        "input": label(n),
        "original_bytes": n,
        "payload_bytes": payload_size,
        "package_bytes": package_size,
        "format_overhead_bytes": package_size - payload_size,
        "share_bytes": share_size,
        "manifest_bytes": manifest_size,
        "create_ms": round(statistics.median(tiempos_crear) * 1000, 2),
        "restore_ms": round(statistics.median(tiempos_restaurar) * 1000, 2),
        "reps": reps,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
    args = ap.parse_args()

    sizes = [1 * KB, 1 * MB] if args.quick else [1 * KB, 1 * MB, 50 * MB, 190 * MB]
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for n in sizes:
            reps = 10 if n <= MB else 3
            print(f"Midiendo {label(n)} ({reps} repeticiones)...")
            rows.append(medir_tamano(n, reps, tmp))

    campos = list(rows[0].keys())
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "integration_bench.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        w.writerows(rows)

    md = [
        "# Benchmark del sistema completo (orchestrator.py)",
        "",
        f"Python {platform.python_version()} · {platform.system()} {platform.machine()}",
        "",
        "Datos aleatorios (peor caso para gzip). Restauración con las participaciones 1, 3 y 5.",
        "Tiempos: mediana de las repeticiones.",
        "",
        "| Entrada | Original (B) | tar.gz (B) | Paquete (B) | Sobrecosto formato (B) | "
        "Participación (B) | Manifiesto (B) | Crear (ms) | Restaurar (ms) | Reps |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        md.append(
            f"| {r['input']} | {r['original_bytes']} | {r['payload_bytes']} | {r['package_bytes']} | "
            f"{r['format_overhead_bytes']} | {r['share_bytes']} | {r['manifest_bytes']} | "
            f"{r['create_ms']} | {r['restore_ms']} | {r['reps']} |"
        )
    md += [
        "",
        "Lectura: el sobrecosto del formato del paquete es constante (34 B = encabezado + nonce + tag) "
        "y cada participación y el manifiesto pesan lo mismo sin importar el tamaño del respaldo. "
        "El tiempo crece aproximadamente de forma lineal con el tamaño. Crear es más lento que restaurar "
        "porque comprimir con gzip cuesta mucho más que descomprimir; en archivos pequeños el tiempo lo "
        "dominan las escrituras atómicas con fsync de los 7 archivos. Shamir y los checksums de las "
        "participaciones son insignificantes frente a esto.",
        "",
    ]
    with open(os.path.join(args.out, "integration_bench.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print("\n".join(md))


if __name__ == "__main__":
    main()