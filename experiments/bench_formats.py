"""Experimento F16 del plan de pruebas (formatos y checksums).

Mide:
  - tamaño de cada participación y del manifiesto en disco;
  - tiempo de crear/escribir/leer/validar una participación y el manifiesto;
  - tiempo del SHA-256 del paquete (package_checksum / verify_package) y de
    escribir/leer el paquete en disco para 1 KB, 1 MB, 50 MB y 190 MB.

Uso:
    python experiments/bench_formats.py            # 1 KB, 1 MB, 50 MB, 190 MB
    python experiments/bench_formats.py --quick    # 1 KB y 1 MB, menos repeticiones
Genera experiments/results/formats_bench.csv y .md
"""
from __future__ import annotations

import argparse
import csv
import os
import platform
import statistics
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import formats as fm  # noqa: E402

KB, MB = 1024, 1024 * 1024


def median_ms(fn, reps: int) -> float:
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    return statistics.median(samples)


def label(n: int) -> str:
    return f"{n // MB} MB" if n >= MB else f"{n // KB} KB"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
    args = ap.parse_args()

    sizes = [1 * KB, 1 * MB] if args.quick else [1 * KB, 1 * MB, 50 * MB, 190 * MB]
    small_reps = 200 if args.quick else 2000
    rows: list[dict] = []

    with tempfile.TemporaryDirectory() as tmp:
        bid = fm.new_backup_id()
        value = os.urandom(fm.SHARE_VALUE_SIZE - 1).rjust(fm.SHARE_VALUE_SIZE, b"\x00")
        share = fm.make_share(bid, 1, value)
        manifest = fm.make_manifest(bid, os.urandom(1024))
        share_path, manifest_path = os.path.join(tmp, "s.json"), os.path.join(tmp, "m.json")
        fm.write_share(share, share_path)
        fm.write_manifest(manifest, manifest_path)

        share_bytes = os.path.getsize(share_path)
        manifest_bytes = os.path.getsize(manifest_path)
        small = [
            ("make_share (checksum)", lambda: fm.make_share(bid, 1, value), share_bytes),
            ("write_share (atómico, fsync)", lambda: fm.write_share(share, share_path), share_bytes),
            ("read_share", lambda: fm.read_share(share_path), share_bytes),
            ("validate_share", lambda: fm.validate_share(share, fm.read_manifest(manifest_path)), share_bytes),
            ("write_manifest (atómico, fsync)", lambda: fm.write_manifest(manifest, manifest_path), manifest_bytes),
            ("read_manifest", lambda: fm.read_manifest(manifest_path), manifest_bytes),
        ]
        for name, fn, size in small:
            reps = max(20, small_reps // 10) if "atómico" in name else small_reps
            rows.append({"operation": name, "input": "—", "bytes": size, "median_ms": round(median_ms(fn, reps), 4), "reps": reps})

        for n in sizes:
            blob = os.urandom(n)
            m = fm.make_manifest(bid, blob)
            pkg_path = os.path.join(tmp, "p.evlp")
            reps = 20 if n <= MB else 3
            rows.append({"operation": "package_checksum (SHA-256)", "input": label(n), "bytes": n,
                         "median_ms": round(median_ms(lambda: fm.package_checksum(blob), reps), 3), "reps": reps})
            rows.append({"operation": "verify_package", "input": label(n), "bytes": n,
                         "median_ms": round(median_ms(lambda: fm.verify_package(blob, m), reps), 3), "reps": reps})
            rows.append({"operation": "write_package", "input": label(n), "bytes": n,
                         "median_ms": round(median_ms(lambda: fm.write_package(blob, pkg_path), reps), 3), "reps": reps})
            rows.append({"operation": "read_package", "input": label(n), "bytes": n,
                         "median_ms": round(median_ms(lambda: fm.read_package(pkg_path), reps), 3), "reps": reps})
            del blob

    os.makedirs(args.out, exist_ok=True)
    csv_path = os.path.join(args.out, "formats_bench.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["operation", "input", "bytes", "median_ms", "reps"])
        w.writeheader()
        w.writerows(rows)

    md = [
        "# Benchmark de formatos y checksums (formats.py)",
        "",
        f"Python {platform.python_version()} · {platform.system()} {platform.machine()}",
        "",
        f"Tamaño en disco: participación **{share_bytes} B** · manifiesto **{manifest_bytes} B** "
        f"(constantes: no dependen del tamaño del respaldo). Cinco participaciones: {5 * share_bytes} B.",
        "",
        "| Operación | Entrada | Bytes | Mediana (ms) | Repeticiones |",
        "|---|---|---:|---:|---:|",
    ]
    for r in rows:
        md.append(f"| {r['operation']} | {r['input']} | {r['bytes']} | {r['median_ms']} | {r['reps']} |")
    md += [
        "",
        "Lectura: leer y validar una participación o el manifiesto cuesta centésimas de milisegundo; "
        "escribirlos cuesta unos pocos milisegundos, dominados por el fsync de la escritura atómica. "
        "El único costo que crece con el respaldo es el SHA-256 del paquete: lineal en su tamaño y "
        "mucho menor que el de comprimirlo o cifrarlo (ver experimento 18).",
        "",
    ]
    with open(os.path.join(args.out, "formats_bench.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print("\n".join(md))


if __name__ == "__main__":
    main()
