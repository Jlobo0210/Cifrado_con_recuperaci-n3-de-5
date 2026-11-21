"""Experimento 18 del plan de pruebas (persona A — cifrado de envolvente).

Mide, para payloads de distintos tamaños:
    - tiempo de encrypt_blob y decrypt_blob (mediana de N repeticiones),
    - throughput en MB/s,
    - tamaño del blob y overhead del formato (debe ser 34 B constantes),
    - tiempo y tamaño de pack_source / unpack_output sobre un archivo de
      contenido aleatorio (incompresible) y uno de texto (compresible).

Uso (desde la raíz del repositorio):
    python experiments/bench_crypto_core.py                # 1 KB, 1 MB, 50 MB, 190 MB
    python experiments/bench_crypto_core.py --quick        # 1 KB, 1 MB, 10 MB
    python experiments/bench_crypto_core.py --reps 10 --out experiments/results

Escribe <out>/crypto_core_bench.csv y <out>/crypto_core_bench.md e imprime
la tabla. Solo usa datos sintéticos (os.urandom / texto repetido); no
registra claves ni plaintext.
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
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import cryptography  # noqa: E402

import crypto_core as cc  # noqa: E402
import packaging_ as pk  # noqa: E402

MB = 1024 * 1024
DEFAULT_SIZES = [1024, 1 * MB, 50 * MB, 190 * MB]
QUICK_SIZES = [1024, 1 * MB, 10 * MB]


def _fmt_size(n: int) -> str:
    return f"{n // MB} MB" if n >= MB else f"{n // 1024} KB"


def _median_time(fn, reps: int) -> float:
    times = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    return statistics.median(times)


def bench_aead(size: int, reps: int) -> dict:
    key, backup_id = cc.generate_key(), uuid.uuid4().bytes
    plaintext = os.urandom(size)
    blob = cc.encrypt_blob(key, plaintext, backup_id)
    assert cc.decrypt_blob(key, blob, backup_id) == plaintext

    t_enc = _median_time(lambda: cc.encrypt_blob(key, plaintext, backup_id), reps)
    t_dec = _median_time(lambda: cc.decrypt_blob(key, blob, backup_id), reps)
    cc.wipe(key)
    return {
        "experimento": "aead",
        "contenido": "aleatorio",
        "tamano_entrada_B": size,
        "tamano_salida_B": len(blob),
        "overhead_B": len(blob) - size,
        "overhead_pct": round(100 * (len(blob) - size) / size, 6),
        "t_ida_ms": round(t_enc * 1000, 3),
        "t_vuelta_ms": round(t_dec * 1000, 3),
        "mbps_ida": round(size / MB / t_enc, 1) if t_enc else "",
        "mbps_vuelta": round(size / MB / t_dec, 1) if t_dec else "",
    }


def bench_packaging(size: int, reps: int, kind: str, workdir: str) -> dict:
    src = os.path.join(workdir, f"entrada_{kind}.bin")
    with open(src, "wb") as f:
        if kind == "aleatorio":
            f.write(os.urandom(size))
        else:
            linea = b"Linea de texto de ejemplo para el respaldo cifrado 3-de-5.\n"
            f.write((linea * (size // len(linea) + 1))[:size])

    payload = pk.pack_source(src)
    t_pack = _median_time(lambda: pk.pack_source(src), reps)

    def _unpack():
        dest = tempfile.mkdtemp(dir=workdir)
        pk.unpack_output(payload, dest)
        shutil.rmtree(dest)

    t_unpack = _median_time(_unpack, reps)
    os.remove(src)
    return {
        "experimento": "tar+gzip",
        "contenido": kind,
        "tamano_entrada_B": size,
        "tamano_salida_B": len(payload),
        "overhead_B": len(payload) - size,
        "overhead_pct": round(100 * (len(payload) - size) / size, 3),
        "t_ida_ms": round(t_pack * 1000, 3),
        "t_vuelta_ms": round(t_unpack * 1000, 3),
        "mbps_ida": round(size / MB / t_pack, 1) if t_pack else "",
        "mbps_vuelta": round(size / MB / t_unpack, 1) if t_unpack else "",
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="tamaños pequeños (prueba rápida)")
    ap.add_argument("--reps", type=int, default=5, help="repeticiones por medición (mediana)")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
    ap.add_argument("--no-packaging", action="store_true", help="omitir mediciones de tar+gzip")
    args = ap.parse_args()

    sizes = QUICK_SIZES if args.quick else DEFAULT_SIZES
    rows = []
    with tempfile.TemporaryDirectory() as workdir:
        for size in sizes:
            reps = args.reps if size <= 50 * MB else max(1, min(args.reps, 3))
            print(f"[aead] {_fmt_size(size)} x{reps}...", flush=True)
            rows.append(bench_aead(size, reps))
            if not args.no_packaging:
                for kind in ("aleatorio", "texto"):
                    print(f"[tar+gzip] {kind} {_fmt_size(size)} x{reps}...", flush=True)
                    rows.append(bench_packaging(size, reps, kind, workdir))

    os.makedirs(args.out, exist_ok=True)
    csv_path = os.path.join(args.out, "crypto_core_bench.csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    entorno = (
        f"Python {platform.python_version()}, cryptography {cryptography.__version__}, "
        f"{platform.system()} {platform.machine()}, {os.cpu_count()} CPU, "
        f"repeticiones={args.reps} (máx. 3 para > 50 MB), mediana"
    )
    headers = ["Experimento", "Contenido", "Entrada", "Salida (B)", "Overhead (B)",
               "Overhead (%)", "Ida (ms)", "Vuelta (ms)", "MB/s ida", "MB/s vuelta"]
    lines = ["# Experimento 18 — cifrado de envolvente", "", f"Entorno: {entorno}", "",
             "Ida = encrypt_blob / pack_source; vuelta = decrypt_blob / unpack_output.", "",
             "| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for r in rows:
        lines.append("| " + " | ".join(str(x) for x in [
            r["experimento"], r["contenido"], _fmt_size(r["tamano_entrada_B"]), r["tamano_salida_B"],
            r["overhead_B"], r["overhead_pct"], r["t_ida_ms"], r["t_vuelta_ms"], r["mbps_ida"], r["mbps_vuelta"],
        ]) + " |")
    md = "\n".join(lines) + "\n"
    with open(os.path.join(args.out, "crypto_core_bench.md"), "w") as f:
        f.write(md)
    print()
    print(md)
    print(f"Resultados en {csv_path}")


if __name__ == "__main__":
    main()
