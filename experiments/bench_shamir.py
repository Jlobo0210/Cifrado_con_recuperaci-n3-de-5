"""Experimento U10 del plan de pruebas.
    Mide el tiempo de ejecución de las funciones split_secret y reconstruct_secret
"""
from __future__ import annotations

import argparse
import csv
import os
import platform
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import shamir as sh  # noqa: E402

THRESHOLD = 3
TOTAL = 5


def samples_ms(fn, reps: int) -> list[float]:
    out = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t0) * 1000)
    return out


def summarize(samples: list[float]) -> tuple[float, float, float]:
    ordered = sorted(samples)
    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
    return statistics.median(samples), statistics.fmean(samples), p95


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=2000)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
    args = ap.parse_args()

    secret = os.urandom(sh.SECRET_SIZE)
    shares = sh.split_secret(secret, THRESHOLD, TOTAL)
    assert sh.reconstruct_secret(shares[:THRESHOLD], THRESHOLD) == secret

    rows = []
    for op, fn in (
        ("split_secret (3-de-5)", lambda: sh.split_secret(secret, THRESHOLD, TOTAL)),
        ("reconstruct_secret (3 shares)", lambda: sh.reconstruct_secret(shares[:THRESHOLD], THRESHOLD)),
        ("reconstruct_secret (5 shares, con verificación)", lambda: sh.reconstruct_secret(shares, THRESHOLD)),
    ):
        med, mean, p95 = summarize(samples_ms(fn, args.reps))
        rows.append({"operation": op, "median_ms": round(med, 4), "mean_ms": round(mean, 4), "p95_ms": round(p95, 4), "reps": args.reps})

    sizes = {
        "secret_bytes": sh.SECRET_SIZE,
        "share_value_bytes": len(shares[0][1]),
        "share_index_bytes": 1,
        "total_values_bytes": len(shares[0][1]) * TOTAL,
    }

    os.makedirs(args.out, exist_ok=True)
    csv_path = os.path.join(args.out, "shamir_bench.csv")
    md_path = os.path.join(args.out, "shamir_bench.md")
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]) + list(sizes))
        w.writeheader()
        for r in rows:
            w.writerow({**r, **sizes})

    lines = [
        f"# Benchmark Shamir {THRESHOLD}-de-{TOTAL} (Z_p, p = 2^521 − 1)",
        "",
        f"Python {platform.python_version()} · {platform.system()} {platform.machine()}",
        "",
        f"Secreto K: {sizes['secret_bytes']} B · valor de cada participación: {sizes['share_value_bytes']} B "
        f"(+ {sizes['share_index_bytes']} B de índice) · valores de las {TOTAL} participaciones: {sizes['total_values_bytes']} B.",
        "",
        "| Operación | Mediana (ms) | Media (ms) | P95 (ms) | Repeticiones |",
        "|---|---:|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(f"| {r['operation']} | {r['median_ms']} | {r['mean_ms']} | {r['p95_ms']} | {r['reps']} |")
    text = "\n".join(lines) + "\n"
    with open(md_path, "w") as f:
        f.write(text)
    print(text)


if __name__ == "__main__":
    main()
