# Benchmark Shamir 3-de-5 (Z_p, p = 2^521 − 1)

Python 3.12.3 · Linux x86_64

Secreto K: 32 B · valor de cada participación: 66 B (+ 1 B de índice) · valores de las 5 participaciones: 330 B.

| Operación | Mediana (ms) | Media (ms) | P95 (ms) | Repeticiones |
|---|---:|---:|---:|---:|
| split_secret (3-de-5) | 0.0116 | 0.0164 | 0.0336 | 2000 |
| reconstruct_secret (3 shares) | 0.5316 | 0.601 | 0.8166 | 2000 |
| reconstruct_secret (5 shares, con verificación) | 1.5941 | 1.7082 | 2.2836 | 2000 |
