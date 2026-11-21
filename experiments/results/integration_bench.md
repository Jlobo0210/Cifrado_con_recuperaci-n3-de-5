# Benchmark del sistema completo (orchestrator.py)

Python 3.12.10 · Windows AMD64

Datos aleatorios (peor caso para gzip). Restauración con las participaciones 1, 3 y 5.
Tiempos: mediana de las repeticiones.

| Entrada | Original (B) | tar.gz (B) | Paquete (B) | Sobrecosto formato (B) | Participación (B) | Manifiesto (B) | Crear (ms) | Restaurar (ms) | Reps |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 KB | 1024 | 1276 | 1310 | 34 | 423 | 373 | 37.53 | 62.51 | 10 |
| 1 MB | 1048576 | 1049158 | 1049192 | 34 | 423 | 376 | 84.58 | 70.71 | 10 |
| 50 MB | 52428800 | 52445080 | 52445114 | 34 | 423 | 377 | 2290.01 | 346.35 | 3 |
| 190 MB | 199229440 | 199290509 | 199290543 | 34 | 423 | 378 | 8560.56 | 1182.24 | 3 |

Lectura: el sobrecosto del formato del paquete es constante (34 B = encabezado + nonce + tag) y cada participación y el manifiesto pesan lo mismo sin importar el tamaño del respaldo. El tiempo crece aproximadamente de forma lineal con el tamaño. Crear es más lento que restaurar porque comprimir con gzip cuesta mucho más que descomprimir; en archivos pequeños el tiempo lo dominan las escrituras atómicas con fsync de los 7 archivos. Shamir y los checksums de las participaciones son insignificantes frente a esto.
