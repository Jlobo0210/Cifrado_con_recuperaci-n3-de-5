# Benchmark del sistema completo (orchestrator.py)

Python 3.12.10 · Windows AMD64

Datos aleatorios (peor caso para gzip). Restauración con las participaciones 1, 3 y 5.
Tiempos: mediana de las repeticiones.

| Entrada | Original (B) | tar.gz (B) | Paquete (B) | Sobrecosto formato (B) | Participación (B) | Manifiesto (B) | Crear (ms) | Restaurar (ms) | Reps |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 KB | 1024 | 1274 | 1308 | 34 | 423 | 373 | 55.85 | 116.16 | 10 |
| 1 MB | 1048576 | 1049157 | 1049191 | 34 | 423 | 376 | 167.28 | 114.97 | 10 |
| 50 MB | 52428800 | 52445079 | 52445113 | 34 | 423 | 377 | 5551.98 | 713.19 | 3 |
| 190 MB | 199229440 | 199290502 | 199290536 | 34 | 423 | 378 | 21003.47 | 2445.23 | 3 |

Lectura: el sobrecosto del formato del paquete es constante (34 B = encabezado + nonce + tag) y cada participación y el manifiesto pesan lo mismo sin importar el tamaño del respaldo. El tiempo crece aproximadamente de forma lineal con el tamaño. Crear es más lento que restaurar porque comprimir con gzip cuesta mucho más que descomprimir; en archivos pequeños el tiempo lo dominan las escrituras atómicas con fsync de los 7 archivos. Shamir y los checksums de las participaciones son insignificantes frente a esto.
