# Benchmark de formatos y checksums (formats.py)

Python 3.10.12 · Linux aarch64

Tamaño en disco: participación **423 B** · manifiesto **373 B** (constantes: no dependen del tamaño del respaldo). Cinco participaciones: 2115 B.

| Operación | Entrada | Bytes | Mediana (ms) | Repeticiones |
|---|---|---:|---:|---:|
| make_share (checksum) | — | 423 | 0.0028 | 2000 |
| write_share (atómico, fsync) | — | 423 | 4.7299 | 200 |
| read_share | — | 423 | 0.0168 | 2000 |
| validate_share | — | 423 | 0.023 | 2000 |
| write_manifest (atómico, fsync) | — | 373 | 4.06 | 200 |
| read_manifest | — | 373 | 0.0201 | 2000 |
| package_checksum (SHA-256) | 1 KB | 1024 | 0.002 | 20 |
| verify_package | 1 KB | 1024 | 0.002 | 20 |
| write_package | 1 KB | 1024 | 5.977 | 20 |
| read_package | 1 KB | 1024 | 0.008 | 20 |
| package_checksum (SHA-256) | 1 MB | 1048576 | 0.566 | 20 |
| verify_package | 1 MB | 1048576 | 0.528 | 20 |
| write_package | 1 MB | 1048576 | 3.903 | 20 |
| read_package | 1 MB | 1048576 | 0.048 | 20 |
| package_checksum (SHA-256) | 50 MB | 52428800 | 22.364 | 3 |
| verify_package | 50 MB | 52428800 | 22.086 | 3 |
| write_package | 50 MB | 52428800 | 55.972 | 3 |
| read_package | 50 MB | 52428800 | 12.443 | 3 |
| package_checksum (SHA-256) | 190 MB | 199229440 | 82.574 | 3 |
| verify_package | 190 MB | 199229440 | 82.775 | 3 |
| write_package | 190 MB | 199229440 | 172.711 | 3 |
| read_package | 190 MB | 199229440 | 48.927 | 3 |

Lectura: leer y validar una participación o el manifiesto cuesta centésimas de milisegundo; escribirlos cuesta unos pocos milisegundos, dominados por el fsync de la escritura atómica. El único costo que crece con el respaldo es el SHA-256 del paquete: lineal en su tamaño y mucho menor que el de comprimirlo o cifrarlo (ver experimento 18).
