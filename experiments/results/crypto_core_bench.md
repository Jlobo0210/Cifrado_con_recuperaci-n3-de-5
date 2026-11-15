# Experimento 18 — cifrado de envolvente

Entorno: Python 3.13.18, cryptography 50.0.1, Linux x86_64, 4 CPU, repeticiones=5 (máx. 3 para > 50 MB), mediana

Ida = encrypt_blob / pack_source; vuelta = decrypt_blob / unpack_output.

| Experimento | Contenido | Entrada | Salida (B) | Overhead (B) | Overhead (%) | Ida (ms) | Vuelta (ms) | MB/s ida | MB/s vuelta |
|---|---|---|---|---|---|---|---|---|---|
| aead | aleatorio | 1 KB | 1058 | 34 | 3.320312 | 0.004 | 0.004 | 223.7 | 250.3 |
| tar+gzip | aleatorio | 1 KB | 1296 | 272 | 26.562 | 0.223 | 0.535 | 4.4 | 1.8 |
| tar+gzip | texto | 1 KB | 238 | -786 | -76.758 | 0.167 | 0.543 | 5.9 | 1.8 |
| aead | aleatorio | 1 MB | 1048610 | 34 | 0.003242 | 0.854 | 0.905 | 1170.7 | 1105.1 |
| tar+gzip | aleatorio | 1 MB | 1049186 | 610 | 0.058 | 19.186 | 2.151 | 52.1 | 464.8 |
| tar+gzip | texto | 1 MB | 3291 | -1045285 | -99.686 | 2.859 | 1.727 | 349.8 | 579.2 |
| aead | aleatorio | 50 MB | 52428834 | 34 | 6.5e-05 | 72.949 | 71.062 | 685.4 | 703.6 |
| tar+gzip | aleatorio | 50 MB | 52445103 | 16303 | 0.031 | 1042.032 | 76.827 | 48.0 | 650.8 |
| tar+gzip | texto | 50 MB | 152818 | -52275982 | -99.709 | 134.214 | 63.061 | 372.5 | 792.9 |
| aead | aleatorio | 190 MB | 199229474 | 34 | 1.7e-05 | 264.655 | 287.929 | 717.9 | 659.9 |
| tar+gzip | aleatorio | 190 MB | 199290523 | 61083 | 0.031 | 3885.389 | 291.315 | 48.9 | 652.2 |
| tar+gzip | texto | 190 MB | 580035 | -198649405 | -99.709 | 569.592 | 313.797 | 333.6 | 605.5 |
