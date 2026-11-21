# Cifrado de envolvente (persona A)

Módulos: `src/crypto_core.py`, `src/packaging_.py`, `src/exceptions.py`
Pruebas: `tests/test_crypto_core.py`, `tests/test_packaging.py`, `tests/test_envelope_roundtrip.py`
Experimento: `experiments/bench_crypto_core.py` (caso 18 del plan de pruebas)

Este componente protege el contenido del usuario. Recibe un archivo o directorio, lo convierte en un único payload tar+gzip y lo cifra con ChaCha20-Poly1305 usando una clave aleatoria de 256 bits. Al restaurar hace el camino inverso y solo extrae el contenido después de que la verificación AEAD fue exitosa. No conoce Shamir, el manifiesto ni las participaciones: recibe y devuelve bytes.

## 1. Interfaz pública

### `crypto_core.py`

| Función | Descripción |
|---|---|
| `generate_key() -> bytearray` | 32 bytes de `os.urandom`. Una clave nueva por respaldo. Es un `bytearray` para poder borrarla con `wipe()`. |
| `encrypt_blob(key, plaintext, backup_id) -> bytes` | Cifra y devuelve `MAGIC ‖ VERSION ‖ ALG_ID ‖ NONCE ‖ CIPHERTEXT ‖ TAG`. `backup_id` son los 16 bytes crudos del UUID (`uuid.UUID(...).bytes`). |
| `decrypt_blob(key, blob, backup_id) -> bytes` | Valida la estructura, reconstruye el AAD y descifra. Lanza `AuthenticationError` si el tag no verifica. |
| `parse_header(blob) -> dict` | Lee versión, algoritmo y tamaños **sin clave**. Para el inspector y para comparar con los campos `version`/`algorithm` del manifiesto. |
| `wipe(buffer)` | Sobrescribe con ceros un `bytearray` (clave o plaintext). Mitigación de mejor esfuerzo. |

Constantes útiles para los demás módulos: `KEY_SIZE = 32`, `BACKUP_ID_SIZE = 16`, `FORMAT_OVERHEAD = 34`, `ALGORITHM_NAMES = {0x01: "ChaCha20-Poly1305"}`.

### `packaging_.py`

| Función | Descripción |
|---|---|
| `pack_source(path) -> bytes` | Empaqueta archivo o directorio en tar+gzip. Aplica el límite preliminar (400 MB en disco) y el autoritativo (200 MB empaquetado). |
| `unpack_output(payload, output_dir) -> None` | Extrae de forma segura y "todo o nada" (ver §4). |

### Excepciones (`exceptions.py`)

| Excepción | Cuándo | Hereda de |
|---|---|---|
| `InvalidBlobFormatError` | MAGIC incorrecto, blob < 34 bytes, tipo no bytes | `EnvelopeError`, `ValueError` |
| `AuthenticationError` | Cualquier fallo del tag: clave, backup_id, encabezado, nonce, ciphertext o tag alterados. **Mismo mensaje siempre.** | `EnvelopeError` |
| `PayloadTooLargeError` | Supera el límite preliminar o el autoritativo | `EnvelopeError`, `ValueError` |
| `ExtractionError` | tar/gzip dañado, rutas peligrosas, dispositivos, o el destino ya contiene una entrada con el mismo nombre | `EnvelopeError` |

## 2. Uso desde el orquestador

```python
import uuid
import crypto_core as cc
import packaging_ as pk

# Crear
backup_uuid = uuid.uuid4()
key = cc.generate_key()
blob = cc.encrypt_blob(key, pk.pack_source(input_path), backup_uuid.bytes)
shares = split_secret(bytes(key), 3, 5)      # persona B
cc.wipe(key)                                 # la clave no se guarda en ningún lado

# Restaurar
key = bytearray(reconstruct_secret(shares, 3))
try:
    payload = cc.decrypt_blob(key, blob, uuid.UUID(manifest.backup_id).bytes)
finally:
    cc.wipe(key)
pk.unpack_output(payload, output_path)       # solo se llega aquí si AEAD verificó
```

`manifest.backup_id` es el hex de 32 caracteres; el AAD usa los 16 bytes crudos, por eso se convierte con `uuid.UUID(...).bytes` (o `bytes.fromhex(...)`).

## 3. Formato del blob (versión 1)

```
offset  tamaño  campo
0       4       MAGIC = b"EVLP"
4       1       VERSION = 0x01
5       1       ALG_ID = 0x01 (ChaCha20-Poly1305, RFC 8439)
6       12      NONCE (os.urandom(12))
18      n       CIPHERTEXT
18+n    16      TAG (Poly1305)

AAD = MAGIC ‖ VERSION ‖ ALG_ID ‖ BACKUP_ID(16 B)    → 22 bytes
```

- Tamaño mínimo válido: 34 bytes (payload vacío). Sobrecosto constante de 34 bytes, sin importar el tamaño (comprobado en `test_case18_overhead_constante` y en el experimento).
- El nonce no está en el AAD porque ya es entrada del AEAD: alterarlo hace fallar el tag (caso 13).
- `VERSION` y `ALG_ID` sí están en el AAD. `decrypt_blob` no los rechaza explícitamente: un valor alterado produce el mismo `AuthenticationError` genérico que una clave incorrecta, para no dar un oráculo de "qué byte cambió" (caso 12). Para mostrar la versión sin clave se usa `parse_header`.

## 4. Empaquetado, límites y extracción

**Compresión.** tar + gzip antes de cifrar (el ciphertext no es comprimible). Un archivo suelto también va en un tar de un miembro, para conservar su nombre.

**Límite de 200 MB.** Se aplica al payload ya empaquetado (`200 × 1024 × 1024` bytes), que es lo que se cifra y se guarda. Antes de empaquetar hay un rechazo rápido si el origen supera 400 MB en disco; el caso 8 comprueba con un espía que `tarfile.open` ni siquiera se llama en ese caso.

**Extracción segura ("todo o nada").** `unpack_output`:

1. Lee todas las entradas del tar y valida cada una con `_check_member` antes de escribir nada: rechaza rutas absolutas, componentes `..`, enlaces simbólicos o duros que apunten fuera del destino y dispositivos/FIFOs.
2. Extrae en un directorio temporal oculto dentro del destino, con el filtro `"data"` de `tarfile` cuando existe.
3. Si alguna entrada ya existe en el destino, aborta sin sobrescribir nada.
4. Mueve las entradas al destino y borra el temporal. Ante cualquier error, el destino queda como estaba.

Así la protección contra *path traversal* ya no depende solo de la versión de Python (limitación que se había declarado en el Entregable 1).

## 5. La clave solo en memoria

- Ningún módulo de A escribe la clave ni el plaintext a disco o a logs. Los mensajes de `AuthenticationError` no incluyen la clave ni el plaintext (`test_ningun_secreto_en_mensajes_de_error`). `ExtractionError` sí nombra la entrada problemática, pero solo ocurre después de que AEAD verificó y le habla al dueño del respaldo.
- `generate_key()` devuelve un `bytearray` y `encrypt_blob`/`decrypt_blob` lo aceptan sin copiarlo a `bytes`, para que el orquestador lo borre con `wipe()` al terminar.
- Limitación: Python y `cryptography` pueden tener copias internas que no se pueden borrar desde Python, y el sistema operativo podría paginar memoria a swap. `wipe()` reduce la ventana de exposición pero no es una garantía formal.

## 6. Pruebas (casos 1–18 del plan)

| Caso | Prueba | Estado |
|---|---|---|
| 1 Roundtrip básico | `test_case1_roundtrip_basico` | ✅ |
| 2 Payload vacío | `test_case2_payload_vacio` | ✅ |
| 3 Binario arbitrario | `test_case3_contenido_binario_arbitrario` | ✅ |
| 4 Directorio anidado, nombres y permisos | `test_case4_directorio_anidado`, `test_case4_preserva_bit_de_ejecucion` | ✅ |
| 5 Archivo individual | `test_case5_archivo_individual` | ✅ |
| 6 ~199 MB | `test_case6_payload_grande_smoke` (5 MB, siempre) y `test_case6_payload_cercano_a_200mb` (199 MB, con `EVLP_SLOW_TESTS=1`) | ✅ |
| 7 > 200 MB empaquetado | `test_case7_excede_limite_autoritativo` | ✅ |
| 8 > 400 MB en disco, sin empaquetar | `test_case8_excede_umbral_preliminar` (con espía sobre `tarfile.open`) | ✅ |
| 9 Clave incorrecta | `test_case9_clave_incorrecta` | ✅ |
| 10 backup_id incorrecto | `test_case10_backup_id_incorrecto` | ✅ |
| 11 Bit alterado | `test_case11_bit_flip_en_ciphertext`, `test_tag_alterado_falla_autenticacion` | ✅ |
| 12 ALG_ID alterado | `test_case12_alg_id_alterado`, `test_version_alterada_falla_autenticacion` | ✅ |
| 13 Nonce alterado | `test_case13_nonce_alterado` | ✅ |
| 14 Blob truncado | `test_case14_blob_truncado`, `test_blob_sin_espacio_para_tag_es_formato_invalido` | ✅ |
| 15 MAGIC incorrecto | `test_case15_magic_incorrecto` | ✅ |
| 16 Bloques reordenados | `test_case16_reordenar_bytes_ciphertext` | ✅ |
| 17 1000 nonces sin colisión | `test_case17_nonces_sin_colision` (nonces sacados de blobs reales) | ✅ |
| 18 Tiempos y overhead | `test_case18_overhead_constante` + `experiments/bench_crypto_core.py` | ✅ |

Pruebas adicionales: mensajes de autenticación idénticos, validación de entradas, `wipe`, `parse_header`, extracción segura (traversal, symlinks, dispositivos, todo o nada, no sobrescribir), Unicode, directorios vacíos, y el flujo completo `pack → encrypt → decrypt → unpack`.

```bash
pip install -r requirements.txt
python -m pytest tests/test_crypto_core.py tests/test_packaging.py tests/test_envelope_roundtrip.py -q
EVLP_SLOW_TESTS=1 python -m pytest -q -k case6     # prueba de ~199 MB
```

## 7. Experimento 18

```bash
python experiments/bench_crypto_core.py            # 1 KB, 1 MB, 50 MB, 190 MB
python experiments/bench_crypto_core.py --quick    # versión rápida
```

Genera `experiments/results/crypto_core_bench.csv` y `.md`. Los resultados incluidos en el repositorio se tomaron en un contenedor Linux x86_64 de 4 CPU (Python 3.13, cryptography 50); conviene repetirlos en el equipo de la demo para el informe.

Resumen de esa corrida (mediana):

| Tamaño | Blob − entrada | Cifrar | Descifrar | tar+gzip (aleatorio) | tar+gzip (texto) |
|---|---|---|---|---|---|
| 1 KB | 34 B | 0,004 ms | 0,004 ms | 0,22 ms | 0,17 ms |
| 1 MB | 34 B | 0,85 ms | 0,91 ms | 19 ms | 2,9 ms |
| 50 MB | 34 B | 73 ms | 71 ms | 1,04 s | 134 ms |
| 190 MB | 34 B | 265 ms | 288 ms | 3,89 s | 570 ms |

Lectura: el sobrecosto del formato es exactamente 34 bytes en todos los tamaños. ChaCha20-Poly1305 corre a ~700 MB/s, así que el cuello de botella al crear un respaldo es gzip (~49 MB/s en datos incompresibles). En datos aleatorios gzip agrega ~0,03 %; en texto reduce el tamaño ~99 %.

## 8. Cambios respecto al Entregable 1

1. **Interfaz con `backup_id` en vez de `aad`.** El plan inicial pedía `encrypt_blob(key, plaintext, aad)`. Se cambió a `backup_id` para que el AAD lo construya siempre este módulo (`HEADER ‖ BACKUP_ID`) y nadie pueda pasar un AAD inconsistente. Ya estaba así en la sección de arquitectura del Entregable 1.
2. **`generate_key()` devuelve `bytearray`.** Antes `bytes`. Permite borrar la clave con `wipe()`. Se comporta igual que `bytes` para Shamir (`int.from_bytes`, `len`, comparación).
3. **Nuevas funciones `parse_header` y `wipe`, y nueva excepción `ExtractionError`.**
4. **Tamaño mínimo de blob de 34 bytes.** Un blob de 18 a 33 bytes ahora es `InvalidBlobFormatError` en lugar de llegar al AEAD.
5. **Extracción segura propia.** El Entregable 1 dependía solo del filtro `"data"` de Python 3.12+. Ahora hay una validación propia de cada entrada, extracción atómica y no se sobrescriben archivos existentes.
6. **Archivo suelto en `"."`.** `pack_source(".")` ahora usa el nombre real de la carpeta en lugar de `"."`.

## 9. Limitaciones conocidas

- El payload completo (hasta 200 MB) se mantiene en memoria durante el empaquetado y el cifrado; no hay cifrado por bloques en streaming. Es suficiente para el límite del prototipo.
- El borrado de la clave es de mejor esfuerzo (ver §5).
- Compresión antes de cifrar: riesgo teórico de canal lateral por tamaño (CRIME/BREACH), fuera del modelo de adversario (uso local, sin oráculo interactivo).
- tar no guarda propietarios al extraer con el filtro `"data"`, y quita bits peligrosos (setuid, escritura de grupo/otros). Se conservan los bits de ejecución en Linux/macOS; en Windows no existen esos permisos, por lo que esa prueba se omite allí.
