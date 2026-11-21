# CLI, orquestación, inspector y pruebas de integración (persona D)

Módulos: `src/orchestrator.py`, `src/cli.py`
Pruebas: `tests/test_integration.py` (casos 19–29 del plan)
Demostración: `demo/demo.py`
Experimento: `experiments/bench_integration.py` → `experiments/results/integration_bench.{csv,md}` (caso 30)

El orquestador **no hace criptografía**: llama en orden a los módulos de A, B y C y solo depende de sus funciones públicas. La CLI solo lee argumentos, llama al orquestador y muestra los resultados.

## 1. Interfaz pública

| Función | Descripción |
|---|---|
| `create_backup(input_path, output_dir) -> str` | Crea el respaldo y devuelve el `backup_id` |
| `restore_backup(share_paths, output_path) -> list[tuple[str, str]]` | Restaura y devuelve las participaciones descartadas `[(ruta, motivo)]` |
| `inspect(path) -> dict` | Metadatos no secretos de una participación, un manifiesto o un paquete `.evlp` |

### Excepciones

| Excepción | Cuándo | Mensaje |
|---|---|---|
| `NotEnoughSharesError` | Quedan menos de 3 participaciones válidas | Detallado, con `.rejected` (motivos de formatos, sin secretos) |
| `VerificationError` | El paquete no coincide con el manifiesto (tamaño, SHA-256 o encabezado), o ninguna terna verifica AEAD | Siempre `GENERIC_ERROR` (Sección 6.3) |

Ambas heredan de `RestoreError`. También pueden propagarse `FormatError` (manifiesto mal formado o ausente), `PayloadTooLargeError` (más de 200 MB), `ExtractionError` (destino ocupado) y `FileNotFoundError`.

## 2. Flujo

**Crear (A → B → C):**
1. `pack_source` empaqueta y aplica el límite de 200 MB **antes** de generar la clave o escribir algo.
2. `generate_key` → `encrypt_blob` (AAD con el `backup_id`) → `split_secret(K, 3, 5)` → `wipe(K)`.
3. Se escriben paquete, manifiesto y 5 participaciones. Si falla la escritura a mitad, se borran los archivos ya escritos.

**Restaurar (C → B → A):**
1. `infer_backup_id` identifica el respaldo y `locate_files` busca manifiesto y paquete en la carpeta de las participaciones (Sección 6.5).
2. `verify_package` (tamaño y SHA-256) y `parse_header` (versión y algoritmo contra el manifiesto). Si algo no coincide: `VerificationError`.
3. `load_shares` descarta las dañadas, duplicadas o de otro respaldo (Sección 6.6). Si quedan menos de 3: `NotEnoughSharesError`.
4. Para cada terna de participaciones válidas: `reconstruct_secret` → `decrypt_blob` → `wipe(K)`. Se usa la primera que verifique AEAD.
5. `unpack_output` extrae **solo después** de una verificación AEAD exitosa.

### ¿Por qué se prueban ternas?

El checksum de una participación no es un MAC (ver `docs/formatos.md` §4): una participación alterada con su checksum recalculado pasa la capa de formatos. Con exactamente 3 participaciones, AEAD la detecta y la restauración falla con el mensaje genérico. Con 4 o 5, la terna que la incluye falla y se prueba la siguiente; como máximo son C(5, 3) = 10 intentos. Con participaciones sanas, el primer intento funciona. Así se cumple la tolerancia de la Sección 6.6 también en este caso.

## 3. CLI

```bash
python src/cli.py crear ORIGEN -o CARPETA_SALIDA
python src/cli.py restaurar SHARE [SHARE ...] -o CARPETA_DESTINO
python src/cli.py inspeccionar ARCHIVO [ARCHIVO ...]
```

- Código de salida 0 si todo salió bien y 1 si hubo error. Los errores se muestran en una línea, sin traceback.
- Al restaurar se informa cada participación descartada con su motivo (`dañada`, `duplicada`, `de otro respaldo`), nunca su valor.
- `inspeccionar` nunca muestra el campo `value` ni la clave; para un `.evlp` solo lee el encabezado.

## 4. La clave solo en memoria

K se maneja como `bytearray` y se borra con `crypto_core.wipe()` justo después de `split_secret` al crear, y después de cada intento de descifrado al restaurar (incluso si falla). Nunca se escribe en disco ni se imprime. Como explican `crypto_core.py` y `shamir.py`, es una mitigación de mejor esfuerzo: Python y `cryptography` pueden dejar copias internas (por ejemplo, el `bytes` que devuelve `reconstruct_secret`).

## 5. Pruebas (casos 19–29 del plan)

| Caso del plan | Prueba |
|---|---|
| 19 Las diez combinaciones de 3 | `test_caso19_las_diez_combinaciones_restauran` |
| 20 Solo dos participaciones | `test_caso20_dos_participaciones_no_alcanzan` (las 10 parejas) |
| 21 Participación repetida | `test_caso21_*` |
| 22 Participación alterada | `test_caso22_*` (sin y con checksum recalculado, archivo ilegible) |
| 23 Mezcla de dos respaldos | `test_caso23_*` |
| 24 Paquete modificado | `test_caso24_*` (byte del ciphertext, tag con manifiesto actualizado, ALG_ID, truncado) |
| 25 Manifiesto modificado | `test_caso25_*` (checksum, tamaño, umbral, total, algoritmo, versión, backup_id, created_at) |
| 26 Archivo vacío | `test_caso26_archivo_vacio`, `test_caso26_directorio_vacio` |
| 27 Archivo binario | `test_caso27_archivo_binario` |
| 28 Cercano a 200 MB | `test_caso28_respaldo_cercano_a_200mb` (lenta) |
| 29 Supera el límite | `test_caso29_limite_se_respeta_desde_la_orquestacion` (límite reducido) y `test_caso29_respaldo_que_supera_200mb` (lenta) |
| 30 Mediciones | `experiments/bench_integration.py` |
| Mensaje genérico (6.3) | `test_mensaje_generico_identico_en_todos_los_fallos_de_verificacion` |
| Inspector | `test_inspector_*` |
| CLI | `test_cli_*` |

```bash
python -m pytest tests/test_integration.py -q
EVLP_SLOW_TESTS=1 python -m pytest tests/test_integration.py -q   # incluye 28 y 29 con ~200 MB
python experiments/bench_integration.py                             # o --quick
python demo/demo.py
```

## 6. Cambios respecto al Entregable 1

- `restore_backup` devuelve la lista de participaciones descartadas en lugar de `None`, para que la CLI pueda informarlas aunque la restauración salga bien.
- `inspect` también acepta el paquete `.evlp` (muestra solo su encabezado).
- El guion de demostración es `demo/demo.py` en lugar de `demo.sh`, para que funcione igual en Windows, Linux y macOS.

## 7. Limitaciones conocidas

- `created_at` del manifiesto no está protegido (Sección 5.2); la prueba `test_caso25_created_at_no_esta_protegido` lo documenta.
- Con una participación alterada y checksum recalculado, el peor caso son 10 intentos de descifrado. Para un paquete cercano a 200 MB eso puede tardar varios segundos, pero solo pasa si hay participaciones manipuladas.
- El manifiesto y el paquete deben estar en la misma carpeta que al menos una de las participaciones entregadas (Sección 6.5).