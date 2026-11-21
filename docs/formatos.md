# Formatos, serialización y empaquetado (persona C)

Módulo: `src/formats.py`
Pruebas: `tests/test_formats.py`
Experimento: `experiments/bench_formats.py` → `experiments/results/formats_bench.{csv,md}`

Define cómo se ve cada archivo del respaldo en disco y decide qué participaciones son utilizables **antes** de intentar reconstruir la clave. No importa `crypto_core.py`, `shamir.py` ni `packaging_.py`: solo usa la biblioteca estándar (`json`, `hashlib`, `hmac`, `dataclasses`, `tempfile`, `os`, `re`, `uuid`). Los valores fijos que necesita (66 bytes, p, `"shamir-zp-m521"`, 34 bytes de sobrecosto, `"ChaCha20-Poly1305"`) están como constantes y `tests/test_formats.py` comprueba que coinciden con los otros módulos.

## 1. Archivos de un respaldo

| Archivo | Contenido | Permisos (POSIX) |
|---|---|---|
| `<backup_id>.manifest.json` | Manifiesto, sin secretos | 0644 |
| `<backup_id>.evlp` | Paquete cifrado (el blob de `crypto_core`), binario | 0644 |
| `<backup_id>.share<i>.json` | Participación `i` = 1..5, una por custodio | 0600 |

`backup_id` = 16 bytes de UUID v4 en hexadecimal minúscula (32 caracteres, `new_backup_id()`). `backup_id_to_bytes(backup_id)` devuelve los 16 bytes crudos que esperan `encrypt_blob` / `decrypt_blob` (AAD). Todas las escrituras son atómicas (temporal en la misma carpeta + `os.replace`).

## 2. Manifiesto (`Manifest`)

JSON UTF-8, claves en este orden, sin campos adicionales:

| Campo | Valor |
|---|---|
| `format` | `"EVLP-MANIFEST"` |
| `version` | `1` (entero) |
| `backup_id` | 32 hex minúsculas |
| `created_at` | ISO 8601 UTC, `"2026-09-14T15:30:00Z"` (informativo) |
| `algorithm` | `"ChaCha20-Poly1305"` |
| `sharing_scheme` | `"shamir-zp-m521"` |
| `threshold`, `total_shares` | `3`, `5` |
| `package_size` | bytes del paquete cifrado (34 ≤ n ≤ 200 MB + 34) |
| `package_checksum` | `"sha256:"` + SHA-256 del paquete completo |

## 3. Participación (`ShareFile`)

| Campo | Valor |
|---|---|
| `format` | `"EVLP-SHARE"` |
| `version`, `backup_id`, `threshold`, `total_shares`, `sharing_scheme` | como en el manifiesto |
| `index` | entero 1..5 (nunca 0) |
| `value` | f(i) como **132 hex minúsculas** = 66 bytes big-endian de ancho fijo, valor < p |
| `checksum` | `"sha256:"` + SHA-256 de los campos (ver §4) |

Una participación pesa ≈ 0,4 KB (423 B en el benchmark) y **no depende del tamaño del respaldo**. `ShareFile.value` no aparece en `repr()`/`str()`, ni en mensajes de error, ni en `inspect_file`.

## 4. Checksums

- **Paquete:** `SHA-256(BLOB)` completo, leído por bloques de 1 MiB. Va en el manifiesto con prefijo `sha256:`.
- **Participación:** `SHA-256(b"EVLP-SHARE-CHK" ‖ VERSION(1 B) ‖ BACKUP_ID(16 B) ‖ INDEX(1 B) ‖ THRESHOLD(1 B) ‖ TOTAL(1 B) ‖ VALUE(66 B))`. Son bytes de ancho fijo: no depende del orden de claves ni de espacios del JSON.

**No son MAC.** Cualquiera puede recalcularlos, así que solo detectan daño accidental. Una participación alterada con su checksum recalculado pasa `validate_share`; la atrapan `shamir.reconstruct_secret` (clave que no cabe en 256 bits, o participaciones sobrantes inconsistentes) o, al final, la verificación AEAD.

## 5. Lectura estricta

`read_manifest` / `read_share` rechazan con `FormatError` (subclase de `ValueError`): archivos de más de 64 KiB, UTF-8 inválido, JSON inválido, `NaN`/`Infinity`, claves duplicadas, campos faltantes o adicionales, tipos incorrectos (un `bool` no es entero), versión ≠ 1, `backup_id`/`value`/`checksum` fuera de formato (mayúsculas incluidas), índice fuera de 1..5, `value ≥ p`, `threshold`/`total_shares` ≠ 3/5, algoritmo o esquema desconocidos. `read_share` valida estructura y rangos, **no** el checksum (eso es `validate_share`).

## 6. Interfaz pública

| Función | Descripción |
|---|---|
| `new_backup_id() -> str` / `backup_id_to_bytes(id) -> bytes` | Identificador y sus 16 bytes crudos |
| `make_manifest(backup_id, blob) -> Manifest` | Calcula `package_size`, `package_checksum`, `created_at` (UTC) |
| `make_share(backup_id, index, value) -> ShareFile` | Valida y calcula el checksum; recibe lo que devuelve `split_secret` |
| `write_manifest` / `read_manifest` | JSON ↔ `Manifest` |
| `write_share` / `read_share` | JSON ↔ `ShareFile` |
| `write_package(blob, path)` / `read_package(path)` | Paquete binario (tamaño validado) |
| `verify_package(blob, manifest) -> bool` | Tamaño y SHA-256 del paquete |
| `validate_share(share, manifest) -> bool` | Pertenece al respaldo y no está dañada |
| `diagnose_share(share, manifest) -> str \| None` | `None` o el motivo: `"dañada"`, `"de otro respaldo"` |
| `find_duplicate_indices(shares) -> list[int]` | Índices repetidos |
| `load_shares(paths, manifest) -> (válidas, rechazadas)` | Lee, valida y descarta; rechazadas = `[(ruta, motivo)]` con `"dañada"`, `"duplicada"`, `"de otro respaldo"` |
| `infer_backup_id(paths) -> str` | `backup_id` mayoritario entre las participaciones legibles |
| `locate_files(directory, backup_id=None) -> (manifest_path, package_path)` | Búsqueda automática; el error dice qué archivo falta |
| `inspect_file(path) -> dict` | Metadatos no secretos de un manifiesto o participación (`checksum_ok` en participaciones) |
| `manifest_filename` / `package_filename` / `share_filename` | Convención de nombres |

Cambios respecto a la interfaz de la Semana 1: `version` es `int` (no `str`); el manifiesto añade `package_size` y `sharing_scheme`; la participación añade `threshold`, `total_shares` y `sharing_scheme`; el campo `package_checksum` lleva prefijo `sha256:`.

## 7. Uso desde el orquestador (persona D)

```python
import crypto_core as cc, shamir, packaging_ as pk, formats as fm

# Crear (A -> B -> C)
backup_id = fm.new_backup_id()
key = cc.generate_key()
blob = cc.encrypt_blob(key, pk.pack_source(input_path), fm.backup_id_to_bytes(backup_id))
shares = shamir.split_secret(bytes(key), 3, 5)
cc.wipe(key)
fm.write_package(blob, os.path.join(out, fm.package_filename(backup_id)))
fm.write_manifest(fm.make_manifest(backup_id, blob), os.path.join(out, fm.manifest_filename(backup_id)))
for index, value in shares:
    fm.write_share(fm.make_share(backup_id, index, value), os.path.join(out, fm.share_filename(backup_id, index)))

# Restaurar (C -> B -> A)
backup_id = fm.infer_backup_id(share_paths)
manifest_path, package_path = fm.locate_files(os.path.dirname(share_paths[0]), backup_id)
manifest = fm.read_manifest(manifest_path)
blob = fm.read_package(package_path)
if not fm.verify_package(blob, manifest) or cc.parse_header(blob)["version"] != manifest.version:
    ...                                   # mismo mensaje genérico que un fallo de autenticación
valid, rejected = fm.load_shares(share_paths, manifest)   # rejected: [(ruta, motivo)] para informar
if len(valid) < manifest.threshold:
    ...                                   # "no hay participaciones suficientes" + lista de rechazadas
key = bytearray(shamir.reconstruct_secret([(s.index, s.value) for s in valid], manifest.threshold))
try:
    payload = cc.decrypt_blob(key, blob, fm.backup_id_to_bytes(manifest.backup_id))
finally:
    cc.wipe(key)
pk.unpack_output(payload, output_path)
```

Puntos a tener en cuenta:

- **Diagnóstico diferenciado vs. mensajes genéricos:** el motivo de rechazo de una participación (`dañada`, `duplicada`, `de otro respaldo`) se puede mostrar al usuario porque sale de la capa de formatos, antes de cualquier operación criptográfica y sobre datos no secretos. Los fallos de `shamir.InconsistentSharesError`, `crypto_core.AuthenticationError` y un `verify_package` falso deben mostrarse con el **mismo mensaje genérico** (decisión "Mensajes de error no diferenciados" del Entregable 1).
- **Más de 3 participaciones y una alterada con checksum recalculado:** `reconstruct_secret` lanza `InconsistentSharesError`. Si se quiere tolerar, reintentar con los subconjuntos de 3 (máx. 10) y quedarse con el que verifique AEAD.
- **`verify_package` no cruza `VERSION` / `ALG_ID`** del encabezado con el manifiesto; se hace con `cc.parse_header(blob)` (versión y `ALGORITHM_NAMES`).
- **Inspector:** `fm.inspect_file(path)` ya devuelve el `dict` de `inspect()` sin el valor de la participación; `FormatError` si el archivo no es ninguno de los dos tipos.
- **Carpeta con varios respaldos:** `locate_files(dir)` sin `backup_id` falla si hay más de un manifiesto; use `infer_backup_id(share_paths)`.

## 8. Pruebas

| Caso del plan | Prueba |
|---|---|
| F1 manifiesto roundtrip y checksum | `test_F1_roundtrip_manifiesto` |
| F2 participación roundtrip | `test_F2_roundtrip_participacion` |
| F3 ceros a la izquierda, 0 y p − 1 | `test_F3_valores_borde_conservan_66_bytes` |
| F4 participación válida | `test_F4_participacion_valida` |
| F5 valor alterado | `test_F5_valor_alterado_sin_recalcular_checksum` |
| F6 índice alterado | `test_F6_indice_alterado_sin_recalcular_checksum` |
| F7 otro respaldo con checksum correcto | `test_F7_participacion_de_otro_respaldo_con_checksum_correcto` |
| F8 índices 0, 6, negativo, decimal, texto | `test_F8_indice_invalido_*` |
| F9 valor de longitud/formato/rango inválido | `test_F9_valor_invalido*` |
| F10 JSON inválido, versión, campos, claves duplicadas | `test_F10_*` |
| F11 índices duplicados | `test_F11_*`, `test_load_shares_*` |
| F12 paquete o manifiesto alterados | `test_F12_*` |
| F13 umbral/total/algoritmo inválidos | `test_F13_manifiesto_invalido` |
| F14 el valor no se filtra | `test_F14_*` |
| F15 búsqueda automática de archivos | `test_F15_*`, `test_infer_backup_id` |
| F16 tamaños y experimento | `test_F16_tamano_de_los_archivos`, `experiments/bench_formats.py` |
| Integración A + B + C | `test_integracion_*` (las 10 combinaciones, 2 participaciones, repetida/ajena/dañada, paquete alterado, participación alterada con checksum recalculado) |

```bash
python -m pytest tests/test_formats.py -q
python experiments/bench_formats.py            # o --quick
```

Las pruebas de integración y de constantes se omiten si `cryptography` o los demás módulos no están disponibles.

## 9. Limitaciones y fuera de alcance

- El checksum no es un MAC (ver §4); no hay secret sharing verificable (fuera de alcance del proyecto).
- El manifiesto no está cifrado ni firmado: `created_at`, `threshold` y `total_shares` no quedan protegidos criptográficamente (los dos últimos se comparan con las constantes de la versión 1). `backup_id`, versión y algoritmo sí están ligados al AAD del paquete.
- La exportación de participaciones a QR (opcional en el enunciado) no se implementó; el contenido a codificar sería el mismo JSON de la participación.
- Los permisos 0600/0644 son de POSIX; en Windows `os.chmod` solo controla el bit de solo lectura.
