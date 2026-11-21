# Shamir Secret Sharing

Módulo: `src/shamir.py`
Pruebas: `tests/test_shamir.py`
Experimento: `experiments/bench_shamir.py` → `experiments/results/shamir_bench.{csv,md}`

Reparte la clave `K` de 256 bits entre 5 custodios: **cualquier 3** la reconstruyen y **2 o menos no obtienen información** sobre ella. Implementa lo definido en el Entregable 1 (§4.3, §6.7, §7.1, §8.3). Solo ve enteros/bytes: no conoce el archivo del usuario, el AEAD, el manifiesto ni el formato de las participaciones, y no usa bibliotecas externas.

## 1. Esquema (según el Entregable 1)

| Elemento | Valor |
|---|---|
| Campo | Z_p con p = 2^521 − 1 (primo de Mersenne); p > 2^256 |
| Secreto | `K`, **exactamente 32 bytes**, tratado como un entero big-endian |
| Polinomio | `f(x) = K + a1·x + a2·x² (mod p)` para 3-de-5; `a_i` uniformes en Z_p |
| Participaciones | `(i, f(i))`, `i = 1..n`; **nunca `i = 0`** (`f(0) = K`) |
| Valor `f(i)` | entero big-endian de **66 bytes** de ancho fijo (⌈521/8⌉), con ceros a la izquierda |
| Índice | entero 1..255 (cabe en 1 byte; el proyecto usa 1..5) |
| Reconstrucción | Lagrange en `x = 0`; inverso por Fermat, `pow(a, p−2, p)` |
| Aleatoriedad | `os.urandom`, con muestreo con rechazo para que `a_i` sea uniforme en Z_p |
| Nombre en manifiesto/share | `sharing_scheme = "shamir-zp-m521"` (`shamir.SHARING_SCHEME`) |

## 2. Interfaz pública

| Función | Descripción |
|---|---|
| `split_secret(secret, threshold, total_shares) -> list[tuple[int, bytes]]` | `[(1, v1), ..., (n, vn)]`, cada `v` de 66 bytes. Acepta `bytes`, `bytearray` o `memoryview` de 32 bytes. |
| `reconstruct_secret(shares, threshold) -> bytes` | Devuelve `K` (32 bytes). Con menos de `threshold` participaciones distintas falla de inmediato, sin interpolar. |

Restricciones: `2 <= threshold <= total_shares <= 255`; secreto de 32 bytes.
Constantes para otros módulos: `P`, `SECRET_SIZE = 32`, `SHARE_VALUE_SIZE = 66`, `SHARING_SCHEME`, `MAX_SHARES = 255`. (`formats.py` no debe importar `shamir.py`; estas constantes son la referencia para sus valores fijos.)

### Excepciones

Se definen en `shamir.py` (no en `exceptions.py`, de la persona A) para no tocar archivos compartidos. **Todas heredan de `ValueError`** (caso U3/U6 del plan) y de `ShamirError`.

| Excepción | Cuándo |
|---|---|
| `InvalidParametersError` | `threshold`/`total_shares` fuera de rango o no enteros; secreto que no es bytes-like de 32 bytes |
| `InvalidShareError` | Participación mal formada; **índice 0** o fuera de 1..255; **índice repetido**; valor que no mide 66 bytes o es ≥ p |
| `InsufficientSharesError` | Menos participaciones distintas que el umbral |
| `InconsistentSharesError` | Más del umbral y las sobrantes no concuerdan con el polinomio, **o** la clave reconstruida no cabe en 256 bits |

## 3. Algoritmo

**Reparto.** `K = int.from_bytes(secret, "big")`; se generan `t−1` coeficientes uniformes en Z_p; `f(i)` se evalúa con Horner mod p para `i = 1..n` y se serializa con `.to_bytes(66, "big")`.

**Reconstrucción.** Se validan todas las participaciones (forma, índice, longitud 66, valor < p, sin repetidos). Con ≥ `t`, se usan las primeras `t` y
`K = Σ_i f(x_i) · Π_{j≠i} (−x_j) / (x_i − x_j)  (mod p)`.

Tamaños (3-de-5): valor 66 B + índice 1 B por participación; 330 B de valores en total. Tiempos del orden de décimas de milisegundo (ver `experiments/results/shamir_bench.md`).

## 4. Seguridad: "2 participaciones no revelan nada"

Con `f(x) = K + a1·x + a2·x²`, dos custodios con índices `x1 ≠ x2` ven `(f(x1), f(x2))`. La aplicación `(a1, a2) → (f(x1), f(x2))` es lineal con matriz `[[x1, x1²], [x2, x2²]]`, de determinante `x1·x2·(x2 − x1)`, distinto de 0 en Z_p para todo par de índices (p es primo y 0 < x1 < x2 < p). Es por tanto una biyección de Z_p² en sí mismo **para cada valor de K**; como `a1, a2` son uniformes e independientes, lo que ven dos custodios tiene la misma distribución para cualquier secreto (secreto perfecto de Shannon, no depende del poder de cómputo).

Verificación en las pruebas:
- `U8` (constructiva): con 2 participaciones reales y **cualquier** secreto candidato K' se construye el polinomio por (0, K'), (x1, y1), (x2, y2) y un tercer punto compatible hace que el sistema reconstruya K'.
- Determinante ≠ 0 comprobado para **todos** los pares de índices 1..255.
- Chi-cuadrado sobre el valor de una participación con secreto fijo.

## 5. Lo que Shamir NO da (y quién lo cubre)

| Riesgo | Qué hace `reconstruct_secret` | Quién lo detecta |
|---|---|---|
| Participación alterada **de forma pequeña**, con exactamente `t` entregadas | Devuelve otra clave en silencio | Checksum del share (`formats.py`); tag AEAD (`crypto_core.py`) |
| Participación alterada/aleatoria/de otro respaldo, con exactamente `t`, que lleva a un entero ≥ 2^256 | `InconsistentSharesError` (el entero no puede ser una clave) | Este módulo (comprobación extra) |
| Más de `t` entregadas y alguna no concuerda | `InconsistentSharesError` | Este módulo (comprobación extra) |
| Participación repetida / índice 0 / valor mal formado | `InvalidShareError` | Este módulo |
| Menos de `t` | `InsufficientSharesError` | Este módulo |

La integridad real del sistema sigue siendo la del Entregable 1: `validate_share` (checksum y `backup_id`) antes de reconstruir y AEAD al final (§5.4).

## 6. Decisiones de esta implementación respecto al Entregable 1

El PDF fija el esquema y las interfaces; estos puntos lo completan y conviene que el equipo los conozca:

1. **Secreto de exactamente 32 bytes.** Z_p no codifica la longitud, y el PDF define la entrada como `K` de 256 bits; `reconstruct_secret` devuelve siempre 32 bytes (con ceros a la izquierda si hace falta).
2. **Cualquier error de este módulo es `ValueError`**, como pide U3 y U6.
3. **Comprobación `K < 2^256`.** Una clave reconstruida con participaciones incorrectas es casi uniforme en Z_p y cae fuera de 256 bits con probabilidad 1 − 2^-265; en ese caso se lanza `InconsistentSharesError` en lugar de entregar una "clave" imposible al AEAD. **El orquestador debe tratar este error igual que un fallo AEAD, con mensaje genérico** (§6.3 del PDF). No sustituye al AEAD: una alteración pequeña sigue dando una clave de 256 bits incorrecta y solo AEAD la detecta.
4. **Verificación de participaciones sobrantes.** Si se pasan más de 3, las extra deben estar sobre el polinomio de las primeras 3. Consecuencia para el orquestador (§6.6, "tolerancia ante participaciones no válidas"): si pasa **todas** las participaciones que superaron `validate_share` y una fue alterada con checksum recalculado, recibirá `InconsistentSharesError` en vez de una clave incorrecta. Si se quiere tolerar eso, puede reintentar con los subconjuntos de 3 (máximo 10) y quedarse con el que verifique AEAD. Pasar exactamente 3 no activa esta comprobación.
5. **Sin borrado de memoria del secreto.** Con enteros nativos de Python no se pueden sobrescribir los coeficientes ni el secreto intermedio; solo se reduce su vida útil. El orquestador debe envolver el resultado en `bytearray` y borrarlo con `crypto_core.wipe()` (mejor esfuerzo, igual que en el módulo de la persona A).
6. **Tiempo no constante.** La aritmética de enteros de Python no es de tiempo constante; fuera del modelo de adversario del Entregable 1 (§2), pero es otra razón para no reutilizar este código con otros fines.
7. **Límite de 255 participaciones** por el índice de 1 byte (el proyecto usa 5).

## 7. Uso desde el orquestador

```python
import crypto_core as cc
from shamir import split_secret, reconstruct_secret, ShamirError

# Crear (A -> B -> C)
key = cc.generate_key()                      # bytearray de 32 B
blob = cc.encrypt_blob(key, payload, backup_uuid.bytes)
shares = split_secret(bytes(key), 3, 5)      # [(1, 66 B), ..., (5, 66 B)]
cc.wipe(key)
# luego formats.make_share(backup_id, i, value) por cada (i, value)

# Restaurar (C -> B -> A), solo con participaciones que pasaron validate_share
try:
    key = bytearray(reconstruct_secret([(s.index, s.value) for s in valid], 3))
except ShamirError:
    ...  # mismo mensaje genérico que un fallo de autenticación
try:
    payload = cc.decrypt_blob(key, blob, backup_uuid.bytes)
finally:
    cc.wipe(key)
```

Para la persona C: `value` son siempre 66 bytes (big-endian, ancho fijo, < p) e `index` está en 1..5.

## 8. Pruebas

| Caso del plan | Test |
|---|---|
| U1 roundtrip con 3 shares | `test_U1_roundtrip_con_exactamente_3` |
| U2 las 10 combinaciones | `test_U2_las_10_combinaciones_de_3_de_5` |
| U3 solo 2 shares → `ValueError` | `test_U3_dos_participaciones_no_alcanzan` |
| U4 K = 0 | `test_U4_secreto_cero` |
| U5 K = 2^256 − 1 | `test_U5_secreto_maximo_de_256_bits` |
| U6 índice 0 → `ValueError` | `test_U6_indice_cero_o_fuera_de_rango` |
| U7 índice repetido | `test_U7_*` |
| U8 "no revela nada" | `test_U8_*`, chi-cuadrado |
| U9 1000 ejecuciones | `test_U9_1000_roundtrips_...` |
| U10 tiempos | `experiments/bench_shamir.py` |

Adicionales: constantes del esquema (p, 66 B, `sharing_scheme`), inverso de Fermat, valores ≥ p o de longitud ≠ 66, ceros a la izquierda, muestreo con rechazo, otros `t`-de-`n` (hasta 3-de-255), tipos de entrada, alteración y mezcla de respaldos, y una prueba de integración con `crypto_core` (se omite si el módulo no está).

Ejecutar: `python -m pytest tests/test_shamir.py`.
