"""
shamir.py — Compartición de secretos de Shamir (umbral t-de-n) sobre Z_p.

Manejo en memoria: Python usa enteros inmutables, por lo que los
coeficientes y el secreto intermedio no se pueden sobrescribir. Se
minimiza su vida útil (variables locales) pero no se garantiza el borrado;
el orquestador debe envolver el resultado en un bytearray y borrarlo con
crypto_core.wipe().
"""

from __future__ import annotations

import os
from typing import Sequence

__all__ = [
    "ShamirError",
    "InvalidParametersError",
    "InvalidShareError",
    "InsufficientSharesError",
    "InconsistentSharesError",
    "split_secret",
    "reconstruct_secret",
    "P",
    "SECRET_SIZE",
    "SHARE_VALUE_SIZE",
    "MAX_SHARES",
    "MIN_THRESHOLD",
    "SHARING_SCHEME",
]

# --- Constantes --------------------------------------------------------------

P: int = (1 << 521) - 1  # primo de Mersenne 2^521 − 1
SECRET_SIZE: int = 32  # K: 256 bits
SHARE_VALUE_SIZE: int = (521 + 7) // 8  # 66 bytes, ancho fijo del valor f(i)
MAX_SHARES: int = 255  # el índice se guarda en 1 byte (el proyecto usa 1..5)
MIN_THRESHOLD: int = 2  # con t = 1 cada participación sería el secreto
SHARING_SCHEME: str = "shamir-zp-m521" 

_random_bytes = os.urandom

_BITMASK_521: int = (1 << 521) - 1


# --- Excepciones ------------------------------------------------------------

class ShamirError(ValueError):
    """Clase base para todos los errores de este módulo."""

class InvalidParametersError(ShamirError):
    """threshold / total_shares / secreto con valores o tipos inválidos."""

class InvalidShareError(ShamirError):
    """Participación mal formada: índice fuera de 1..255 (en particular 0),
    índice repetido, valor que no mide 66 bytes o que es >= p."""

class InsufficientSharesError(ShamirError):
    """Hay menos participaciones que el umbral: no se puede reconstruir."""

class InconsistentSharesError(ShamirError):
    """Las participaciones no corresponden a una clave válida: o bien hay más
    de `threshold` y no todas están sobre el mismo polinomio, o bien la
    clave reconstruida no cabe en 256 bits. En ambos casos al menos una
    participación está alterada o pertenece a otro respaldo."""


# --- Aritmética ------------------------------------------------------------------


def _random_zp() -> int:
    """Entero uniforme en Z_p por muestreo con rechazo sobre os.urandom."""
    while True:
        r = int.from_bytes(_random_bytes(SHARE_VALUE_SIZE), "big") & _BITMASK_521
        if r < P:  # solo se rechaza 2^521 − 1: probabilidad 2^-521
            return r


def _inv(a: int) -> int:
    """Inverso modular por Fermat (p primo): a^(p−2) mod p."""
    return pow(a, P - 2, P)


def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    """Horner mod p. coeffs[0] = K, coeffs[k] = coeficiente de x^k."""
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % P
    return acc


def _lagrange(points: Sequence[tuple[int, int]], at: int) -> int:
    """Valor en x = `at` del único polinomio de grado < len(points) que pasa
    por `points` (índices distintos). Con at = 0 devuelve el secreto."""
    total = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                num = (num * (at - xj)) % P
                den = (den * (xi - xj)) % P
        total = (total + yi * num * _inv(den)) % P
    return total


# --- Validación de entradas ----------------------------------------------------


def _check_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidParametersError(f"{name} debe ser un entero, se recibió {type(value).__name__}.")
    return value


def _validate_threshold(threshold: object) -> int:
    t = _check_int(threshold, "threshold")
    if t < MIN_THRESHOLD:
        raise InvalidParametersError(f"threshold debe ser >= {MIN_THRESHOLD} (se recibió {t}).")
    if t > MAX_SHARES:
        raise InvalidParametersError(f"threshold debe ser <= {MAX_SHARES} (se recibió {t}).")
    return t


def _parse_shares(shares: Sequence[tuple[int, bytes]]) -> list[tuple[int, int]]:
    """Valida cada participación y devuelve [(índice, valor como entero)]."""
    try:
        items = list(shares)
    except TypeError:
        raise InvalidShareError("shares debe ser una lista de pares (índice, valor).") from None

    parsed: list[tuple[int, int]] = []
    seen: set[int] = set()
    for pos, item in enumerate(items):
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise InvalidShareError(f"La participación #{pos + 1} no es un par (índice, valor).")
        index, value = item
        if isinstance(index, bool) or not isinstance(index, int):
            raise InvalidShareError(f"La participación #{pos + 1} tiene un índice que no es entero.")
        if not 1 <= index <= MAX_SHARES:
            raise InvalidShareError(
                f"La participación #{pos + 1} tiene índice {index}; debe estar entre 1 y {MAX_SHARES} (0 está prohibido)."
            )
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise InvalidShareError(f"La participación con índice {index} tiene un valor que no es bytes.")
        value = bytes(value)
        if len(value) != SHARE_VALUE_SIZE:
            raise InvalidShareError(
                f"La participación con índice {index} debe tener un valor de {SHARE_VALUE_SIZE} bytes (tiene {len(value)})."
            )
        y = int.from_bytes(value, "big")
        if y >= P:
            raise InvalidShareError(f"La participación con índice {index} tiene un valor fuera de Z_p (>= p).")
        if index in seen:
            raise InvalidShareError(f"El índice {index} aparece más de una vez: participación repetida.")
        seen.add(index)
        parsed.append((index, y))
    return parsed


# --- API pública -------------------------------------------------------------------


def split_secret(secret: bytes, threshold: int, total_shares: int) -> list[tuple[int, bytes]]:
    """Parte `secret` (K, exactamente 32 bytes) en `total_shares` participaciones.

    Devuelve [(1, v1), ..., (n, vn)]: índices 1..n (nunca 0, nunca repetidos)
    y valores de EXACTAMENTE 66 bytes (f(i) big-endian de ancho fijo).
    Con `threshold` participaciones cualesquiera se reconstruye K; con menos,
    no se obtiene información alguna sobre él (secreto perfecto).

    Lanza InvalidParametersError (es ValueError) si el secreto no es
    bytes-like de 32 bytes, si threshold/total_shares no son enteros o si no
    se cumple 2 <= threshold <= total_shares <= 255.
    """
    if not isinstance(secret, (bytes, bytearray, memoryview)):
        raise InvalidParametersError(f"secret debe ser bytes, bytearray o memoryview, se recibió {type(secret).__name__}.")
    secret_b = bytes(secret)
    if len(secret_b) != SECRET_SIZE:
        raise InvalidParametersError(f"El secreto debe medir exactamente {SECRET_SIZE} bytes (se recibieron {len(secret_b)}).")
    t = _validate_threshold(threshold)
    n = _check_int(total_shares, "total_shares")
    if n > MAX_SHARES:
        raise InvalidParametersError(f"total_shares debe ser <= {MAX_SHARES} (se recibió {n}).")
    if t > n:
        raise InvalidParametersError(f"threshold ({t}) no puede ser mayor que total_shares ({n}).")

    coeffs = [int.from_bytes(secret_b, "big")] + [_random_zp() for _ in range(t - 1)]
    return [(x, _eval_poly(coeffs, x).to_bytes(SHARE_VALUE_SIZE, "big")) for x in range(1, n + 1)]


def reconstruct_secret(shares: list[tuple[int, bytes]], threshold: int) -> bytes:
    """Reconstruye K (32 bytes) con >= `threshold` participaciones.

    Todos los errores heredan de ShamirError (que es ValueError):
        - InvalidParametersError: threshold inválido.
        - InvalidShareError: participación mal formada, índice 0 o fuera de
          1..255, índice repetido, valor que no mide 66 bytes o es >= p.
        - InsufficientSharesError: hay menos de `threshold` participaciones
          distintas. Falla de inmediato, sin interpolar.
        - InconsistentSharesError: (a) se entregaron MÁS de `threshold` y las
          sobrantes no están sobre el polinomio de las primeras `threshold`;
          o (b) el entero reconstruido no cabe en 256 bits, por lo que no
          puede ser una clave K.

    Con exactamente `threshold` participaciones alteradas pero que den un
    entero < 2^256 (probabilidad ~2^-265 si se alteran al azar) Shamir no lo
    puede notar: lo detecta después AEAD.
    """
    t = _validate_threshold(threshold)
    parsed = _parse_shares(shares)
    if len(parsed) < t:
        raise InsufficientSharesError(
            f"Se necesitan al menos {t} participaciones distintas y solo se recibieron {len(parsed)}."
        )

    base, extra = parsed[:t], parsed[t:]
    for x, y in extra:
        if _lagrange(base, x) != y:
            raise InconsistentSharesError(
                "Las participaciones no son consistentes entre sí: al menos una está alterada o pertenece a otro respaldo."
            )
    k = _lagrange(base, 0)
    if k >> (8 * SECRET_SIZE):
        raise InconsistentSharesError(
            "Las participaciones no producen una clave válida: al menos una está alterada o pertenece a otro respaldo."
        )
    return k.to_bytes(SECRET_SIZE, "big")
