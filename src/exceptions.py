"""
Excepciones propias del componente de cifrado de envolvente.

Se definen excepciones específicas en lugar de usar solo ValueError genérico
en todos los casos, para que el orquestador pueda distinguir,
programáticamente, entre un error de formato/tamaño y un fallo de
autenticidad — sin que el MENSAJE que ve el usuario final revele cuál de las
causas de un fallo de autenticidad ocurrió (ver Sección 6 del Entregable 1:
"Mensajes de error no diferenciados").
"""


class EnvelopeError(Exception):
    """Clase base para todos los errores de este componente."""


class InvalidBlobFormatError(EnvelopeError, ValueError):
    """
    El blob no tiene un formato reconocible: MAGIC incorrecto, o el blob
    está truncado (menos de 18 bytes de encabezado fijo).

    Hereda también de ValueError para mantener compatibilidad con el plan
    de pruebas, que espera ValueError en estos casos.
    """


class AuthenticationError(EnvelopeError):
    """
    La verificación de autenticidad (tag de Poly1305) falló.

    Se lanza de forma IDÉNTICA sin importar si la causa real fue:
      - clave incorrecta,
      - backup_id incorrecto (AAD no coincide),
      - ciphertext, nonce o encabezado alterados,
      - reordenamiento de bytes del ciphertext.

    Esto es intencional: no se debe filtrar al llamador cuál de estas
    causas ocurrió (Sección 6 del Entregable 1).
    """


class PayloadTooLargeError(EnvelopeError, ValueError):
    """
    El contenido a respaldar excede el límite permitido, ya sea en el
    chequeo preliminar (tamaño en disco) o en el chequeo autoritativo
    (tamaño del payload ya empaquetado).

    Hereda también de ValueError por la misma razón que
    InvalidBlobFormatError.
    """