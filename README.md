# Respaldo cifrado con recuperación 3-de-5

Proyecto 3 de Criptografía Aplicada. Un archivo o directorio se cifra con **ChaCha20-Poly1305** usando una clave aleatoria de 256 bits, y esa clave se reparte con **Shamir 3-de-5** entre cinco custodios. Con 3 participaciones cualesquiera se restaura el respaldo; con 2 no se obtiene información sobre la clave.

## Requisitos

- Python 3.10 o superior (se recomienda 3.12, que incluye el filtro `data` de `tarfile`).
- Dependencias fijadas en `requirements.txt`: `cryptography==50.0.2` y `pytest==9.2.0` (con estas versiones se ejecutaron todas las pruebas y experimentos).

```bash
python -m venv venv
```

```bash
venv\Scripts\activate          # Windows
source venv/bin/activate       # Linux / macOS
```

```bash
pip install -r requirements.txt
```

## Uso

```bash
python src/cli.py crear mis_documentos -o respaldo
```

Genera en `respaldo/` el paquete cifrado (`<id>.evlp`), el manifiesto (`<id>.manifest.json`) y cinco participaciones (`<id>.share1.json` … `<id>.share5.json`). Cada participación se entrega a un custodio distinto.

Para restaurar, se reúnen al menos 3 participaciones en la carpeta donde están el paquete y el manifiesto:

```bash
python src/cli.py restaurar respaldo/<id>.share1.json respaldo/<id>.share3.json respaldo/<id>.share5.json -o restaurado
```

Para ver los metadatos de un archivo sin revelar ningún secreto:

```bash
python src/cli.py inspeccionar respaldo/<id>.share2.json
```

Con varias participaciones, el inspector además avisa si hay índices repetidos o participaciones de otro respaldo, y dice si alcanzan para restaurar:

```bash
python src/cli.py inspeccionar respaldo/<id>.share1.json respaldo/<id>.share2.json otra_carpeta/<otro_id>.share3.json
```

## Demostración

```bash
python demo/demo.py
```

Reparte las participaciones entre 5 custodios simulados y prueba las 10 combinaciones de 3, solo 2 custodios, una participación repetida, una dañada, una de otro respaldo, un paquete manipulado y la revisión de un grupo con el inspector. Los archivos quedan en `demo/salida_demo/`.

## Pruebas y experimentos

```bash
python -m pytest -q
```

Las pruebas lentas (~200 MB) se activan con la variable `EVLP_SLOW_TESTS=1`. Los experimentos están en `experiments/` y sus resultados en `experiments/results/`.

## Estructura

| Ruta | Responsable | Contenido |
|---|---|---|
| `src/crypto_core.py`, `src/packaging_.py`, `src/exceptions.py` | Persona A | Cifrado AEAD y empaquetado tar+gzip |
| `src/shamir.py` | Persona B | Shamir 3-de-5 sobre Z_p, p = 2^521 − 1 |
| `src/formats.py` | Persona C | Manifiesto, participaciones, paquete y checksums |
| `src/orchestrator.py`, `src/cli.py` | Persona D | Flujo completo, CLI e inspector |
| `tests/` | Todos | Pruebas unitarias y de integración |
| `demo/demo.py` | Persona D | Guion de demostración |
| `docs/` | Todos | Documentación de cada módulo |

Más detalle en `docs/cifrado_envolvente.md`, `docs/shamir.md`, `docs/formatos.md` y `docs/orquestacion.md`.