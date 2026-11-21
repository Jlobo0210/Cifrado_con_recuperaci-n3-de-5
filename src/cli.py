"""
cli.py — Interfaz de línea de comandos del respaldo 3-de-5 (Persona D).

Uso:
    python src/cli.py crear ORIGEN -o CARPETA_SALIDA
    python src/cli.py restaurar SHARE [SHARE ...] -o CARPETA_DESTINO
    python src/cli.py inspeccionar ARCHIVO [ARCHIVO ...]

Toda la lógica está en orchestrator.py; aquí solo se leen los argumentos,
se llama a la función correspondiente y se muestran los resultados. Los
errores se muestran como un mensaje de una línea, sin traceback.

Código de salida: 0 si todo salió bien, 1 si hubo un error.
"""

from __future__ import annotations

import argparse
import sys

import orchestrator
from exceptions import EnvelopeError


def cmd_crear(args: argparse.Namespace) -> None:
    backup_id = orchestrator.create_backup(args.origen, args.salida)
    print(f"Respaldo creado: {backup_id}")
    print(f"Archivos en: {args.salida}")
    print(f"  {backup_id}.evlp            (paquete cifrado)")
    print(f"  {backup_id}.manifest.json   (manifiesto)")
    for i in range(1, 6):
        print(f"  {backup_id}.share{i}.json     (participación del custodio {i})")
    print("Entregue cada participación a un custodio distinto. Con 3 de ellas se puede restaurar.")


def cmd_restaurar(args: argparse.Namespace) -> None:
    try:
        rejected = orchestrator.restore_backup(args.shares, args.destino)
    except orchestrator.NotEnoughSharesError as exc:
        _print_rejected(exc.rejected, sys.stderr)
        raise
    _print_rejected(rejected)
    print(f"Respaldo restaurado en: {args.destino}")


def cmd_inspeccionar(args: argparse.Namespace) -> int:
    errores = 0
    for i, path in enumerate(args.archivos):
        if i > 0:
            print()
        print(f"== {path}")
        try:
            info = orchestrator.inspect(path)
        except (ValueError, EnvelopeError, OSError) as exc:
            # Un archivo malo no detiene la revisión de los demás.
            print(f"  Error: {exc}")
            errores += 1
            continue
        for key, value in info.items():
            print(f"  {key}: {value}")

    # Con varios archivos, además se revisan las participaciones como grupo.
    if len(args.archivos) > 1:
        grupo = orchestrator.check_share_group(args.archivos)
        print()
        print("== Revisión del grupo de participaciones")
        for linea in grupo["resumen"]:
            print(f"  {linea}")
        for linea in grupo["advertencias"]:
            print(f"  ADVERTENCIA: {linea}")
        if not grupo["advertencias"]:
            print("  Sin advertencias.")
    return 1 if errores else 0


def _print_rejected(rejected: list[tuple[str, str]], file=None) -> None:
    for path, reason in rejected:
        print(f"Participación descartada ({reason}): {path}", file=file or sys.stdout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="Respaldo cifrado (ChaCha20-Poly1305) con recuperación 3-de-5 (Shamir).",
    )
    sub = parser.add_subparsers(dest="comando", required=True)

    p = sub.add_parser("crear", help="Cifra un archivo o directorio y genera 5 participaciones.")
    p.add_argument("origen", help="Archivo o directorio a respaldar.")
    p.add_argument("-o", "--salida", required=True, help="Carpeta donde se guardan los archivos del respaldo.")
    p.set_defaults(func=cmd_crear)

    p = sub.add_parser("restaurar", help="Restaura un respaldo con al menos 3 participaciones.")
    p.add_argument("shares", nargs="+", help="Archivos de participación (.share<i>.json).")
    p.add_argument("-o", "--destino", required=True, help="Carpeta donde se extrae el contenido.")
    p.set_defaults(func=cmd_restaurar)

    p = sub.add_parser(
        "inspeccionar",
        help="Muestra metadatos no secretos; con varias participaciones avisa de índices repetidos y mezclas.",
    )
    p.add_argument("archivos", nargs="+", help="Participaciones, manifiesto o paquete (.evlp).")
    p.set_defaults(func=cmd_inspeccionar)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        codigo = args.func(args)
    except (orchestrator.RestoreError, EnvelopeError, ValueError, OSError) as exc:
        # FormatError y los errores de shamir heredan de ValueError.
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return codigo or 0  # crear y restaurar no devuelven nada; inspeccionar sí


if __name__ == "__main__":
    sys.exit(main())