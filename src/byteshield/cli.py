"""CLI — punto de entrada ``python -m byteshield.cli``."""

from __future__ import annotations

import argparse
import sys
from typing import Any

from byteshield.ingesta import cargar_targets
from byteshield.motor_reglas import NIVEL_CRITICO, NIVEL_MEDIO
from byteshield.motor_tls import CONNECT_TIMEOUT, DEFAULT_PORTS
from byteshield.pipeline import run_scan
from byteshield.reporting import exportar_json, imprimir_banner, imprimir_resumen
from byteshield.utils import setup_logging


def main(argv: list[str] | None = None) -> None:
    setup_logging()
    parser = argparse.ArgumentParser(
        description="TLS Scanner — Análisis defensivo de configuración TLS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python -m byteshield.cli --target 172.18.0.2
  python -m byteshield.cli --target api.example.com --ports 443 8443
  python -m byteshield.cli --targets lista.txt --output reporte.json
        """,
    )
    parser.add_argument("--target", metavar="HOST", help="Host o IP a analizar")
    parser.add_argument("--targets", metavar="ARCHIVO", help="Archivo con lista de hosts")
    parser.add_argument(
        "--ports",
        metavar="P",
        nargs="+",
        type=int,
        default=DEFAULT_PORTS,
        help="Puertos a escanear (default: 80 443 8080 8443)",
    )
    parser.add_argument("--output", metavar="ARCHIVO", help="Exportar reporte en JSON")
    parser.add_argument(
        "--timeout",
        metavar="SEG",
        type=int,
        default=CONNECT_TIMEOUT,
        help=f"Timeout de conexión en segundos (default: {CONNECT_TIMEOUT})",
    )
    parser.add_argument(
        "--trigger",
        default="comando_manual",
        help="Disparador lógico (comando_manual, cicd_hook, cron_schedule, webhook_evento)",
    )
    parser.add_argument(
        "--deps",
        action="store_true",
        help="Forzar mapeo de dependencias (SANs + crt.sh) según política",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Sin salida coloreada de progreso (solo errores mínimos)",
    )

    args = parser.parse_args(argv)

    if not args.quiet:
        imprimir_banner()

    try:
        hosts = cargar_targets(args.target, args.targets, strict=True)
    except (FileNotFoundError, ValueError) as e:
        from byteshield.reporting import RED, RESET

        print(f"{RED}[!] {e}{RESET}")
        sys.exit(1)

    flags: dict[str, Any] = {"deps": bool(args.deps)}

    todos_resultados = run_scan(
        hosts,
        args.ports,
        verbose=not args.quiet,
        connect_timeout=args.timeout,
        trigger=args.trigger,
        flags=flags,
        include_deps=True if args.deps else None,
    )

    if not args.quiet:
        imprimir_resumen(todos_resultados)

    if args.output:
        exportar_json(todos_resultados, args.output)

    niveles = [r["nivel"] for r in todos_resultados]
    if NIVEL_CRITICO in niveles:
        sys.exit(2)
    if NIVEL_MEDIO in niveles:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
