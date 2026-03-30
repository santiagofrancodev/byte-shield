"""Salida consola, colores opcionales y exportación JSON."""

from __future__ import annotations

import datetime
import json
import logging
from typing import Any

from byteshield.motor_reglas import NIVEL_CRITICO, NIVEL_MEDIO, NIVEL_SEGURO

log = logging.getLogger("byteshield.reporting")

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
RESET = "\033[0m"

COLOR_NIVEL = {
    NIVEL_CRITICO: RED,
    NIVEL_MEDIO: YELLOW,
    NIVEL_SEGURO: GREEN,
}


def estado_tls(habilitado: bool) -> str:
    if habilitado:
        return f"{RED}[ ENABLED ]{RESET}"
    return f"{GREEN}[ DISABLED ]{RESET}"


def imprimir_banner() -> None:
    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  TLS SCANNER — Operación Defensa Web{RESET}")
    print(f"{CYAN}  CloudLabs Learning × Talento Tech{RESET}")
    print(f"{CYAN}{'═'*60}{RESET}\n")


def imprimir_resultado_host(
    host: str,
    puerto: int,
    resultados_tls: dict[str, Any],
    nivel: str,
    hallazgos: list[str],
    recomendaciones: list[str],
) -> None:
    color_nivel = COLOR_NIVEL.get(nivel, WHITE)
    print(f"\n{BOLD}{WHITE}{'─'*60}{RESET}")
    print(f"{BOLD}{GREEN}[+] Iniciando auditoría para: {WHITE}{host}:{puerto}{RESET}")
    print(f"{BOLD}{WHITE}{'─'*60}{RESET}")

    print(f"\n{BOLD}[RESULTADOS DE PROTOCOLO]{RESET}")
    for nombre in ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]:
        info = resultados_tls.get(nombre, {})
        habilitado = info.get("habilitado", False)
        print(f"  {WHITE}{nombre}:{RESET}  {estado_tls(habilitado)}")

    print(f"\n{BOLD}[ANÁLISIS DE RIESGO]{RESET}")
    print(f"  Nivel de criticidad:  {color_nivel}{BOLD}{nivel}{RESET}")
    for h in hallazgos:
        print(f"  {YELLOW}Riesgo:{RESET}         {h}")
    for r in recomendaciones:
        print(f"  {CYAN}Recomendación:{RESET}  {r}")


def imprimir_resumen(todos_resultados: list[dict[str, Any]]) -> None:
    if len(todos_resultados) <= 1:
        return

    print(f"\n{BOLD}{WHITE}{'═'*60}{RESET}")
    print(f"{BOLD}[VISTA CONSOLIDADA — COMPARATIVA]{RESET}")
    print(f"{'─'*60}")
    header = f"  {'HOST:PUERTO':<30} {'NIVEL':<10} {'TLS1.0':^8} {'TLS1.1':^8} {'TLS1.2':^8} {'TLS1.3':^8}"
    print(header)
    print(f"{'─'*60}")

    for r in todos_resultados:
        host = f"{r['host']}:{r['puerto']}"
        nivel = r["nivel"]
        color = COLOR_NIVEL.get(nivel, WHITE)
        tls10 = "SI" if r["tls"].get("TLS 1.0", {}).get("habilitado") else "no"
        tls11 = "SI" if r["tls"].get("TLS 1.1", {}).get("habilitado") else "no"
        tls12 = "SI" if r["tls"].get("TLS 1.2", {}).get("habilitado") else "no"
        tls13 = "SI" if r["tls"].get("TLS 1.3", {}).get("habilitado") else "no"
        print(
            f"  {host:<30} {color}{nivel:<10}{RESET} {tls10:^8} {tls11:^8} {tls12:^8} {tls13:^8}"
        )

    print(f"{'─'*60}\n")


def exportar_json(todos_resultados: list[dict[str, Any]], ruta_salida: str) -> None:
    reporte = {
        "generado_en": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "herramienta": "Byte-Shield (tls_scanner) — CloudLabs Hackathon",
        "resultados": todos_resultados,
    }
    for r in reporte["resultados"]:
        r.pop("_raw", None)

    with open(ruta_salida, "w", encoding="utf-8") as fh:
        json.dump(reporte, fh, indent=2, ensure_ascii=False)
    log.info("Reporte exportado → %s", ruta_salida)
    print(f"\n{GREEN}[✓] Reporte exportado → {ruta_salida}{RESET}")
