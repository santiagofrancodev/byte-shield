#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         TLS SCANNER — Operación Defensa Web                      ║
║         CloudLabs Learning × Talento Tech Hackathon              ║
║         Autor: Senior Backend Engineer / Security Researcher     ║
║         Enfoque: Ciberseguridad DEFENSIVA — Análisis de Config   ║
╚══════════════════════════════════════════════════════════════════╝

Uso:
    python3 tls_scanner.py --target 172.18.0.2
    python3 tls_scanner.py --target 172.18.0.2 --ports 443 8443
    python3 tls_scanner.py --target 172.18.0.2 --output reporte.json
    python3 tls_scanner.py --targets lista.txt --output reporte.json
"""

import ssl
import socket
import json
import argparse
import sys
import datetime
import warnings
from typing import Optional

# Silenciar DeprecationWarnings de ssl en Python 3.12+
# (las constantes siguen funcionando; el warning es solo informativo)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ──────────────────────────────────────────────────────────────────
# CONSTANTES DE COLOR (ANSI — compatibles con Kali Linux / bash)
# ──────────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ──────────────────────────────────────────────────────────────────
# CONFIGURACIÓN DE PROTOCOLOS TLS A AUDITAR
# ──────────────────────────────────────────────────────────────────
TLS_PROTOCOLS = [
    # (nombre_display, atributo_ssl, versión_obsoleta)
    ("TLS 1.0", "PROTOCOL_TLSv1",   True),
    ("TLS 1.1", "PROTOCOL_TLSv1_1", True),
    ("TLS 1.2", "PROTOCOL_TLSv1_2", False),
    ("TLS 1.3", "PROTOCOL_TLS",     False),   # TLS 1.3 se negocia vía PROTOCOL_TLS
]

DEFAULT_PORTS    = [80, 443, 8080, 8443]
CONNECT_TIMEOUT  = 5   # segundos para socket / TLS handshake


# ══════════════════════════════════════════════════════════════════
# MÓDULO 1 — INGESTA Y VALIDACIÓN
# ══════════════════════════════════════════════════════════════════

def validar_objetivo(objetivo: str) -> str:
    """Valida que el objetivo sea un hostname o IP básicamente correcto."""
    objetivo = objetivo.strip()
    if not objetivo:
        raise ValueError("El objetivo no puede estar vacío.")
    # Intento de resolución DNS básica
    try:
        socket.getaddrinfo(objetivo, None)
    except socket.gaierror:
        raise ValueError(f"No se pudo resolver el objetivo: '{objetivo}'")
    return objetivo


def cargar_targets(target: Optional[str], targets_file: Optional[str]) -> list[str]:
    """Devuelve la lista de hosts a analizar."""
    targets = []
    if target:
        targets.append(target)
    if targets_file:
        try:
            with open(targets_file) as fh:
                for linea in fh:
                    linea = linea.strip()
                    if linea and not linea.startswith("#"):
                        targets.append(linea)
        except FileNotFoundError:
            print(f"{RED}[!] Archivo no encontrado: {targets_file}{RESET}")
            sys.exit(1)
    if not targets:
        print(f"{RED}[!] Debes indicar al menos un objetivo (--target o --targets).{RESET}")
        sys.exit(1)
    return targets


# ══════════════════════════════════════════════════════════════════
# MÓDULO 2 — ESCANEO DE PUERTOS (socket puro)
# ══════════════════════════════════════════════════════════════════

def escanear_puerto(host: str, puerto: int, timeout: int = CONNECT_TIMEOUT) -> bool:
    """Devuelve True si el puerto TCP está abierto."""
    try:
        with socket.create_connection((host, puerto), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def escanear_puertos(host: str, puertos: list[int]) -> list[int]:
    """Retorna la lista de puertos abiertos."""
    abiertos = []
    for p in puertos:
        estado = escanear_puerto(host, p)
        icono  = f"{GREEN}ABIERTO{RESET}" if estado else f"{RED}CERRADO{RESET}"
        print(f"  Puerto {WHITE}{p:5d}{RESET}/TCP  →  {icono}")
        if estado:
            abiertos.append(p)
    return abiertos


# ══════════════════════════════════════════════════════════════════
# MÓDULO 3 — MOTOR DE ANÁLISIS TLS
# ══════════════════════════════════════════════════════════════════

def probar_protocolo_tls(host: str, puerto: int,
                         protocolo_attr: str,
                         forzar_version: Optional[str] = None,
                         timeout: int = CONNECT_TIMEOUT) -> bool:
    """
    Intenta un handshake TLS usando el protocolo indicado.
    Para TLS 1.3 usamos PROTOCOL_TLS con minimum_version / maximum_version.
    """
    try:
        ctx = ssl.SSLContext(getattr(ssl, protocolo_attr))
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        # Control fino de versión para TLS 1.3
        if forzar_version == "TLS1_3":
            if hasattr(ssl, "TLSVersion"):
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            else:
                # Python < 3.7 sin soporte TLSVersion
                return False

        with socket.create_connection((host, puerto), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True

    except ssl.SSLError:
        return False
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    except AttributeError:
        # El atributo del protocolo no existe en esta versión de OpenSSL
        return False


def auditar_tls_en_puerto(host: str, puerto: int) -> dict:
    """
    Ejecuta la auditoría TLS completa sobre un puerto y devuelve
    un dict con los resultados por protocolo.
    """
    resultados = {}

    for nombre, attr, obsoleto in TLS_PROTOCOLS:
        if nombre == "TLS 1.3":
            habilitado = probar_protocolo_tls(host, puerto, attr,
                                              forzar_version="TLS1_3")
        else:
            # Para versiones legacy, primero verificamos que el atributo exista
            if not hasattr(ssl, attr):
                habilitado = False
            else:
                habilitado = probar_protocolo_tls(host, puerto, attr)

        resultados[nombre] = {
            "habilitado": habilitado,
            "obsoleto":   obsoleto,
        }

    return resultados


# ══════════════════════════════════════════════════════════════════
# MÓDULO 4 — MOTOR DE EVALUACIÓN Y CRITICIDAD
# ══════════════════════════════════════════════════════════════════

# Niveles: CRITICO > MEDIO > SEGURO
NIVEL_CRITICO = "CRÍTICO"
NIVEL_MEDIO   = "MEDIO"
NIVEL_SEGURO  = "SEGURO"

def calcular_criticidad(resultados_tls: dict) -> tuple[str, list[str], list[str]]:
    """
    Aplica la lógica de criticidad del reto:
      - CRÍTICO : acepta TLS 1.0 o TLS 1.1
      - MEDIO   : acepta TLS 1.2 pero NO tiene TLS 1.3
      - SEGURO  : TLS 1.3 activo y sin versiones obsoletas

    Retorna (nivel, hallazgos[], recomendaciones[])
    """
    tls10   = resultados_tls.get("TLS 1.0", {}).get("habilitado", False)
    tls11   = resultados_tls.get("TLS 1.1", {}).get("habilitado", False)
    tls12   = resultados_tls.get("TLS 1.2", {}).get("habilitado", False)
    tls13   = resultados_tls.get("TLS 1.3", {}).get("habilitado", False)

    hallazgos       = []
    recomendaciones = []

    # ── Detectar hallazgos ──────────────────────────────────────
    if tls10:
        hallazgos.append("TLS 1.0 habilitado — protocolo obsoleto desde 2018 (RFC 8996).")
        recomendaciones.append("Deshabilitar TLS 1.0 en la configuración del servidor "
                               "(nginx: ssl_protocols TLSv1.2 TLSv1.3;).")
    if tls11:
        hallazgos.append("TLS 1.1 habilitado — deprecado formalmente (RFC 8996).")
        recomendaciones.append("Deshabilitar TLS 1.1 para evitar ataques de degradación "
                               "criptográfica (POODLE, BEAST).")
    if tls12 and not tls13:
        hallazgos.append("TLS 1.2 activo pero TLS 1.3 ausente — configuración subóptima.")
        recomendaciones.append("Habilitar TLS 1.3 para cifrado con Perfect Forward Secrecy "
                               "y handshake más rápido.")
    if not tls12 and not tls13:
        hallazgos.append("Ni TLS 1.2 ni TLS 1.3 detectados — posible fallo de handshake "
                         "o servicio no TLS en este puerto.")
        recomendaciones.append("Verificar si el puerto sirve TLS o ajustar la configuración "
                               "para soportar al menos TLS 1.2.")

    # ── Asignar nivel ───────────────────────────────────────────
    if tls10 or tls11:
        nivel = NIVEL_CRITICO
    elif tls12 and not tls13:
        nivel = NIVEL_MEDIO
    elif tls13:
        nivel = NIVEL_SEGURO
        if not hallazgos:
            hallazgos.append("TLS 1.3 implementado. Sin protocolos obsoletos detectados.")
            recomendaciones.append("Mantener configuración actual y revisar periódicamente "
                                   "los cipher suites activos.")
    else:
        nivel = NIVEL_MEDIO  # incertidumbre

    return nivel, hallazgos, recomendaciones


# ══════════════════════════════════════════════════════════════════
# MÓDULO 5 — OUTPUT ESTÁNDAR EN CONSOLA (formato del reto)
# ══════════════════════════════════════════════════════════════════

COLOR_NIVEL = {
    NIVEL_CRITICO: RED,
    NIVEL_MEDIO:   YELLOW,
    NIVEL_SEGURO:  GREEN,
}

def estado_tls(habilitado: bool) -> str:
    if habilitado:
        return f"{RED}[ ENABLED ]{RESET}"
    return f"{GREEN}[ DISABLED ]{RESET}"


def imprimir_banner():
    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  TLS SCANNER — Operación Defensa Web{RESET}")
    print(f"{CYAN}  CloudLabs Learning × Talento Tech{RESET}")
    print(f"{CYAN}{'═'*60}{RESET}\n")


def imprimir_resultado_host(host: str, puerto: int,
                             resultados_tls: dict,
                             nivel: str,
                             hallazgos: list[str],
                             recomendaciones: list[str]):
    color_nivel = COLOR_NIVEL.get(nivel, WHITE)
    print(f"\n{BOLD}{WHITE}{'─'*60}{RESET}")
    print(f"{BOLD}{GREEN}[+] Iniciando auditoría para: {WHITE}{host}:{puerto}{RESET}")
    print(f"{BOLD}{WHITE}{'─'*60}{RESET}")

    print(f"\n{BOLD}[RESULTADOS DE PROTOCOLO]{RESET}")
    for nombre in ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]:
        info       = resultados_tls.get(nombre, {})
        habilitado = info.get("habilitado", False)
        print(f"  {WHITE}{nombre}:{RESET}  {estado_tls(habilitado)}")

    print(f"\n{BOLD}[ANÁLISIS DE RIESGO]{RESET}")
    print(f"  Nivel de criticidad:  {color_nivel}{BOLD}{nivel}{RESET}")
    for h in hallazgos:
        print(f"  {YELLOW}Riesgo:{RESET}         {h}")
    for r in recomendaciones:
        print(f"  {CYAN}Recomendación:{RESET}  {r}")


def imprimir_resumen(todos_resultados: list[dict]):
    """Vista consolidada comparativa cuando hay múltiples hosts/puertos."""
    if len(todos_resultados) <= 1:
        return

    print(f"\n{BOLD}{WHITE}{'═'*60}{RESET}")
    print(f"{BOLD}[VISTA CONSOLIDADA — COMPARATIVA]{RESET}")
    print(f"{'─'*60}")
    header = f"  {'HOST:PUERTO':<30} {'NIVEL':<10} {'TLS1.0':^8} {'TLS1.1':^8} {'TLS1.2':^8} {'TLS1.3':^8}"
    print(header)
    print(f"{'─'*60}")

    for r in todos_resultados:
        host    = f"{r['host']}:{r['puerto']}"
        nivel   = r['nivel']
        color   = COLOR_NIVEL.get(nivel, WHITE)
        tls10   = "SI" if r['tls'].get("TLS 1.0", {}).get("habilitado") else "no"
        tls11   = "SI" if r['tls'].get("TLS 1.1", {}).get("habilitado") else "no"
        tls12   = "SI" if r['tls'].get("TLS 1.2", {}).get("habilitado") else "no"
        tls13   = "SI" if r['tls'].get("TLS 1.3", {}).get("habilitado") else "no"
        print(f"  {host:<30} {color}{nivel:<10}{RESET} {tls10:^8} {tls11:^8} {tls12:^8} {tls13:^8}")

    print(f"{'─'*60}\n")


# ══════════════════════════════════════════════════════════════════
# MÓDULO 6 — EXPORTACIÓN A JSON
# ══════════════════════════════════════════════════════════════════

def exportar_json(todos_resultados: list[dict], ruta_salida: str):
    reporte = {
        "generado_en": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "herramienta": "tls_scanner.py — CloudLabs Hackathon",
        "resultados":  todos_resultados,
    }
    # Limpiamos los campos internos no serializables antes de guardar
    for r in reporte["resultados"]:
        r.pop("_raw", None)

    with open(ruta_salida, "w", encoding="utf-8") as fh:
        json.dump(reporte, fh, indent=2, ensure_ascii=False)
    print(f"\n{GREEN}[✓] Reporte exportado → {ruta_salida}{RESET}")


# ══════════════════════════════════════════════════════════════════
# ORQUESTADOR PRINCIPAL
# ══════════════════════════════════════════════════════════════════

def auditar_host(host: str, puertos: list[int]) -> list[dict]:
    """
    Ejecuta el pipeline completo para un host dado:
      INGESTA → PUERTOS → TLS → CRITICIDAD → OUTPUT
    """
    resultados_host = []

    # Validación del objetivo
    try:
        host = validar_objetivo(host)
    except ValueError as e:
        print(f"{RED}[!] {e}{RESET}")
        return []

    print(f"\n{BOLD}{CYAN}[*] Objetivo: {host}{RESET}")
    print(f"{CYAN}[*] Escaneando puertos: {puertos}{RESET}")

    puertos_abiertos = escanear_puertos(host, puertos)

    if not puertos_abiertos:
        print(f"{YELLOW}[!] No se encontraron puertos abiertos en {host}.{RESET}")
        return []

    for puerto in puertos_abiertos:
        print(f"\n{CYAN}[*] Auditando TLS en {host}:{puerto} ...{RESET}")
        resultados_tls = auditar_tls_en_puerto(host, puerto)
        nivel, hallazgos, recomendaciones = calcular_criticidad(resultados_tls)

        imprimir_resultado_host(host, puerto, resultados_tls,
                                nivel, hallazgos, recomendaciones)

        resultados_host.append({
            "host":            host,
            "puerto":          puerto,
            "nivel":           nivel,
            "tls":             resultados_tls,
            "hallazgos":       hallazgos,
            "recomendaciones": recomendaciones,
            "timestamp":       datetime.datetime.now(datetime.timezone.utc).isoformat(),
        })

    return resultados_host


def main():
    parser = argparse.ArgumentParser(
        description="TLS Scanner — Análisis defensivo de configuración TLS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 tls_scanner.py --target 172.18.0.2
  python3 tls_scanner.py --target api.example.com --ports 443 8443
  python3 tls_scanner.py --targets lista.txt --output reporte.json
        """,
    )
    parser.add_argument("--target",  metavar="HOST",    help="Host o IP a analizar")
    parser.add_argument("--targets", metavar="ARCHIVO", help="Archivo con lista de hosts (uno por línea)")
    parser.add_argument("--ports",   metavar="P", nargs="+", type=int,
                        default=DEFAULT_PORTS, help="Puertos a escanear (default: 80 443 8080 8443)")
    parser.add_argument("--output",  metavar="ARCHIVO", help="Exportar reporte en JSON")
    parser.add_argument("--timeout", metavar="SEG", type=int, default=CONNECT_TIMEOUT,
                        help=f"Timeout de conexión en segundos (default: {CONNECT_TIMEOUT})")

    args = parser.parse_args()

    imprimir_banner()

    hosts = cargar_targets(args.target, args.targets)

    todos_resultados = []
    for host in hosts:
        resultados = auditar_host(host, args.ports)
        todos_resultados.extend(resultados)

    imprimir_resumen(todos_resultados)

    if args.output:
        exportar_json(todos_resultados, args.output)

    # Exit code útil para integración CI/CD
    niveles = [r["nivel"] for r in todos_resultados]
    if NIVEL_CRITICO in niveles:
        sys.exit(2)   # Hallazgos críticos
    elif NIVEL_MEDIO in niveles:
        sys.exit(1)   # Hallazgos medios
    sys.exit(0)       # Todo OK


if __name__ == "__main__":
    main()
