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
import os
import argparse
import sys
import datetime
import warnings
import urllib.request
import urllib.error
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
# MÓDULO 4 — MOTOR DE EVALUACIÓN Y CUMPLIMIENTO (Compliance-as-Code)
# ══════════════════════════════════════════════════════════════════

# Niveles: CRITICO > MEDIO > SEGURO
NIVEL_CRITICO = "CRÍTICO"
NIVEL_MEDIO   = "MEDIO"
NIVEL_SEGURO  = "SEGURO"

NIVEL_PRIORIDAD: dict[str, int] = {
    NIVEL_SEGURO:  0,
    NIVEL_MEDIO:   1,
    NIVEL_CRITICO: 2,
}

# ──────────────────────────────────────────────────────────────────
# FUENTE DE VERDAD — Estándares de cumplimiento por protocolo TLS
# ──────────────────────────────────────────────────────────────────
ESTANDARES_CUMPLIMIENTO: dict[str, dict] = {
    "TLS 1.0": {
        "nivel": NIVEL_CRITICO,
        "fuente_oficial": "RFC 8996 (2021), NIST SP 800-52 Rev. 2",
        "motivo_tecnico": (
            "Protocolo obsoleto desde 2018. Vulnerable a ataques POODLE y BEAST "
            "por debilidades en CBC y falta de AEAD."
        ),
        "recomendacion_accionable": (
            "Deshabilitar TLS 1.0 en la configuración del servidor "
            "(nginx: ssl_protocols TLSv1.2 TLSv1.3;)."
        ),
    },
    "TLS 1.1": {
        "nivel": NIVEL_CRITICO,
        "fuente_oficial": "RFC 8996 (2021), NIST SP 800-52 Rev. 2",
        "motivo_tecnico": (
            "Deprecado formalmente. Susceptible a degradación criptográfica "
            "y carece de cipher suites AEAD modernos."
        ),
        "recomendacion_accionable": (
            "Deshabilitar TLS 1.1 para evitar ataques de degradación "
            "criptográfica (POODLE, BEAST)."
        ),
    },
    "TLS 1.2": {
        "nivel": NIVEL_SEGURO,
        "fuente_oficial": "RFC 5246, NIST SP 800-52 Rev. 2",
        "motivo_tecnico": (
            "Versión segura vigente. Requiere cipher suites modernos "
            "(ECDHE + AES-GCM / CHACHA20-POLY1305)."
        ),
        "recomendacion_accionable": (
            "Mantener habilitado. Validar que los cipher suites "
            "no incluyan RC4, DES, 3DES o NULL."
        ),
        "alerta_sin_tls13": {
            "nivel": NIVEL_MEDIO,
            "fuente_oficial": "NIST SP 800-52 Rev. 2",
            "motivo_tecnico": (
                "TLS 1.2 activo pero TLS 1.3 ausente — configuración subóptima. "
                "Se pierde handshake 0-RTT y PFS obligatorio."
            ),
            "recomendacion_accionable": (
                "Habilitar TLS 1.3 para cifrado con Perfect Forward Secrecy "
                "y handshake más rápido (1-RTT)."
            ),
        },
    },
    "TLS 1.3": {
        "nivel": NIVEL_SEGURO,
        "fuente_oficial": "RFC 8446 (2018), NIST SP 800-52 Rev. 2",
        "motivo_tecnico": (
            "Versión más segura disponible. PFS obligatorio, "
            "handshake 1-RTT, sin cipher suites legacy."
        ),
        "recomendacion_accionable": (
            "Mantener configuración actual y revisar periódicamente "
            "los cipher suites activos."
        ),
    },
}

# ──────────────────────────────────────────────────────────────────
# MOTOR HÍBRIDO — Enriquecimiento vía API con fallback local
# ──────────────────────────────────────────────────────────────────
API_ENRICHMENT_URL = "https://ciphersuite.info/api/cs/"
API_TIMEOUT = 2

_api_disponible: bool | None = None   # None = no testeada aún


def _verificar_disponibilidad_api() -> bool:
    """Hace un ping liviano a la API para cachear si está accesible."""
    global _api_disponible
    if _api_disponible is not None:
        return _api_disponible
    try:
        req = urllib.request.Request(
            API_ENRICHMENT_URL,
            method="GET",
            headers={"Accept": "application/json", "User-Agent": "ByteShield/1.0"},
        )
        urllib.request.urlopen(req, timeout=API_TIMEOUT)
        _api_disponible = True
    except (urllib.error.URLError, socket.timeout, OSError):
        _api_disponible = False
    return _api_disponible


def enriquecer_desde_api(protocolo: str) -> dict | None:
    """
    Consulta ciphersuite.info para enriquecer la evaluación de un protocolo.

    Retorna dict con metadatos adicionales o None en modo offline/air-gapped.
    Timeout estricto de 2s para no bloquear el pipeline.
    """
    if not _verificar_disponibilidad_api():
        return None

    version_map: dict[str, str] = {
        "TLS 1.0": "tls10",
        "TLS 1.1": "tls11",
        "TLS 1.2": "tls12",
        "TLS 1.3": "tls13",
    }
    slug = version_map.get(protocolo)
    if not slug:
        return None

    try:
        url = f"{API_ENRICHMENT_URL}?tls={slug}"
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"Accept": "application/json", "User-Agent": "ByteShield/1.0"},
        )
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        total = len(data.get("ciphersuites", []))
        insecure = sum(
            1 for cs in data.get("ciphersuites", [])
            if "insecure" in str(cs.get("security", "")).lower()
        )
        return {
            "fuente": "ciphersuite.info",
            "total_suites": total,
            "suites_inseguras": insecure,
        }
    except (urllib.error.URLError, socket.timeout, OSError,
            json.JSONDecodeError, KeyError):
        return None


# ──────────────────────────────────────────────────────────────────
# EVALUADOR DE CRITICIDAD (data-driven, desacoplado)
# ──────────────────────────────────────────────────────────────────

def _nivel_maximo(niveles: list[str]) -> str:
    """Retorna el nivel de mayor prioridad de la lista."""
    if not niveles:
        return NIVEL_MEDIO
    return max(niveles, key=lambda n: NIVEL_PRIORIDAD.get(n, 0))


def _formatear_hallazgo(protocolo: str, estandar: dict,
                        api_data: dict | None = None) -> str:
    """Genera string de hallazgo con referencia legal/técnica."""
    fuente = estandar["fuente_oficial"].split(",")[0].strip()
    if api_data:
        fuente = f"{fuente} + {api_data['fuente']}"
    texto = f"[{fuente}] {protocolo} habilitado — {estandar['motivo_tecnico']}"
    if api_data and api_data.get("suites_inseguras", 0) > 0:
        texto += (
            f" ({api_data['suites_inseguras']}/{api_data['total_suites']} "
            f"cipher suites marcadas como inseguras)"
        )
    return texto


def calcular_criticidad(resultados_tls: dict) -> tuple[str, list[str], list[str]]:
    """
    Motor de evaluación Compliance-as-Code.

    Cruza los resultados del escaneo TLS con ESTANDARES_CUMPLIMIENTO
    y opcionalmente enriquece con datos de ciphersuite.info (fallback
    offline si no hay red).

    Retorna (nivel, hallazgos[], recomendaciones[]) — firma preservada
    para compatibilidad con dashboard.py.
    """
    hallazgos:       list[str] = []
    recomendaciones: list[str] = []
    niveles_detectados: list[str] = []

    tls13_habilitado = resultados_tls.get("TLS 1.3", {}).get("habilitado", False)
    tls12_habilitado = resultados_tls.get("TLS 1.2", {}).get("habilitado", False)

    for protocolo, estandar in ESTANDARES_CUMPLIMIENTO.items():
        info = resultados_tls.get(protocolo, {})
        habilitado = info.get("habilitado", False)

        if not habilitado:
            continue

        nivel_estandar = estandar["nivel"]

        # Protocolos marcados como CRÍTICO por RFC 8996 → hallazgo automático
        if nivel_estandar == NIVEL_CRITICO:
            api_data = enriquecer_desde_api(protocolo)
            hallazgos.append(_formatear_hallazgo(protocolo, estandar, api_data))
            recomendaciones.append(estandar["recomendacion_accionable"])
            niveles_detectados.append(NIVEL_CRITICO)

        # TLS 1.2 presente pero sin TLS 1.3 → alerta MEDIO
        elif protocolo == "TLS 1.2" and not tls13_habilitado:
            alerta = estandar.get("alerta_sin_tls13", {})
            if alerta:
                fuente = alerta.get("fuente_oficial", estandar["fuente_oficial"])
                fuente_short = fuente.split(",")[0].strip()
                hallazgos.append(
                    f"[{fuente_short}] {alerta['motivo_tecnico']}"
                )
                recomendaciones.append(alerta["recomendacion_accionable"])
                niveles_detectados.append(alerta["nivel"])

    # Caso especial: ningún protocolo moderno detectado
    if not tls12_habilitado and not tls13_habilitado:
        hallazgos.append(
            "[NIST SP 800-52] Ni TLS 1.2 ni TLS 1.3 detectados — "
            "posible fallo de handshake o servicio no TLS en este puerto."
        )
        recomendaciones.append(
            "Verificar si el puerto sirve TLS o ajustar la configuración "
            "para soportar al menos TLS 1.2."
        )
        niveles_detectados.append(NIVEL_MEDIO)

    # Caso seguro: TLS 1.3 activo sin hallazgos
    if tls13_habilitado and not hallazgos:
        hallazgos.append(
            "[RFC 8446] TLS 1.3 implementado. Sin protocolos obsoletos detectados."
        )
        recomendaciones.append(
            ESTANDARES_CUMPLIMIENTO["TLS 1.3"]["recomendacion_accionable"]
        )
        niveles_detectados.append(NIVEL_SEGURO)

    nivel_final = _nivel_maximo(niveles_detectados)
    return nivel_final, hallazgos, recomendaciones


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
# MÓDULO 7 — ANÁLISIS CON IA (Gemini / OpenAI / Groq)
# ══════════════════════════════════════════════════════════════════
#
# Configuración via variables de entorno:
#   BYTESHIELD_AI_KEY       — API key del proveedor (requerida)
#   BYTESHIELD_AI_PROVIDER  — 'gemini' (default) | 'openai' | 'groq'
#
# Groq (https://console.groq.com): capa gratuita generosa para pruebas; API tipo OpenAI.

AI_TIMEOUT = 20   # segundos — APIs de IA son más lentas que ciphersuite.info
GROQ_MODEL_DEFAULT = "llama-3.3-70b-versatile"


def _build_prompt(resultados: list[dict]) -> str:
    """Construye el prompt estructurado con los hallazgos del escaneo."""
    lines = [
        "Eres un analista senior de ciberseguridad defensiva. "
        "Analiza los siguientes hallazgos de auditoría TLS y genera un reporte ejecutivo "
        "conciso (máximo 300 palabras) con tres secciones claramente delimitadas:\n"
        "1. RESUMEN EJECUTIVO — impacto de negocio para el CISO.\n"
        "2. RIESGOS PRIORIZADOS — listado por criticidad.\n"
        "3. PLAN DE ACCIÓN INMEDIATO — pasos concretos para remediar.\n"
        "Responde directamente sin preámbulos ni agradecimientos.",
        "",
        "HALLAZGOS DE AUDITORÍA TLS:",
    ]
    for r in resultados:
        lines.append(f"\nServidor: {r['host']}:{r['puerto']}  |  Nivel: {r['nivel']}")
        for h in r.get("hallazgos", []):
            lines.append(f"  - {h}")
        if r.get("recomendaciones"):
            lines.append("  Recomendaciones actuales:")
            for rec in r.get("recomendaciones", []):
                lines.append(f"    > {rec}")
    return "\n".join(lines)


def _friendly_http_error_ia(e: urllib.error.HTTPError, provider: str) -> str:
    """Mensaje legible para la UI; evita volcar JSON largo de proveedores."""
    code = e.code
    try:
        raw = e.read().decode("utf-8", errors="replace")
    except Exception:
        raw = ""
    if code == 429:
        if provider == "gemini":
            return (
                "Cuota o límite de solicitudes de Gemini agotado (HTTP 429). "
                "Revisa el plan en Google AI Studio, espera al reinicio de cuota, "
                "o usa pruebas gratuitas: BYTESHIELD_AI_PROVIDER=groq y una clave en "
                "https://console.groq.com (BYTESHIELD_AI_KEY). "
                "También: BYTESHIELD_AI_OPENAI_KEY o BYTESHIELD_AI_GROQ_KEY para reintento automático."
            )
        if provider == "groq":
            return (
                "Cuota de Groq agotada (HTTP 429). Revisa límites en console.groq.com o espera unos minutos."
            )
        return (
            "Cuota o límite de la API de IA agotado (HTTP 429). Revisa el plan o las credenciales."
        )
    snippet = raw[:220].replace("\n", " ").strip()
    return f"Error HTTP {code} ({provider}): {snippet or '(sin cuerpo de respuesta)'}"


def _gemini_request(prompt: str, api_key: str) -> str:
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.0-flash:generateContent?key={api_key}"
    )
    payload = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"maxOutputTokens": 600},
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["candidates"][0]["content"]["parts"][0]["text"]


def _openai_request(prompt: str, api_key: str) -> str:
    url = "https://api.openai.com/v1/chat/completions"
    payload = json.dumps({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 600,
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


def _groq_request(prompt: str, api_key: str) -> str:
    """API compatible con OpenAI en https://api.groq.com (clave gratuita en console.groq.com)."""
    url = "https://api.groq.com/openai/v1/chat/completions"
    model = os.environ.get("BYTESHIELD_GROQ_MODEL", GROQ_MODEL_DEFAULT).strip() or GROQ_MODEL_DEFAULT
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 600,
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            # Groq/Cloudflare a veces rechazan el User-Agent por defecto de urllib (403).
            "User-Agent": "Byte-Shield/1.0 (TLS audit; +https://github.com/)",
        },
    )
    with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


def analizar_con_ia(resultados: list[dict]) -> str:
    """
    Envía los hallazgos del escaneo a una API de IA y retorna
    un análisis ejecutivo en texto plano.

    Lanza RuntimeError con mensaje descriptivo si falla (sin API key,
    error de red, respuesta inesperada). El caller decide cómo manejarlo.
    """
    api_key = os.environ.get("BYTESHIELD_AI_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "Variable de entorno BYTESHIELD_AI_KEY no configurada. "
            "Exporta la clave antes de iniciar el dashboard."
        )

    provider = os.environ.get("BYTESHIELD_AI_PROVIDER", "gemini").lower().strip()
    prompt = _build_prompt(resultados)

    try:
        if provider == "openai":
            return _openai_request(prompt, api_key)
        if provider == "groq":
            return _groq_request(prompt, api_key)
        return _gemini_request(prompt, api_key)
    except urllib.error.HTTPError as e:
        # Reintentos si Gemini devuelve 429: Groq (gratis) u OpenAI opcional
        if provider == "gemini" and e.code == 429:
            groq_fb = os.environ.get("BYTESHIELD_AI_GROQ_KEY", "").strip()
            if groq_fb:
                try:
                    return _groq_request(prompt, groq_fb)
                except urllib.error.HTTPError as e2:
                    raise RuntimeError(_friendly_http_error_ia(e2, "groq")) from e2
                except (urllib.error.URLError, socket.timeout, OSError) as e2:
                    raise RuntimeError(
                        f"Error de red al contactar groq (fallback): {e2}"
                    ) from e2
                except (json.JSONDecodeError, KeyError, IndexError) as e2:
                    raise RuntimeError(
                        f"Respuesta inesperada de groq (fallback): {e2}"
                    ) from e2
            fallback = os.environ.get("BYTESHIELD_AI_OPENAI_KEY", "").strip()
            if fallback:
                try:
                    return _openai_request(prompt, fallback)
                except urllib.error.HTTPError as e2:
                    raise RuntimeError(_friendly_http_error_ia(e2, "openai")) from e2
                except (urllib.error.URLError, socket.timeout, OSError) as e2:
                    raise RuntimeError(
                        f"Error de red al contactar openai (fallback): {e2}"
                    ) from e2
                except (json.JSONDecodeError, KeyError, IndexError) as e2:
                    raise RuntimeError(
                        f"Respuesta inesperada de openai (fallback): {e2}"
                    ) from e2
        raise RuntimeError(_friendly_http_error_ia(e, provider)) from e
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        raise RuntimeError(f"Error de red al contactar {provider}: {e}") from e
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        raise RuntimeError(f"Respuesta inesperada de {provider}: {e}") from e


# ══════════════════════════════════════════════════════════════════
# MÓDULO 8 — MAPEO DE DEPENDENCIAS CRIPTOGRÁFICAS
#
# Combina dos fuentes de descubrimiento:
#   1. SANs del certificado TLS (stdlib puro — ssl.getpeercert)
#   2. Certificate Transparency Logs via crt.sh (urllib.request)
# ══════════════════════════════════════════════════════════════════

CRTSH_URL     = "https://crt.sh/?q={domain}&output=json"
CRTSH_TIMEOUT = 8


def extraer_sans_certificado(host: str, puerto: int = 443) -> list[str]:
    """
    Conecta al servidor y extrae los Subject Alternative Names (SANs)
    del certificado TLS usando ssl.getpeercert() — stdlib puro.

    Retorna lista de dominios DNS del SAN, o [] si falla.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, puerto), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        sans = [
            valor
            for tipo, valor in cert.get("subjectAltName", [])
            if tipo == "DNS"
        ]
        return sans
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
        return []


def _normalizar_dominio(entrada: str) -> Optional[str]:
    """
    Convierte wildcards (*.empresa.com) a su dominio base (empresa.com).
    Filtra entradas no-DNS.
    """
    entrada = entrada.strip().lstrip("*.")
    if not entrada or " " in entrada or "/" in entrada:
        return None
    return entrada.lower()


def descubrir_subdominios_crtsh(dominio: str) -> list[str]:
    """
    Consulta crt.sh (Certificate Transparency Logs) para descubrir
    subdominios públicamente registrados del dominio base.

    Retorna lista de subdominios únicos, o [] si offline / error.
    """
    try:
        url = CRTSH_URL.format(domain=f"%.{dominio}")
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "ByteShield/1.0"},
        )
        with urllib.request.urlopen(req, timeout=CRTSH_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        vistos: set[str] = set()
        resultado = []
        for entry in data:
            for nombre in entry.get("name_value", "").split("\n"):
                norm = _normalizar_dominio(nombre)
                if norm and norm not in vistos and dominio in norm:
                    vistos.add(norm)
                    resultado.append(norm)
        return sorted(resultado)

    except (urllib.error.URLError, socket.timeout, OSError,
            json.JSONDecodeError, KeyError):
        return []


def _dominio_base(host: str) -> Optional[str]:
    """Extrae el dominio de segundo nivel (empresa.com) de un hostname."""
    partes = host.split(".")
    if len(partes) >= 2:
        return ".".join(partes[-2:])
    return None


def mapear_dependencias(host: str, puerto: int = 443) -> dict:
    """
    Punto de entrada principal del módulo de mapeo.

    Retorna un dict con:
      - sans:         dominios del certificado TLS del host
      - crtsh:        subdominios de Certificate Transparency Logs
      - todos:        unión deduplicada de ambas fuentes
      - dominio_base: dominio raíz detectado
      - fuentes:      qué fuentes respondieron ('cert', 'crtsh', ninguna)
    """
    sans   = extraer_sans_certificado(host, puerto)
    dominio = _dominio_base(host) or host
    crtsh  = descubrir_subdominios_crtsh(dominio)

    todos: list[str] = sorted({
        _normalizar_dominio(s) or s
        for s in sans + crtsh
        if s and s != host
    })

    fuentes = []
    if sans:
        fuentes.append("cert")
    if crtsh:
        fuentes.append("crtsh")

    return {
        "host":         host,
        "puerto":       puerto,
        "dominio_base": dominio,
        "sans":         sans,
        "crtsh":        crtsh,
        "todos":        todos,
        "fuentes":      fuentes,
    }


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
