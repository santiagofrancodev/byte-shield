"""Motor TLS — handshakes y enriquecimiento opcional."""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
import warnings
from typing import Any, Optional

warnings.filterwarnings("ignore", category=DeprecationWarning)

# Timeouts (CONTEXTO)
CONNECT_TIMEOUT = 5
API_TIMEOUT = 2
CRTSH_TIMEOUT = 8

DEFAULT_PORTS = [80, 443, 8080, 8443]

TLS_PROTOCOLS: list[tuple[str, str, bool]] = [
    ("TLS 1.0", "PROTOCOL_TLSv1", True),
    ("TLS 1.1", "PROTOCOL_TLSv1_1", True),
    ("TLS 1.2", "PROTOCOL_TLSv1_2", False),
    ("TLS 1.3", "PROTOCOL_TLS", False),
]

API_ENRICHMENT_URL = "https://ciphersuite.info/api/cs/"

_api_disponible: bool | None = None


def reset_api_cache() -> None:
    """Útil en tests para forzar nueva comprobación de ciphersuite.info."""
    global _api_disponible
    _api_disponible = None


def _verificar_disponibilidad_api() -> bool:
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
            1
            for cs in data.get("ciphersuites", [])
            if "insecure" in str(cs.get("security", "")).lower()
        )
        return {
            "fuente": "ciphersuite.info",
            "total_suites": total,
            "suites_inseguras": insecure,
        }
    except (urllib.error.URLError, socket.timeout, OSError, json.JSONDecodeError, KeyError):
        return None


def escanear_puerto(host: str, puerto: int, timeout: int = CONNECT_TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, puerto), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def escanear_puertos(
    host: str,
    puertos: list[int],
    *,
    verbose: bool = False,
    timeout: int = CONNECT_TIMEOUT,
) -> list[int]:
    """Lista de puertos abiertos. Si ``verbose``, imprime (solo CLI)."""
    _R = "\033[91m"
    _G = "\033[92m"
    _W = "\033[97m"
    _RST = "\033[0m"
    abiertos: list[int] = []
    for p in puertos:
        estado = escanear_puerto(host, p, timeout=timeout)
        if verbose:
            icono = f"{_G}ABIERTO{_RST}" if estado else f"{_R}CERRADO{_RST}"
            print(f"  Puerto {_W}{p:5d}{_RST}/TCP  →  {icono}")
        if estado:
            abiertos.append(p)
    return abiertos


def probar_protocolo_tls(
    host: str,
    puerto: int,
    protocolo_attr: str,
    forzar_version: Optional[str] = None,
    timeout: int = CONNECT_TIMEOUT,
) -> bool:
    try:
        ctx = ssl.SSLContext(getattr(ssl, protocolo_attr))
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if forzar_version == "TLS1_3":
            if hasattr(ssl, "TLSVersion"):
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            else:
                return False

        with socket.create_connection((host, puerto), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True

    except ssl.SSLError:
        return False
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    except AttributeError:
        return False


def auditar_tls_en_puerto(host: str, puerto: int) -> dict[str, Any]:
    resultados: dict[str, Any] = {}

    for nombre, attr, obsoleto in TLS_PROTOCOLS:
        if nombre == "TLS 1.3":
            habilitado = probar_protocolo_tls(host, puerto, attr, forzar_version="TLS1_3")
        else:
            if not hasattr(ssl, attr):
                habilitado = False
            else:
                habilitado = probar_protocolo_tls(host, puerto, attr)

        resultados[nombre] = {
            "habilitado": habilitado,
            "obsoleto": obsoleto,
        }

    return resultados
