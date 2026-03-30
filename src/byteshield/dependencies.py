"""Mapeo de dependencias — SANs + crt.sh."""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
from typing import Optional

from byteshield.motor_tls import CONNECT_TIMEOUT, CRTSH_TIMEOUT

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"


def extraer_sans_certificado(host: str, puerto: int = 443) -> list[str]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, puerto), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        return [valor for tipo, valor in cert.get("subjectAltName", []) if tipo == "DNS"]
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
        return []


def _normalizar_dominio(entrada: str) -> Optional[str]:
    entrada = entrada.strip().lstrip("*.")
    if not entrada or " " in entrada or "/" in entrada:
        return None
    return entrada.lower()


def descubrir_subdominios_crtsh(dominio: str) -> list[str]:
    try:
        url = CRTSH_URL.format(domain=f"%.{dominio}")
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "ByteShield/1.0"},
        )
        with urllib.request.urlopen(req, timeout=CRTSH_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        vistos: set[str] = set()
        resultado: list[str] = []
        for entry in data:
            for nombre in entry.get("name_value", "").split("\n"):
                norm = _normalizar_dominio(nombre)
                if norm and norm not in vistos and dominio in norm:
                    vistos.add(norm)
                    resultado.append(norm)
        return sorted(resultado)

    except (urllib.error.URLError, socket.timeout, OSError, json.JSONDecodeError, KeyError):
        return []


def _dominio_base(host: str) -> Optional[str]:
    partes = host.split(".")
    if len(partes) >= 2:
        return ".".join(partes[-2:])
    return None


def mapear_dependencias(host: str, puerto: int = 443) -> dict:
    sans = extraer_sans_certificado(host, puerto)
    dominio = _dominio_base(host) or host
    crtsh = descubrir_subdominios_crtsh(dominio)

    todos: list[str] = sorted(
        {
            _normalizar_dominio(s) or s
            for s in sans + crtsh
            if s and s != host
        }
    )

    fuentes: list[str] = []
    if sans:
        fuentes.append("cert")
    if crtsh:
        fuentes.append("crtsh")

    return {
        "host": host,
        "puerto": puerto,
        "dominio_base": dominio,
        "sans": sans,
        "crtsh": crtsh,
        "todos": todos,
        "fuentes": fuentes,
    }
