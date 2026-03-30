"""Enriquecimiento IA por audiencia (CONTEXTO §13)."""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from typing import Any

from byteshield.ia import (
    _friendly_http_error_ia,
    _gemini_request,
    _groq_request,
    _openai_request,
)

AUDIENCE_PROMPTS: dict[str, str] = {
    "cicd": """
        Responde SOLO con JSON válido. Sin prosa. Sin markdown.
        Campos obligatorios: exit_code (0 o 2), host, findings (lista),
        action (PASS o BLOCK), timestamp ISO8601.
    """,
    "tecnico": """
        Eres un ingeniero de seguridad senior. Analiza este hallazgo TLS
        y genera un reporte técnico que incluya:
        - Descripción técnica del problema
        - CVE o referencia normativa exacta
        - Comandos exactos de remediación (con rutas de archivo reales)
        - Comando de validación post-remediación
        Usa lenguaje técnico preciso. Sin resúmenes ejecutivos.
    """,
    "gestor": """
        Explica este hallazgo de seguridad para un líder técnico no especialista
        en ciberseguridad. Incluye:
        - Qué está mal y por qué importa (sin acrónimos técnicos)
        - Qué servicio o negocio se ve afectado
        - Qué acción se requiere y en qué plazo
        - A quién se debe asignar la remediación
        Máximo 200 palabras. Tono profesional, directo.
    """,
    "ejecutivo": """
        Genera un resumen ejecutivo de máximo 150 palabras para un CISO o directivo.
        Incluye:
        - Semáforo de riesgo: ROJO (crítico), AMARILLO (alto), VERDE (normal)
        - Impacto regulatorio si aplica (PCI-DSS, GDPR, ISO 27001)
        - Una sola acción recomendada con plazo
        - Sin jerga técnica. Sin comandos. Sin CVEs.
        Formato: párrafo breve + tabla de 2 columnas (Riesgo | Acción).
    """,
}


def _scan_summary(scan_result: dict[str, Any] | list[dict[str, Any]]) -> str:
    if isinstance(scan_result, list):
        parts = []
        for r in scan_result:
            parts.append(
                f"Servidor {r.get('host')}:{r.get('puerto')} nivel {r.get('nivel')}. "
                f"Hallazgos: {r.get('hallazgos', [])}"
            )
        return "\n".join(parts)
    return json.dumps(scan_result, ensure_ascii=False, indent=2)


def enrich_for_audience(
    scan_result: dict[str, Any] | list[dict[str, Any]],
    audience: str,
    *,
    api_key: str | None = None,
    provider: str | None = None,
) -> str:
    """
    Reformula hallazgos TLS según perfil: cicd, tecnico, gestor, ejecutivo.
    Requiere BYTESHIELD_AI_KEY salvo que se pasen api_key/provider explícitos.
    """
    aud = audience.lower().strip()
    base = AUDIENCE_PROMPTS.get(aud)
    if not base:
        raise ValueError(f"Audiencia desconocida: {audience}")

    key = (api_key or os.environ.get("BYTESHIELD_AI_KEY", "")).strip()
    if not key:
        raise RuntimeError("BYTESHIELD_AI_KEY no configurada (requerida para enriquecimiento).")

    prov = (provider or os.environ.get("BYTESHIELD_AI_PROVIDER", "gemini")).lower().strip()
    body = _scan_summary(scan_result)
    prompt = f"{base.strip()}\n\nDATOS DEL ESCANEO:\n{body}"

    try:
        if prov == "openai":
            return _openai_request(prompt, key)
        if prov == "groq":
            return _groq_request(prompt, key)
        return _gemini_request(prompt, key)
    except urllib.error.HTTPError as e:
        raise RuntimeError(_friendly_http_error_ia(e, prov)) from e
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        raise RuntimeError(f"Error de red al contactar {prov}: {e}") from e
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        raise RuntimeError(f"Respuesta inesperada de {prov}: {e}") from e
