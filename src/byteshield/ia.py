"""Análisis con IA (Gemini / OpenAI / Groq) — urllib stdlib."""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from typing import Any

AI_TIMEOUT = 20
GROQ_MODEL_DEFAULT = "llama-3.3-70b-versatile"


def _build_prompt(resultados: list[dict[str, Any]]) -> str:
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
            "User-Agent": "Byte-Shield/1.0 (TLS audit; +https://github.com/)",
        },
    )
    with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


def analizar_con_ia(resultados: list[dict[str, Any]]) -> str:
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
