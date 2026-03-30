"""Enrutamiento de reportes por disparador y severidad (CONTEXTO §13)."""

from __future__ import annotations

from typing import Any, Callable

from byteshield.motor_reglas import NIVEL_CRITICO, get_max_severity


def should_broadcast(finding: dict[str, Any]) -> bool:
    return finding.get("severity") == "CRITICAL" or finding.get("nivel") == NIVEL_CRITICO


def resolve_audiences(trigger: str, severity: str) -> list[str]:
    """
    Determina qué perfiles reciben salida.
    severidad: CRÍTICO | MEDIO | SEGURO
    """
    if severity == NIVEL_CRITICO:
        return ["cicd", "tecnico", "gestor", "ejecutivo"]

    mapping: dict[str, list[str]] = {
        "cicd_hook": ["cicd"],
        "comando_mensaje": ["tecnico"],
        "comando_manual": ["tecnico"],
        "cron_schedule": ["gestor"],
        "webhook_evento": ["tecnico", "gestor"],
    }
    return mapping.get(trigger, ["tecnico"])


def route_report(
    scan_result: list[dict[str, Any]],
    trigger: str,
    *,
    enrich_fn: Callable[..., str] | None = None,
    deliver_fn: Callable[..., None] | None = None,
) -> dict[str, Any]:
    """
    Resuelve audiencias y opcionalmente enriquece con IA y entrega por canal.

    ``enrich_fn(audience)`` y ``deliver_fn(audience, content)`` son inyectables para tests.
    """
    severity = get_max_severity(scan_result)
    audiences = resolve_audiences(trigger, severity)

    out: dict[str, Any] = {
        "trigger": trigger,
        "severity": severity,
        "audiences": audiences,
        "deliveries": {},
    }

    if enrich_fn is None:
        from byteshield.ai_enrichment import enrich_for_audience

        def _enrich(aud: str) -> str:
            return enrich_for_audience(scan_result, aud)

        enrich_fn = _enrich

    for aud in audiences:
        try:
            text = enrich_fn(aud)
        except Exception as e:
            text = f"[enriquecimiento omitido: {e}]"
        out["deliveries"][aud] = {"formato": "texto", "cuerpo": text}
        if deliver_fn:
            deliver_fn(aud, text)

    return out
