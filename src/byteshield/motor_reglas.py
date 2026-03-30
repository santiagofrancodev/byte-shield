"""Motor de reglas — Compliance-as-Code."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from byteshield.motor_tls import enriquecer_desde_api

NIVEL_CRITICO = "CRÍTICO"
NIVEL_MEDIO = "MEDIO"
NIVEL_SEGURO = "SEGURO"

NIVEL_PRIORIDAD: dict[str, int] = {
    NIVEL_SEGURO: 0,
    NIVEL_MEDIO: 1,
    NIVEL_CRITICO: 2,
}

_ESTANDARES_CACHE: dict[str, Any] | None = None


def _compliance_candidates() -> list[Path]:
    here = Path(__file__).resolve().parent
    root = here.parent.parent
    return [
        here / "compliance" / "ESTANDARES_CUMPLIMIENTO.json",
        root / "compliance" / "ESTANDARES_CUMPLIMIENTO.json",
    ]


def load_estandares() -> dict[str, dict[str, Any]]:
    """Carga ESTANDARES_CUMPLIMIENTO desde JSON empaquetado o repo."""
    global _ESTANDARES_CACHE
    if _ESTANDARES_CACHE is not None:
        return _ESTANDARES_CACHE
    for p in _compliance_candidates():
        if p.exists():
            with p.open(encoding="utf-8") as f:
                _ESTANDARES_CACHE = json.load(f)
                return _ESTANDARES_CACHE
    raise FileNotFoundError(
        "No se encontró ESTANDARES_CUMPLIMIENTO.json (byteshield/compliance o /compliance)."
    )


def _nivel_maximo(niveles: list[str]) -> str:
    if not niveles:
        return NIVEL_MEDIO
    return max(niveles, key=lambda n: NIVEL_PRIORIDAD.get(n, 0))


def _formatear_hallazgo(
    protocolo: str,
    estandar: dict[str, Any],
    api_data: dict | None = None,
) -> str:
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


def calcular_criticidad(resultados_tls: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    ESTANDARES = load_estandares()
    hallazgos: list[str] = []
    recomendaciones: list[str] = []
    niveles_detectados: list[str] = []

    tls13_habilitado = resultados_tls.get("TLS 1.3", {}).get("habilitado", False)
    tls12_habilitado = resultados_tls.get("TLS 1.2", {}).get("habilitado", False)

    for protocolo, estandar in ESTANDARES.items():
        info = resultados_tls.get(protocolo, {})
        habilitado = info.get("habilitado", False)

        if not habilitado:
            continue

        nivel_estandar = estandar["nivel"]

        if nivel_estandar == NIVEL_CRITICO:
            api_data = enriquecer_desde_api(protocolo)
            hallazgos.append(_formatear_hallazgo(protocolo, estandar, api_data))
            recomendaciones.append(estandar["recomendacion_accionable"])
            niveles_detectados.append(NIVEL_CRITICO)

        elif protocolo == "TLS 1.2" and not tls13_habilitado:
            alerta = estandar.get("alerta_sin_tls13", {})
            if alerta:
                fuente = alerta.get("fuente_oficial", estandar["fuente_oficial"])
                fuente_short = fuente.split(",")[0].strip()
                hallazgos.append(f"[{fuente_short}] {alerta['motivo_tecnico']}")
                recomendaciones.append(alerta["recomendacion_accionable"])
                niveles_detectados.append(alerta["nivel"])

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

    if tls13_habilitado and not hallazgos:
        hallazgos.append(
            "[RFC 8446] TLS 1.3 implementado. Sin protocolos obsoletos detectados."
        )
        recomendaciones.append(ESTANDARES["TLS 1.3"]["recomendacion_accionable"])
        niveles_detectados.append(NIVEL_SEGURO)

    nivel_final = _nivel_maximo(niveles_detectados)
    return nivel_final, hallazgos, recomendaciones


def get_max_severity(resultados: list[dict[str, Any]]) -> str:
    """Mayor severidad entre varios hosts/puertos."""
    if not resultados:
        return NIVEL_SEGURO
    niveles = [r.get("nivel", NIVEL_MEDIO) for r in resultados]
    return _nivel_maximo(niveles)


def should_map_dependencies(severity: str, trigger: str, flags: dict[str, Any]) -> bool:
    """
    Decide si ejecutar mapeo de dependencias post-escaneo (CONTEXTO §15).

    severity: CRÍTICO | MEDIO | SEGURO (salida del motor)
    trigger: cicd_hook | comando_manual | cron_schedule | webhook_evento | ...
    flags: p.ej. {"deps": True}
    """
    if severity == NIVEL_CRITICO:
        return True
    if severity == NIVEL_MEDIO:
        if trigger == "cicd_hook":
            return True
        if trigger == "comando_manual":
            return bool(flags.get("deps", False))
        if trigger == "cron_schedule":
            return False
    return False
