"""Fase 1 — Ingesta y validación de objetivos."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any, Optional

from byteshield.utils import get_logger

log = get_logger("ingesta")


def validar_objetivo(objetivo: str) -> str:
    """Valida que el objetivo sea un hostname o IP básicamente correcto."""
    objetivo = objetivo.strip()
    if not objetivo:
        raise ValueError("El objetivo no puede estar vacío.")
    try:
        socket.getaddrinfo(objetivo, None)
    except socket.gaierror:
        raise ValueError(f"No se pudo resolver el objetivo: '{objetivo}'")
    return objetivo


def cargar_targets(
    target: Optional[str],
    targets_file: Optional[str],
    *,
    strict: bool = True,
) -> list[str]:
    """
    Devuelve la lista de hosts a analizar.

    Si ``strict`` es True, lanza FileNotFoundError / ValueError en error.
    Si es False, comportamiento legado con mensajes (para compat).
    """
    targets: list[str] = []
    if target:
        targets.append(target)
    if targets_file:
        path = Path(targets_file)
        if not path.is_file():
            if strict:
                raise FileNotFoundError(f"Archivo no encontrado: {targets_file}")
            raise FileNotFoundError(targets_file)
        with path.open(encoding="utf-8") as fh:
            for linea in fh:
                linea = linea.strip()
                if linea and not linea.startswith("#"):
                    targets.append(linea)
    if not targets:
        raise ValueError("Debes indicar al menos un objetivo (--target o --targets).")
    return targets


def load_static_inventory(targets_file: str | Path = "targets.json") -> list[dict[str, Any]]:
    """
    Carga inventario estático de objetivos (CONTEXTO §16).
    """
    path = Path(targets_file)
    if not path.exists():
        raise FileNotFoundError(f"Inventario no encontrado: {targets_file}")

    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    targets = data.get("targets", [])
    validated: list[dict[str, Any]] = []
    for t in targets:
        if "host" in t and "port" in t:
            validated.append(t)
        else:
            log.warning("Objetivo ignorado (formato inválido): %s", t)
    return validated


def load_static_inventory_for_host(host: str, targets_file: str | Path = "targets.json") -> dict[str, Any]:
    """Busca un host en el inventario y devuelve metadatos y dependientes."""
    try:
        targets = load_static_inventory(targets_file)
    except FileNotFoundError:
        return {"found": False, "host": host, "dependents": [], "source": "static"}

    for t in targets:
        if t["host"] == host or t.get("alias") == host:
            return {
                "found": True,
                "host": t["host"],
                "dependents": t.get("dependents", []),
                "environment": t.get("environment", "unknown"),
                "tags": t.get("tags", []),
            }
    return {"found": False, "host": host, "dependents": [], "source": "static"}


def discover_cloudrun_services(project_id: str | None = None, region: str = "us-central1") -> list[dict[str, Any]]:
    """
    [STUB — NO IMPLEMENTADO AÚN]

    Descubre servicios en Google Cloud Run. Ver CONTEXTO_RETO_TLS.MD §16.
    """
    raise NotImplementedError(
        "Cloud Run discovery no implementado. "
        "Usa load_static_inventory() o configura credenciales GCP. "
        "Ver documentación en CONTEXTO_RETO_TLS.MD §16."
    )
