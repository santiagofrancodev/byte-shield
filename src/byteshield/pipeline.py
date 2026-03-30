"""Orquestación ingest → TLS → reglas → (deps) → resultados estructurados."""

from __future__ import annotations

import datetime
from typing import Any

from byteshield.dependencies import mapear_dependencias
from byteshield.ingesta import load_static_inventory_for_host, validar_objetivo
from byteshield.motor_reglas import calcular_criticidad, should_map_dependencies
from byteshield.motor_tls import CONNECT_TIMEOUT, auditar_tls_en_puerto, escanear_puertos
from byteshield.reporting import imprimir_resultado_host
from byteshield.utils import get_logger

log = get_logger("pipeline")


def _want_deps_map(
    nivel: str,
    trigger: str,
    flags: dict[str, Any],
    include_deps: bool | None,
) -> bool:
    if include_deps is True:
        return True
    if include_deps is False:
        return False
    return should_map_dependencies(nivel, trigger, flags)


def _build_deps_map(host: str, puerto: int) -> dict[str, Any]:
    mapeo = mapear_dependencias(host, puerto)
    inv = load_static_inventory_for_host(host)
    blast = list(inv.get("dependents", [])) if inv.get("found") else []
    return {
        "executed": True,
        "source": "static" if inv.get("found") else "discovery",
        "blast_radius": blast,
        "dependency_chain": {},
        "mapeo_tls": mapeo,
    }


def auditar_host(
    host: str,
    puertos: list[int],
    *,
    verbose: bool = True,
    connect_timeout: int = CONNECT_TIMEOUT,
    trigger: str = "comando_manual",
    flags: dict[str, Any] | None = None,
    include_deps: bool | None = None,
) -> list[dict[str, Any]]:
    """
    Pipeline completo para un host.

    ``include_deps`` fuerza mapeo de dependencias si es True; si es None,
    aplica ``should_map_dependencies`` según nivel y trigger.
    """
    flags = dict(flags or {})
    resultados_host: list[dict[str, Any]] = []

    try:
        host = validar_objetivo(host)
    except ValueError as e:
        log.warning("%s", e)
        if verbose:
            from byteshield.reporting import RED, RESET

            print(f"{RED}[!] {e}{RESET}")
        return []

    if verbose:
        from byteshield.reporting import BOLD, CYAN, RESET

        print(f"\n{BOLD}{CYAN}[*] Objetivo: {host}{RESET}")
        print(f"{CYAN}[*] Escaneando puertos: {puertos}{RESET}")

    puertos_abiertos = escanear_puertos(host, puertos, verbose=verbose, timeout=connect_timeout)

    if not puertos_abiertos:
        if verbose:
            from byteshield.reporting import RED, RESET, YELLOW

            print(f"{YELLOW}[!] No se encontraron puertos abiertos en {host}.{RESET}")
        return []

    for puerto in puertos_abiertos:
        if verbose:
            from byteshield.reporting import CYAN, RESET

            print(f"\n{CYAN}[*] Auditando TLS en {host}:{puerto} ...{RESET}")

        resultados_tls = auditar_tls_en_puerto(host, puerto)
        nivel, hallazgos, recomendaciones = calcular_criticidad(resultados_tls)

        if verbose:
            imprimir_resultado_host(
                host, puerto, resultados_tls, nivel, hallazgos, recomendaciones
            )

        row: dict[str, Any] = {
            "host": host,
            "puerto": puerto,
            "nivel": nivel,
            "tls": resultados_tls,
            "hallazgos": hallazgos,
            "recomendaciones": recomendaciones,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "trigger": trigger,
        }

        if _want_deps_map(nivel, trigger, flags, include_deps):
            row["deps_map"] = _build_deps_map(host, puerto)
            row["deps_map_reason"] = None
        else:
            row["deps_map"] = None
            row["deps_map_reason"] = (
                f"Omitido por política (nivel={nivel}, trigger={trigger})"
            )

        resultados_host.append(row)

    return resultados_host


def run_scan(
    hosts: list[str],
    puertos: list[int],
    *,
    verbose: bool = True,
    connect_timeout: int = CONNECT_TIMEOUT,
    trigger: str = "comando_manual",
    flags: dict[str, Any] | None = None,
    include_deps: bool | None = None,
) -> list[dict[str, Any]]:
    """Escanea varios hosts y concatena resultados."""
    out: list[dict[str, Any]] = []
    for h in hosts:
        out.extend(
            auditar_host(
                h,
                puertos,
                verbose=verbose,
                connect_timeout=connect_timeout,
                trigger=trigger,
                flags=flags,
                include_deps=include_deps,
            )
        )
    return out
