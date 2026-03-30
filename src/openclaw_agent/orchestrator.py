"""
Orquestador: trigger → escaneo (biblioteca o subproceso) → política de acciones.

El agente solo invoca el contrato del escáner (import byteshield o ``python -m byteshield.cli``).
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

from byteshield.motor_tls import DEFAULT_PORTS
from byteshield.pipeline import run_scan
from openclaw_agent.actions import apply_policy, decide_exit_code
from openclaw_agent.triggers import TriggerContext

log = logging.getLogger("openclaw.orchestrator")


def scan_via_import(
    ctx: TriggerContext,
    *,
    connect_timeout: int = 5,
) -> list[dict[str, Any]]:
    """Modo recomendado: llama al paquete en proceso."""
    inc = ctx.options.get("include_deps")
    return run_scan(
        ctx.hosts,
        ctx.ports,
        verbose=False,
        connect_timeout=connect_timeout,
        trigger=ctx.kind,
        flags=ctx.options,
        include_deps=inc if isinstance(inc, bool) else None,
    )


def scan_via_subprocess(
    ctx: TriggerContext,
    python_exe: str | None = None,
    cwd: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Modo aislamiento: un host, ejecuta CLI y lee JSON generado."""
    if len(ctx.hosts) != 1:
        raise ValueError("subprocess: un solo host.")
    exe = python_exe or sys.executable
    out = Path.cwd() / ".byteshield_last_scan.json"
    cmd = [
        exe,
        "-m",
        "byteshield.cli",
        "--target",
        ctx.hosts[0],
        "--ports",
        *[str(p) for p in ctx.ports],
        "--trigger",
        ctx.kind,
        "--output",
        str(out),
        "--quiet",
    ]
    subprocess.run(cmd, check=False, cwd=cwd)
    if not out.exists():
        return []
    data = json.loads(out.read_text(encoding="utf-8"))
    return list(data.get("resultados", []))


def run_once(
    ctx: TriggerContext,
    mode: Literal["import", "subprocess"] = "import",
) -> int:
    """Un ciclo: escanear → acciones → exit code."""
    logging.basicConfig(level=logging.INFO)
    if mode == "import":
        res = scan_via_import(ctx)
    else:
        res = scan_via_subprocess(ctx)

    apply_policy(res, trigger_kind=ctx.kind)
    code = decide_exit_code(res)
    log.info("Scan completado: %s hallazgos, exit=%s", len(res), code)
    return code


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenClaw agent — Byte-Shield")
    parser.add_argument("--target", required=True, help="Host a escanear")
    parser.add_argument("--ports", nargs="+", type=int, default=DEFAULT_PORTS)
    parser.add_argument(
        "--trigger",
        default="cicd_hook",
        help="Tipo de disparador (cicd_hook, cron_schedule, ...)",
    )
    parser.add_argument(
        "--mode",
        choices=("import", "subprocess"),
        default="import",
    )
    parser.add_argument(
        "--ci-exit",
        action="store_true",
        help="Terminar con código 0/1/2 según hallazgos (CI/CD)",
    )
    args = parser.parse_args()

    ctx = TriggerContext(
        kind=args.trigger,  # type: ignore[arg-type]
        hosts=[args.target],
        ports=args.ports,
    )
    code = run_once(ctx, mode=args.mode)
    if args.ci_exit:
        sys.exit(code)
    sys.exit(0)


if __name__ == "__main__":
    main()
