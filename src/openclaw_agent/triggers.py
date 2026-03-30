"""Disparadores: cron, CI/CD, webhook, mensaje (contratos de datos)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

TriggerKind = Literal[
    "cron_schedule",
    "cicd_hook",
    "webhook_evento",
    "comando_mensaje",
    "comando_manual",
]


@dataclass
class TriggerContext:
    """Salida normalizada hacia el orquestador."""

    kind: TriggerKind
    hosts: list[str]
    ports: list[int]
    trigger_id: str = ""
    options: dict[str, Any] = field(default_factory=dict)


def from_cron(hosts: list[str], ports: list[int] | None = None) -> TriggerContext:
    return TriggerContext(
        kind="cron_schedule",
        hosts=hosts,
        ports=ports or [443],
        trigger_id="cron",
    )


def from_cicd(host: str, port: int = 443) -> TriggerContext:
    return TriggerContext(
        kind="cicd_hook",
        hosts=[host],
        ports=[port],
        trigger_id="cicd",
    )


def from_webhook(hosts: list[str], ports: list[int] | None = None) -> TriggerContext:
    return TriggerContext(
        kind="webhook_evento",
        hosts=hosts,
        ports=ports or [443],
        trigger_id="webhook",
    )


def from_chat_message(host: str, ports: list[int] | None = None) -> TriggerContext:
    return TriggerContext(
        kind="comando_mensaje",
        hosts=[host],
        ports=ports or [443],
        trigger_id="chat",
    )
