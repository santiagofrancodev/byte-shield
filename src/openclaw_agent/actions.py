"""Acciones autónomas: alertas, tickets, reporte, bloqueo CI (exit code)."""

from __future__ import annotations

import json
import logging
import os
import smtplib
import sys
import urllib.error
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from byteshield.motor_reglas import NIVEL_CRITICO, NIVEL_MEDIO

log = logging.getLogger("openclaw.actions")


def decide_exit_code(resultados: list[dict[str, Any]]) -> int:
    niveles = [r.get("nivel") for r in resultados]
    if NIVEL_CRITICO in niveles:
        return 2
    if NIVEL_MEDIO in niveles:
        return 1
    return 0


def block_cicd_if_critical(resultados: list[dict[str, Any]]) -> bool:
    """Devuelve True si se debe bloquear pipeline (severidad crítica)."""
    return decide_exit_code(resultados) == 2


def send_slack_webhook(text: str, webhook_url: str | None = None) -> None:
    url = webhook_url or os.environ.get("BYTESHIELD_SLACK_WEBHOOK", "").strip()
    if not url:
        log.warning("Slack webhook no configurado; omitiendo alerta.")
        return
    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except (urllib.error.URLError, OSError) as e:
        log.error("Fallo enviando a Slack: %s", e)


def send_email_smtp(subject: str, body: str) -> None:
    host = os.environ.get("BYTESHIELD_SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("BYTESHIELD_SMTP_PORT", "587"))
    user = os.environ.get("BYTESHIELD_SMTP_USER", "").strip()
    password = os.environ.get("BYTESHIELD_SMTP_PASS", "").strip()
    to_addr = os.environ.get("BYTESHIELD_ALERT_EMAIL", user).strip()
    if not user or not password:
        log.warning("SMTP no configurado; omitiendo email.")
        return

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_addr
    msg.attach(MIMEText(body, "plain", "utf-8"))

    with smtplib.SMTP(host, port) as smtp:
        smtp.starttls()
        smtp.login(user, password)
        smtp.sendmail(user, [to_addr], msg.as_string())


def apply_policy(
    resultados: list[dict[str, Any]],
    *,
    trigger_kind: str,
) -> list[str]:
    """
    Ejecuta acciones según severidad. Devuelve lista de acciones tomadas.
    """
    taken: list[str] = []
    code = decide_exit_code(resultados)
    if code == 2:
        summary = json.dumps(resultados, ensure_ascii=False, indent=2)[:4000]
        send_slack_webhook(f":rotating_light: TLS CRÍTICO ({trigger_kind})\n```\n{summary}\n```")
        try:
            send_email_smtp("Byte-Shield: hallazgo CRÍTICO", summary)
        except OSError as e:
            log.error("Email: %s", e)
        taken.extend(["slack_or_skip", "email_or_skip"])
    elif code == 1:
        send_slack_webhook(f":large_yellow_circle: TLS MEDIO ({trigger_kind})")
        taken.append("slack_or_skip")
    return taken


def exit_for_ci(resultados: list[dict[str, Any]]) -> None:
    """sys.exit con código de política CI/CD."""
    sys.exit(decide_exit_code(resultados))
