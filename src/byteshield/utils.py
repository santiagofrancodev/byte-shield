"""Configuración y logging estructurado."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

LOGGER_NAME = "byteshield"


def setup_logging(level: int | None = None) -> logging.Logger:
    """Configura el logger raíz de Byte-Shield (idempotente si ya tiene handlers)."""
    log = logging.getLogger(LOGGER_NAME)
    if log.handlers:
        if level is not None:
            log.setLevel(level)
        return log
    log.setLevel(level or logging.INFO)
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    log.addHandler(h)
    return log


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(LOGGER_NAME if not name else f"{LOGGER_NAME}.{name}")


def is_tty() -> bool:
    return sys.stdout.isatty()


def load_yaml_config(path: str | Path) -> dict[str, Any]:
    """Carga opcional byteshield.yaml — requiere PyYAML."""
    path = Path(path)
    if not path.exists():
        return {}
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError:
            get_logger().warning(
                "Archivo YAML configurado pero PyYAML no está instalado; omitiendo."
            )
            return {}
        with path.open(encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def env_int(key: str, default: int) -> int:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default
