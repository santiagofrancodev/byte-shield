#!/usr/bin/env python3
"""
Fachada retrocompatible — el núcleo vive en ``src/byteshield``.

Uso:
    python tls_scanner.py --target HOST
    pip install -e . && byteshield --target HOST
"""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir():
    sys.path.insert(0, str(_SRC))

from byteshield.cli import main
from byteshield.dependencies import mapear_dependencias
from byteshield.ia import analizar_con_ia
from byteshield.ingesta import cargar_targets, validar_objetivo
from byteshield.motor_reglas import (
    NIVEL_CRITICO,
    NIVEL_MEDIO,
    NIVEL_SEGURO,
    calcular_criticidad,
)
from byteshield.motor_tls import (
    CONNECT_TIMEOUT,
    auditar_tls_en_puerto,
    escanear_puerto,
    escanear_puertos,
)
from byteshield.pipeline import auditar_host
from byteshield.reporting import exportar_json

__all__ = [
    "CONNECT_TIMEOUT",
    "NIVEL_CRITICO",
    "NIVEL_MEDIO",
    "NIVEL_SEGURO",
    "validar_objetivo",
    "cargar_targets",
    "escanear_puerto",
    "escanear_puertos",
    "auditar_tls_en_puerto",
    "calcular_criticidad",
    "analizar_con_ia",
    "mapear_dependencias",
    "auditar_host",
    "exportar_json",
    "main",
]

if __name__ == "__main__":
    main()
