#!/usr/bin/env python3
"""
Genera reporte HTML desde JSON — delega en ``byteshield.reporte_html``.
"""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir():
    sys.path.insert(0, str(_SRC))

from byteshield.reporte_html import generar_html, main

__all__ = ["generar_html", "main"]

if __name__ == "__main__":
    main()
