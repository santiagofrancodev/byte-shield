"""Generación de reporte HTML desde el dict/JSON de escaneo."""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from typing import Any

COLOR_CRITICO = "#ef4444"
COLOR_MEDIO = "#f59e0b"
COLOR_SEGURO = "#22c55e"
COLOR_MAP = {"CRÍTICO": COLOR_CRITICO, "MEDIO": COLOR_MEDIO, "SEGURO": COLOR_SEGURO}
BADGE_MAP = {"CRÍTICO": "🔴", "MEDIO": "🟡", "SEGURO": "🟢"}

PROTO_DANGER = {"TLS 1.0", "TLS 1.1"}
PROTO_WARN = {"TLS 1.2"}


def proto_class(nombre: str, habilitado: bool) -> str:
    if not habilitado:
        return "proto-disabled"
    if nombre in PROTO_DANGER:
        return "proto-danger"
    if nombre in PROTO_WARN:
        return "proto-warn"
    return "proto-safe"


TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TLS Scanner — Reporte de Seguridad</title>
<style>
  :root {{
    --bg:      #0f172a;
    --surface: #1e293b;
    --border:  #334155;
    --text:    #e2e8f0;
    --muted:   #94a3b8;
    --critico: {COLOR_CRITICO};
    --medio:   {COLOR_MEDIO};
    --seguro:  {COLOR_SEGURO};
    --cyan:    #22d3ee;
    --font-mono: 'Courier New', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    padding: 2rem;
    line-height: 1.6;
  }}
  header {{
    border-bottom: 2px solid var(--cyan);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
  }}
  header h1 {{
    font-size: 1.8rem;
    color: var(--cyan);
    font-family: var(--font-mono);
  }}
  header p {{ color: var(--muted); font-size: 0.9rem; margin-top: 0.25rem; }}

  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .meta-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
    text-align: center;
  }}
  .meta-card .value {{
    font-size: 2rem;
    font-weight: 700;
    color: var(--cyan);
  }}
  .meta-card .label {{ font-size: 0.8rem; color: var(--muted); margin-top: 0.2rem; }}

  .host-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }}
  .host-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.2rem;
  }}
  .host-header h2 {{
    font-family: var(--font-mono);
    font-size: 1.1rem;
    color: var(--cyan);
  }}
  .badge {{
    padding: 0.3rem 0.9rem;
    border-radius: 99px;
    font-size: 0.85rem;
    font-weight: 700;
    font-family: var(--font-mono);
  }}

  .protocol-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }}
  .protocol-box {{
    border-radius: 8px;
    padding: 0.75rem;
    text-align: center;
    border: 1px solid var(--border);
  }}
  .protocol-box .proto-name {{
    font-size: 0.8rem;
    color: var(--muted);
    font-family: var(--font-mono);
  }}
  .protocol-box .proto-status {{
    font-size: 1rem;
    font-weight: 700;
    font-family: var(--font-mono);
    margin-top: 0.25rem;
  }}
  .proto-danger   {{ background: rgba(239,68,68,0.12);   border-color: var(--critico); }}
  .proto-warn     {{ background: rgba(245,158,11,0.12);  border-color: var(--medio);   }}
  .proto-safe     {{ background: rgba(34,197,94,0.12);   border-color: var(--seguro);  }}
  .proto-disabled {{ background: rgba(51,65,85,0.35);    border-color: var(--border);  }}
  .proto-danger   .proto-status {{ color: var(--critico); }}
  .proto-warn     .proto-status {{ color: var(--medio);   }}
  .proto-safe     .proto-status {{ color: var(--seguro);  }}
  .proto-disabled .proto-status {{ color: var(--muted);   }}

  .findings-section h3 {{
    font-size: 0.85rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 0.6rem;
    font-family: var(--font-mono);
  }}
  .finding-item {{
    display: flex;
    gap: 0.6rem;
    align-items: flex-start;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--border);
    font-size: 0.9rem;
  }}
  .finding-item:last-child {{ border-bottom: none; }}
  .finding-item .icon {{ font-size: 1rem; flex-shrink: 0; }}
  .riesgo {{ color: #fca5a5; }}
  .recom  {{ color: #6ee7b7; }}

  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}

  footer {{
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--muted);
    font-size: 0.8rem;
    font-family: var(--font-mono);
  }}

  @media (max-width: 640px) {{
    .protocol-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .two-col {{ grid-template-columns: 1fr; }}
  }}
</style>
</head>
<body>

<header>
  <h1>&gt;_ TLS SCANNER — Reporte de Seguridad</h1>
  <p>CloudLabs Learning × Talento Tech Hackathon &nbsp;|&nbsp; Enfoque: Ciberseguridad Defensiva</p>
  <p style="margin-top:0.3rem">Generado: {GENERADO}</p>
</header>

<div class="meta-grid">
  <div class="meta-card">
    <div class="value">{TOTAL_HOSTS}</div>
    <div class="label">Servidores analizados</div>
  </div>
  <div class="meta-card">
    <div class="value" style="color:{COLOR_CRITICO_VAL}">{TOTAL_CRITICO}</div>
    <div class="label">🔴 Crítico</div>
  </div>
  <div class="meta-card">
    <div class="value" style="color:{COLOR_MEDIO_VAL}">{TOTAL_MEDIO}</div>
    <div class="label">🟡 Medio</div>
  </div>
  <div class="meta-card">
    <div class="value" style="color:{COLOR_SEGURO_VAL}">{TOTAL_SEGURO}</div>
    <div class="label">🟢 Seguro</div>
  </div>
</div>

{CARDS}

<footer>
  Byte-Shield &nbsp;—&nbsp; Solo librerías estándar de Python &nbsp;|&nbsp;
  Análisis defensivo: sin explotación, sin pentesting activo
</footer>
</body>
</html>"""


def tls_box(nombre: str, info: dict[str, Any]) -> str:
    habilitado = info.get("habilitado", False)
    cls = proto_class(nombre, habilitado)
    status = "ENABLED" if habilitado else "DISABLED"
    return f"""<div class="protocol-box {cls}">
      <div class="proto-name">{nombre}</div>
      <div class="proto-status">{status}</div>
    </div>"""


def render_card(r: dict[str, Any]) -> str:
    nivel = r["nivel"]
    color = COLOR_MAP.get(nivel, "#94a3b8")
    badge = BADGE_MAP.get(nivel, "")
    host = f"{r['host']}:{r['puerto']}"

    proto_boxes = "\n".join(
        tls_box(n, r["tls"].get(n, {}))
        for n in ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]
    )

    hallazgos_html = "\n".join(
        f'<div class="finding-item"><span class="icon riesgo">⚠</span>'
        f'<span class="riesgo">{h}</span></div>'
        for h in r.get("hallazgos", [])
    )
    recom_html = "\n".join(
        f'<div class="finding-item"><span class="icon recom">✔</span>'
        f'<span class="recom">{rec}</span></div>'
        for rec in r.get("recomendaciones", [])
    )

    return f"""<div class="host-card">
  <div class="host-header">
    <h2>[+] {host}</h2>
    <span class="badge" style="background:{color}22;color:{color};border:1px solid {color}">
      {badge} {nivel}
    </span>
  </div>
  <div class="protocol-grid">
    {proto_boxes}
  </div>
  <div class="two-col">
    <div class="findings-section">
      <h3>Riesgos identificados</h3>
      {hallazgos_html}
    </div>
    <div class="findings-section">
      <h3>Recomendaciones</h3>
      {recom_html}
    </div>
  </div>
</div>"""


def generar_html(data: dict[str, Any]) -> str:
    resultados = data.get("resultados", [])
    cards = "\n".join(render_card(r) for r in resultados)

    niveles = [r["nivel"] for r in resultados]
    generado = data.get("generado_en", datetime.datetime.now().isoformat())

    return TEMPLATE.format(
        COLOR_CRITICO=COLOR_CRITICO,
        COLOR_MEDIO=COLOR_MEDIO,
        COLOR_SEGURO=COLOR_SEGURO,
        GENERADO=generado,
        TOTAL_HOSTS=len(resultados),
        TOTAL_CRITICO=niveles.count("CRÍTICO"),
        TOTAL_MEDIO=niveles.count("MEDIO"),
        TOTAL_SEGURO=niveles.count("SEGURO"),
        COLOR_CRITICO_VAL=COLOR_CRITICO,
        COLOR_MEDIO_VAL=COLOR_MEDIO,
        COLOR_SEGURO_VAL=COLOR_SEGURO,
        CARDS=cards,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera reporte HTML desde reporte.json")
    parser.add_argument("--input", default="reporte.json", help="Archivo JSON de entrada")
    parser.add_argument("--output", default="reporte.html", help="Archivo HTML de salida")
    args = parser.parse_args()

    try:
        with open(args.input, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"[!] No se encontró {args.input}")
        sys.exit(1)

    html = generar_html(data)

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(html)

    print(f"[✓] Reporte HTML generado → {args.output}")
    print(f"    Abre con: firefox {args.output}  ó  xdg-open {args.output}")


if __name__ == "__main__":
    main()
