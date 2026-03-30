# Changelog

## 2.0.0 — 2026-03-29

### Added
- Paquete instalable `byte-shield` (`src/byteshield`): ingesta, motor TLS, motor de reglas con `compliance/ESTANDARES_CUMPLIMIENTO.json`, pipeline, IA, API FastAPI opcional.
- `report_router`, `ai_enrichment`, `reporte_html`, `reporte_pdf` (opcional).
- `openclaw_agent`: disparadores, acciones, orquestador (`openclaw-agent`).
- Scripts de consola: `byteshield`, `byteshield-api`, `openclaw-agent`.
- Docker, GitHub Actions CI, Helm chart mínimo, ejemplo Terraform.
- Pruebas unitarias (`pytest`).

### Changed
- `tls_scanner.py` y `generar_reporte.py` son fachadas que añaden `src/` al path e importan el paquete.
