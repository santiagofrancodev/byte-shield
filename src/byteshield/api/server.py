"""FastAPI — POST /scan."""

from __future__ import annotations

import datetime
import logging

try:
    from fastapi import FastAPI, HTTPException
except ImportError as e:
    raise ImportError(
        "FastAPI no está instalado. Usa: pip install byte-shield[api]"
    ) from e

from byteshield.api.models import ScanRequest
from byteshield.pipeline import run_scan

log = logging.getLogger("byteshield.api")

app = FastAPI(title="Byte-Shield API", version="2.0.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    try:
        resultados = run_scan(
            req.targets,
            req.ports,
            verbose=False,
            connect_timeout=req.timeout,
            trigger=req.trigger,
            flags={"deps": req.deps},
            include_deps=True if req.deps else None,
        )
    except Exception as e:
        log.exception("scan failed")
        raise HTTPException(status_code=500, detail=str(e)) from e

    return {
        "generado_en": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "herramienta": "Byte-Shield API",
        "resultados": resultados,
    }


def run() -> None:
    import uvicorn

    uvicorn.run("byteshield.api.server:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    run()
