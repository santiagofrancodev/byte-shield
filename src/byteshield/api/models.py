from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    targets: list[str] = Field(..., min_length=1)
    ports: list[int] = Field(default_factory=lambda: [80, 443, 8080, 8443])
    timeout: int = Field(default=5, ge=1, le=120)
    trigger: str = "comando_manual"
    deps: bool = False


class ScanResultItem(BaseModel):
    host: str
    puerto: int
    nivel: str
    tls: dict[str, Any]
    hallazgos: list[str]
    recomendaciones: list[str]
    timestamp: str
    trigger: Optional[str] = None
    deps_map: Optional[dict[str, Any]] = None
    deps_map_reason: Optional[str] = None


class ScanResponse(BaseModel):
    generado_en: str
    herramienta: str
    resultados: list[dict[str, Any]]
