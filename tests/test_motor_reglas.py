from byteshield.motor_reglas import (
    calcular_criticidad,
    load_estandares,
    should_map_dependencies,
)
from byteshield.report_router import resolve_audiences


def test_load_estandares():
    d = load_estandares()
    assert "TLS 1.0" in d
    assert d["TLS 1.0"]["nivel"] == "CRÍTICO"


def test_calcular_tls10_critico():
    tls = {
        "TLS 1.0": {"habilitado": True, "obsoleto": True},
        "TLS 1.1": {"habilitado": False, "obsoleto": True},
        "TLS 1.2": {"habilitado": True, "obsoleto": False},
        "TLS 1.3": {"habilitado": True, "obsoleto": False},
    }
    nivel, hallazgos, _ = calcular_criticidad(tls)
    assert nivel == "CRÍTICO"
    assert hallazgos


def test_should_map_critical():
    assert should_map_dependencies("CRÍTICO", "cron_schedule", {}) is True


def test_should_map_medio_cicd():
    assert should_map_dependencies("MEDIO", "cicd_hook", {}) is True


def test_should_map_medio_cron():
    assert should_map_dependencies("MEDIO", "cron_schedule", {}) is False


def test_resolve_audiences_critical():
    a = resolve_audiences("cron_schedule", "CRÍTICO")
    assert "cicd" in a and "ejecutivo" in a


def test_resolve_audiences_cron_ok():
    a = resolve_audiences("cron_schedule", "SEGURO")
    assert a == ["gestor"]
