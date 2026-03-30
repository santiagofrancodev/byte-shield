"""
Byte-Shield — auditoría TLS defensiva (paquete importable).
"""

from byteshield.dependencies import mapear_dependencias
from byteshield.ia import analizar_con_ia
from byteshield.ingesta import (
    cargar_targets,
    discover_cloudrun_services,
    load_static_inventory,
    load_static_inventory_for_host,
    validar_objetivo,
)
from byteshield.motor_reglas import (
    NIVEL_CRITICO,
    NIVEL_MEDIO,
    NIVEL_SEGURO,
    calcular_criticidad,
    get_max_severity,
    load_estandares,
    should_map_dependencies,
)
from byteshield.motor_tls import (
    CONNECT_TIMEOUT,
    CRTSH_TIMEOUT,
    DEFAULT_PORTS,
    TLS_PROTOCOLS,
    auditar_tls_en_puerto,
    escanear_puerto,
    escanear_puertos,
    probar_protocolo_tls,
    reset_api_cache,
)
from byteshield.pipeline import auditar_host, run_scan
from byteshield.reporting import exportar_json

__all__ = [
    "CONNECT_TIMEOUT",
    "CRTSH_TIMEOUT",
    "DEFAULT_PORTS",
    "TLS_PROTOCOLS",
    "NIVEL_CRITICO",
    "NIVEL_MEDIO",
    "NIVEL_SEGURO",
    "validar_objetivo",
    "cargar_targets",
    "load_static_inventory",
    "load_static_inventory_for_host",
    "discover_cloudrun_services",
    "escanear_puerto",
    "escanear_puertos",
    "probar_protocolo_tls",
    "auditar_tls_en_puerto",
    "reset_api_cache",
    "load_estandares",
    "calcular_criticidad",
    "get_max_severity",
    "should_map_dependencies",
    "mapear_dependencias",
    "analizar_con_ia",
    "auditar_host",
    "run_scan",
    "exportar_json",
]

__version__ = "2.0.0"
