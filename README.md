# Byte-Shield

> **Motor de Auditoría Proactiva de Configuración TLS para Infraestructuras Críticas**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat&logo=python&logoColor=white)
![Dependencias](https://img.shields.io/badge/Dependencias-0_(stdlib)-22c55e?style=flat)
![Licencia](https://img.shields.io/badge/Licencia-MIT-blue?style=flat)
![Estado](https://img.shields.io/badge/Estado-MVP_Funcional-22d3ee?style=flat)

**Byte Security Group** — *"Defendemos lo que no se ve, para que el mundo nunca deje de aprender"*

---

## Problema

Muchos servidores web tienen HTTPS activo pero configuraciones TLS inseguras. Versiones obsoletas como **TLS 1.0** y **TLS 1.1** exponen a ataques de interceptación, degradación criptográfica (POODLE, BEAST) y manipulación de tráfico. **No basta con "tener HTTPS"** — hay que validar que la configuración cumpla criterios mínimos de seguridad.

## Solución

Byte-Shield es un escáner defensivo que audita servidores web desde el exterior (enfoque **Blackbox**), detecta configuraciones TLS inseguras mediante handshakes forzados, clasifica hallazgos por criticidad y genera reportes con recomendaciones accionables.

---

## Arquitectura del Pipeline

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐
│   INGESTA   │───▶│  MOTOR TLS   │───▶│   REGLAS     │───▶│  REPORTE    │
│             │    │              │    │              │    │             │
│ • Host/IP   │    │ • Handshake  │    │ • Criticidad │    │ • JSON      │
│ • Puertos   │    │   forzado    │    │ • Hallazgos  │    │ • CSV       │
│ • Validación│    │ • TLS 1.0-1.3│    │ • Remediación│    │ • HTML      │
│ • Batch     │    │ • Por versión│    │              │    │ • Dashboard │
└─────────────┘    └──────────────┘    └──────────────┘    └─────────────┘
```

| Fase | Descripción | Módulo |
|------|-------------|--------|
| **Ingesta** | Validación de targets (IP/dominio), resolución DNS, carga batch desde archivo | `tls_scanner.py` — funciones `validar_objetivo()`, `cargar_targets()` |
| **Motor TLS** | Handshakes forzados por versión (TLS 1.0, 1.1, 1.2, 1.3) usando `ssl` + `socket` | `tls_scanner.py` — funciones `probar_protocolo_tls()`, `auditar_tls_en_puerto()` |
| **Reglas** | Clasificación de criticidad (CRÍTICO/MEDIO/SEGURO) con hallazgos y remediación | `tls_scanner.py` — función `calcular_criticidad()` |
| **Reporte** | Salida en JSON, CSV, HTML y dashboard web interactivo | `generar_reporte.py`, `dashboard.py` |

---

## Inicio Rápido

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/byte-shield.git
cd byte-shield

# 2. Escanear un servidor (CLI)
python3 tls_scanner.py --target 34.45.64.235 --ports 443

# 3. Lanzar el dashboard web
python3 dashboard.py --port 8080
# Abrir http://localhost:8080
```

**No se requiere `pip install`.** Todo funciona con la biblioteca estándar de Python 3.10+.

---

## Uso por CLI

### Escaneo individual

```bash
python3 tls_scanner.py --target 34.45.64.235
```

### Puertos específicos

```bash
python3 tls_scanner.py --target 34.45.64.235 --ports 443 8443
```

### Modo batch (múltiples servidores)

```bash
python3 tls_scanner.py --targets lista.txt --output reporte.json
```

Donde `lista.txt` contiene un host por línea:

```
34.45.64.235
api.example.com
192.168.1.100
```

### Generar reporte HTML

```bash
python3 generar_reporte.py --input reporte.json --output reporte.html
```

### Flags disponibles

| Flag | Descripción | Default |
|------|-------------|---------|
| `--target HOST` | Host o IP individual | — |
| `--targets ARCHIVO` | Archivo con lista de hosts | — |
| `--ports P [P ...]` | Puertos a escanear | `80 443 8080 8443` |
| `--output ARCHIVO` | Exportar resultado a JSON | — |
| `--timeout SEG` | Timeout de conexión | `5` |

---

## Dashboard Web

El dashboard permite ejecutar análisis en tiempo real desde una interfaz web interactiva.

```bash
python3 dashboard.py --port 8080
```

### Exponer con ngrok (para demo en vivo)

```bash
ngrok http 8080
```

### Funcionalidades

- Formulario para ingresar targets individuales o en modo batch
- Resultados en **tiempo real** (SSE — Server-Sent Events)
- Tarjetas visuales por servidor con estado TLS y badges de criticidad
- Panel de resumen con contadores
- Exportación directa en **JSON**, **CSV** y **HTML**
- Tema oscuro profesional optimizado para presentaciones

---

## Criterios de Riesgo

| Nivel | Condición | Color |
|-------|-----------|-------|
| **CRÍTICO** | TLS 1.0 o TLS 1.1 habilitado | Rojo |
| **MEDIO** | Solo TLS 1.2 sin TLS 1.3 | Amarillo |
| **SEGURO** | TLS 1.3 activo, sin protocolos obsoletos | Verde |

---

## Formato de Salida JSON

```json
{
  "generado_en": "2026-03-28T05:00:00+00:00",
  "herramienta": "tls_scanner.py — CloudLabs Hackathon",
  "resultados": [
    {
      "host": "34.45.64.235",
      "puerto": 443,
      "nivel": "CRÍTICO",
      "tls": {
        "TLS 1.0": { "habilitado": true,  "obsoleto": true  },
        "TLS 1.1": { "habilitado": true,  "obsoleto": true  },
        "TLS 1.2": { "habilitado": true,  "obsoleto": false },
        "TLS 1.3": { "habilitado": false, "obsoleto": false }
      },
      "hallazgos": [
        "TLS 1.0 habilitado — protocolo obsoleto desde 2018 (RFC 8996).",
        "TLS 1.1 habilitado — deprecado formalmente (RFC 8996)."
      ],
      "recomendaciones": [
        "Deshabilitar TLS 1.0 en la configuración del servidor.",
        "Deshabilitar TLS 1.1 para evitar ataques de degradación criptográfica."
      ]
    }
  ]
}
```

---

## Integración CI/CD

El scanner retorna exit codes que permiten bloquear despliegues con protocolos inseguros:

| Exit Code | Significado |
|-----------|-------------|
| `0` | Todos los servidores seguros |
| `1` | Hallazgos de nivel MEDIO |
| `2` | Hallazgos de nivel CRÍTICO |

Ejemplo en un pipeline:

```bash
python3 tls_scanner.py --target $SERVER_IP --ports 443 --output reporte.json
if [ $? -eq 2 ]; then
  echo "BLOQUEADO: Protocolos TLS obsoletos detectados"
  exit 1
fi
```

---

## Estructura del Proyecto

```
byte-shield/
├── README.md                 # Este archivo
├── .gitignore                # Exclusiones de Python
├── requirements.txt          # Sin dependencias externas
├── tls_scanner.py            # Motor principal — CLI
├── generar_reporte.py        # Generador de reportes HTML
├── dashboard.py              # Dashboard web para demo en vivo
├── static/
│   ├── index.html            # Frontend del dashboard
│   ├── style.css             # Estilos (dark theme)
│   └── app.js                # Lógica frontend (vanilla JS)
├── examples/
│   ├── reporte.json          # Evidencia real del servidor auditado
│   └── reporte.html          # Reporte HTML generado
└── reports/
    └── .gitkeep              # Carpeta para reportes generados
```

---

## Stack Técnico

| Componente | Tecnología |
|------------|------------|
| Lenguaje | Python 3.10+ |
| Handshakes TLS | `ssl` + `socket` (stdlib) |
| Reportes JSON/CSV | `json` + `csv` (stdlib) |
| Dashboard web | `http.server` + `threading` (stdlib) |
| Reportes HTML | Template string con CSS embebido |
| Frontend | HTML5 + CSS3 + JavaScript vanilla |
| Dependencias externas | **Ninguna** |

---

## Equipo

**Byte Security Group** — Operación Defensa Web

Proyecto desarrollado para el reto *"Sistema de Análisis de Configuración TLS y Riesgo de Exposición en Servicios Web"* del programa de Ciberseguridad.

**CloudLabs Learning × Talento Tech Hackathon 2026**

---

## Licencia

MIT
