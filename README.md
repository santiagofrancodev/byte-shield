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

Byte-Shield es un escáner defensivo que audita servidores web desde el exterior (enfoque **Blackbox**), detecta configuraciones TLS inseguras mediante handshakes forzados, clasifica hallazgos por criticidad con referencias legales/técnicas oficiales, y genera reportes accionables.

---

## Arquitectura del Pipeline

```
┌─────────────┐    ┌──────────────┐    ┌──────────────────────┐    ┌─────────────┐
│   INGESTA   │───▶│  MOTOR TLS   │───▶│  MOTOR DE REGLAS     │───▶│  REPORTE    │
│             │    │              │    │  (Compliance-as-Code)│    │             │
│ • Host/IP   │    │ • Handshake  │    │ • ESTANDARES dict    │    │ • JSON      │
│ • Puertos   │    │   forzado    │    │ • Motor híbrido API  │    │ • CSV       │
│ • Validación│    │ • TLS 1.0-1.3│    │   + fallback local   │    │ • HTML      │
│ • Batch     │    │ • Por versión│    │ • Refs RFC/NIST      │    │ • Dashboard │
└─────────────┘    └──────────────┘    └──────────────────────┘    └─────────────┘
```

| Fase | Descripción | Módulo |
|------|-------------|--------|
| **Ingesta** | Validación de targets (IP/dominio), resolución DNS, carga batch desde archivo | `tls_scanner.py` — `validar_objetivo()`, `cargar_targets()` |
| **Motor TLS** | Handshakes forzados por versión (TLS 1.0–1.3) usando `ssl` + `socket` | `tls_scanner.py` — `probar_protocolo_tls()`, `auditar_tls_en_puerto()` |
| **Motor de Reglas** | Compliance-as-Code: diccionario `ESTANDARES_CUMPLIMIENTO` + enriquecimiento híbrido API/local | `tls_scanner.py` — `calcular_criticidad()` |
| **Reporte** | Salida en JSON, CSV, HTML y dashboard web interactivo en tiempo real | `generar_reporte.py`, `dashboard.py` |

---

## Motor de Reglas — Compliance-as-Code

### Fuente de verdad: `ESTANDARES_CUMPLIMIENTO`

Toda la lógica de clasificación reside en un único diccionario estructurado — sin condicionales hardcodeados. Cada entrada de protocolo incluye:

| Campo | Descripción |
|-------|-------------|
| `nivel` | Criticidad base: `CRÍTICO`, `MEDIO` o `SEGURO` |
| `fuente_oficial` | Referencia normativa (RFC, NIST SP) |
| `motivo_tecnico` | Justificación técnica del riesgo |
| `recomendacion_accionable` | Acción concreta para remediar |

```
TLS 1.0  ──▶  CRÍTICO  [RFC 8996, NIST SP 800-52 Rev.2]  POODLE / BEAST / sin AEAD
TLS 1.1  ──▶  CRÍTICO  [RFC 8996, NIST SP 800-52 Rev.2]  Degradación criptográfica
TLS 1.2  ──▶  SEGURO   [RFC 5246,  NIST SP 800-52 Rev.2]  Vigente con cipher suites modernos
            └──▶  MEDIO si TLS 1.3 está ausente   [alerta_sin_tls13]
TLS 1.3  ──▶  SEGURO   [RFC 8446,  NIST SP 800-52 Rev.2]  PFS obligatorio, 1-RTT
```

### Motor híbrido de inteligencia

`calcular_criticidad()` opera en dos modos según la conectividad:

```
                    ┌─────────────────────────────────────┐
                    │     calcular_criticidad()           │
                    └──────────────┬──────────────────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │  _verificar_disponibilidad_api()         │
              │  (ping liviano, cacheado por ejecución)  │
              └────────────┬────────────────┬────────────┘
                           │                │
                    ✅ Online          ❌ Offline / Air-gapped
                           │                │
              ┌────────────▼───┐    ┌───────▼──────────────┐
              │ ciphersuite.info│    │ ESTANDARES_CUMPLIMIENTO│
              │ /api/cs/?tls=* │    │ (diccionario local)    │
              │ timeout: 2s    │    │ sin red requerida      │
              └────────────────┘    └────────────────────────┘
                           │
              ┌────────────▼────────────────────────────────┐
              │  Hallazgo enriquecido:                       │
              │  [RFC 8996 + ciphersuite.info]               │
              │  TLS 1.0 habilitado — ... (N/M cipher suites │
              │  marcadas como inseguras)                    │
              └─────────────────────────────────────────────┘
```

**Comportamiento:**
- **Online:** enriquece cada hallazgo con el conteo de cipher suites inseguras reportadas por `ciphersuite.info`. El timeout estricto de 2 s garantiza que la red nunca bloquea el pipeline.
- **Offline / air-gapped:** usa exclusivamente el diccionario local. La evaluación es idéntica en calidad normativa.
- La disponibilidad de la API se cachea una sola vez por ejecución (`_api_disponible`) para evitar latencia acumulada en escaneos batch.

### Hallazgos con referencia legal

Todos los hallazgos incluyen la fuente normativa en el prefijo:

```
[RFC 8996] TLS 1.0 habilitado — Protocolo obsoleto desde 2018...
[RFC 8996 + ciphersuite.info] TLS 1.1 habilitado — ... (3/12 cipher suites inseguras)
```

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

**Instalación como paquete (recomendado para API, agente y tests):**

```bash
pip install -e ".[api]"          # CLI: byteshield, byteshield-api, openclaw-agent
python -m pytest tests -q
```

**Sin instalación:** `python tls_scanner.py` y `python generar_reporte.py` siguen funcionando (añaden `src/` al path automáticamente).

### Uso como biblioteca

```python
from byteshield.pipeline import run_scan

resultados = run_scan(
    ["example.com"],
    [443],
    verbose=False,
    trigger="comando_manual",
)
```

### API HTTP (FastAPI)

```bash
byteshield-api   # http://0.0.0.0:8000  → POST /scan {"targets":["host"],"ports":[443]}
```

### Agente OpenClaw (superficie mínima)

```bash
openclaw-agent --target 34.45.64.235 --ports 443 --trigger cicd_hook --ci-exit
```

Variables opcionales: `BYTESHIELD_SLACK_WEBHOOK`, `BYTESHIELD_SMTP_*`, `BYTESHIELD_ALERT_EMAIL`.

Ver `ejemplos/targets.json`, `CHANGELOG.md`, `helm/byteshield/`, `terraform/example/`.

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
- Panel de resumen con contadores por nivel
- Exportación directa en **JSON**, **CSV** y **HTML**
- Tema oscuro profesional optimizado para presentaciones

---

## Criterios de Riesgo

| Nivel | Condición | Color |
|-------|-----------|-------|
| **CRÍTICO** | TLS 1.0 o TLS 1.1 habilitado | Rojo |
| **MEDIO** | Solo TLS 1.2 sin TLS 1.3 | Amarillo |
| **SEGURO** | TLS 1.3 activo, sin protocolos obsoletos | Verde |

### Colores por protocolo en reportes y dashboard

| Protocolo | Estado | Color |
|-----------|--------|-------|
| TLS 1.0 / TLS 1.1 | Habilitado | Rojo — peligro activo |
| TLS 1.2 | Habilitado | Amarillo — aceptable, no óptimo |
| TLS 1.3 | Habilitado | Verde — configuración ideal |
| Cualquiera | Deshabilitado | Gris — neutro |

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
        "[RFC 8996] TLS 1.0 habilitado — Protocolo obsoleto desde 2018. Vulnerable a POODLE y BEAST.",
        "[RFC 8996] TLS 1.1 habilitado — Deprecado formalmente. Susceptible a degradación criptográfica."
      ],
      "recomendaciones": [
        "Deshabilitar TLS 1.0 en la configuración del servidor (nginx: ssl_protocols TLSv1.2 TLSv1.3;).",
        "Deshabilitar TLS 1.1 para evitar ataques de degradación criptográfica (POODLE, BEAST)."
      ]
    }
  ]
}
```

---

## Mapeo de Dependencias Criptográficas

Byte-Shield puede descubrir automáticamente infraestructura relacionada con el host auditado e identificar si esas dependencias mantienen el mismo estándar de seguridad TLS.

### ¿Por qué importa?

El "Espejismo del HTTPS": la URL principal puede tener TLS 1.3, pero si llama a subdominios con TLS 1.0, un atacante puede interceptar esos recursos e inyectar código malicioso antes de que llegue al usuario.

### Fuentes de descubrimiento (cero dependencias externas)

```
Host escaneado: empresa.com:443
        │
        ├── [Fuente 1] Certificado TLS — SANs (ssl.getpeercert, stdlib)
        │     └── empresa.com, api.empresa.com, dev.empresa.com, ...
        │
        └── [Fuente 2] Certificate Transparency Logs (urllib.request → crt.sh)
              └── staging.empresa.com, vpn.empresa.com, ...
                         │
                         ▼
              Auto-escaneo TLS de cada dependencia descubierta
                         │
                         ▼
              "dev.empresa.com — CRÍTICO — TLS 1.0 habilitado"
```

| Fuente | Tecnología | Requiere red |
|--------|-----------|--------------|
| SANs del certificado | `ssl.getpeercert()` (stdlib) | Solo al host objetivo |
| Certificate Transparency | `urllib.request` → `crt.sh` | Internet (con fallback offline) |

**Comportamiento offline:** si `crt.sh` no responde, se usan únicamente los SANs del certificado TLS. El análisis continúa sin errores.

El botón "Mapa de Dependencias" aparece en el dashboard tras completar un escaneo y analiza automáticamente hasta 10 dependencias descubiertas.

---

## Análisis con Inteligencia Artificial

Byte-Shield puede enriquecer los hallazgos con un análisis ejecutivo generado por IA (Gemini o OpenAI), visible directamente en el dashboard tras el escaneo.

### Configuración

```bash
# Proveedor: gemini (default) u openai
export BYTESHIELD_AI_KEY="tu_api_key_aqui"
export BYTESHIELD_AI_PROVIDER="gemini"   # o "openai"

python3 dashboard.py --port 8080
```

| Variable | Descripción | Default |
|----------|-------------|---------|
| `BYTESHIELD_AI_KEY` | API key del proveedor (requerida) | — |
| `BYTESHIELD_AI_PROVIDER` | `gemini` o `openai` | `gemini` |

**Comportamiento:**
- Sin `BYTESHIELD_AI_KEY`: el botón "Análisis IA" retorna un error descriptivo — el resto del dashboard funciona con normalidad.
- Con clave: envía los hallazgos del escaneo al modelo y muestra un resumen ejecutivo con impacto de negocio, riesgos priorizados y plan de acción.
- Sin dependencias externas: usa `urllib.request` (stdlib), igual que el motor híbrido de `ciphersuite.info`.
- Timeout de 20 s para no bloquear el pipeline.

---

## Envío de Reporte por Email

El reporte completo (HTML como cuerpo + JSON adjunto) se puede enviar directamente desde el dashboard.

### Configuración

```bash
export BYTESHIELD_SMTP_HOST="smtp.gmail.com"   # default
export BYTESHIELD_SMTP_PORT="587"              # default
export BYTESHIELD_SMTP_USER="tu_cuenta@gmail.com"
export BYTESHIELD_SMTP_PASS="tu_app_password"

python3 dashboard.py --port 8080
```

| Variable | Descripción | Default |
|----------|-------------|---------|
| `BYTESHIELD_SMTP_HOST` | Servidor SMTP | `smtp.gmail.com` |
| `BYTESHIELD_SMTP_PORT` | Puerto SMTP | `587` |
| `BYTESHIELD_SMTP_USER` | Email del remitente (requerido) | — |
| `BYTESHIELD_SMTP_PASS` | Contraseña de app SMTP (requerida) | — |

> Para Gmail, genera una **App Password** en tu cuenta Google (Seguridad → Verificación en 2 pasos → Contraseñas de aplicaciones).

**Sin dependencias externas:** usa `smtplib` + `email.mime` (stdlib Python).

---

## Integración CI/CD

El scanner retorna exit codes que permiten bloquear despliegues con protocolos inseguros (**Shift Left Security**):

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
├── tls_scanner.py            # Motor principal — CLI + Compliance-as-Code
├── generar_reporte.py        # Generador de reportes HTML
├── dashboard.py              # Dashboard web para demo en vivo
├── static/
│   ├── index.html            # Frontend del dashboard
│   ├── style.css             # Estilos (dark theme)
│   └── app.js                # Lógica frontend (vanilla JS + SSE)
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
| Motor de reglas | Diccionario `ESTANDARES_CUMPLIMIENTO` + `urllib.request` (stdlib) |
| Mapeo de dependencias | `ssl.getpeercert()` (SANs) + `urllib.request` → crt.sh (stdlib) |
| Análisis con IA | `urllib.request` → Gemini 2.0 Flash / GPT-4o-mini (stdlib) |
| Envío de email | `smtplib` + `email.mime` (stdlib) |
| Reportes JSON/CSV | `json` + `csv` (stdlib) |
| Dashboard web | `http.server` + `threading` (stdlib) |
| Streaming tiempo real | Server-Sent Events (SSE) via `http.server` |
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
