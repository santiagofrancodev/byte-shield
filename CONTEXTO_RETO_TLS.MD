# CONTEXTO DEL RETO: Operación Defensa Web — Análisis TLS y Riesgo de Exposición

> **Uso:** Este archivo es contexto de referencia para el agente de desarrollo en el IDE. Debe usarse como fuente de verdad sobre los requisitos, restricciones y filosofía del reto.

---

## 1. Visión y Filosofía del Reto

El reto no pide únicamente un escáner TLS. Pide **convertir comportamiento digital en decisiones**. La consigna central es:

> *"¿Pueden los datos contar una historia en tiempo real? Este no es un reto para mirar dashboards; es un reto para convertir comportamiento digital en decisiones."*

Los tres pilares de evaluación no técnicos son:
- **Adaptabilidad** — La solución debe responder a distintos objetivos y contextos.
- **Simplicidad** — La experiencia de análisis debe ser natural y accionable.
- **Visión de negocio** — Los hallazgos técnicos deben traducirse en valor comprensible para perfiles no técnicos.

La clave está en **convertir datos en una experiencia de análisis más natural y accionable**, no solo en mostrar resultados crudos de herramientas.

---

## 2. Información General

| Campo | Detalle |
|---|---|
| Título | Operación Defensa Web: Análisis de Configuración TLS |
| Organizador | CloudLabs TALENTO |
| Tiempo disponible | 8 horas (MVP) |
| Enfoque | Ciberseguridad **defensiva** — auditoría, diagnóstico y recomendación |
| Prohibido | Explotación de vulnerabilidades, pentesting activo, DoS, interceptación de tráfico real |

### Objetivo Central del MVP

Construir un pipeline end-to-end que:
1. Reciba uno o varios dominios / IPs como entrada.
2. Ejecute análisis TLS sobre cada objetivo.
3. Clasifique los hallazgos por criticidad.
4. Genere un reporte claro con recomendaciones accionables de hardening.

---

## 3. El Problema: "El Espejismo del HTTPS"

La presencia del candado de seguridad (HTTPS) no garantiza protección real. Persisten riesgos por:

- Habilitación de **TLS 1.0 y TLS 1.1** (protocolos obsoletos, susceptibles a ataques de degradación criptográfica).
- Suites de cifrado débiles por razones de **compatibilidad heredada**.
- Falta de visibilidad centralizada sobre el estado de múltiples dominios.
- Ausencia de reportes comprensibles para equipos técnicos y de gestión.

### Preguntas que la solución debe responder

- ¿Qué versiones de TLS están habilitadas en cada servidor?
- ¿Qué servicios permiten configuraciones obsoletas o inseguras?
- ¿Cuáles hallazgos representan mayor criticidad?
- ¿Qué acciones deben ejecutarse para fortalecer la configuración?
- ¿Cómo comparar el nivel de exposición entre varios dominios o entornos?

---

## 4. Arquitectura del MVP (Pipeline de 4 Fases)

```
[Entrada] → [Motor TLS] → [Motor de Reglas] → [Reporte / Visualización]
```

### Fase 1 — Ingesta y Validación

- Aceptar dominios, IPs o listas de servidores.
- Validar formato de entrada.
- Manejar errores: timeouts, puertos cerrados, dominios no resolubles.
- Soportar análisis individual y por lote.

### Fase 2 — Motor TLS

Debe detectar **como mínimo**:
- Versiones de TLS habilitadas (1.0, 1.1, 1.2, 1.3).
- Presencia de protocolos obsoletos.
- Configuraciones inseguras o no recomendadas.
- Estado general del servidor evaluado.

Se valorará adicionalmente:
- Puertos asociados al servicio analizado.
- Inconsistencias entre servidores analizados.
- Nivel de exposición relativo por host.
- Clasificación de criticidad por hallazgo.

### Fase 3 — Motor de Evaluación y Reglas

Traduce hallazgos técnicos crudos a inteligencia accionable:

| Nivel | Descripción | Ejemplo |
|---|---|---|
| **Base** (Datos de Red) | Extracción técnica | Puerto 443 activo. TLS 1.0 habilitado. |
| **Medio** (Clasificación) | Severidad y contexto | Severidad ALTA. Riesgo de downgrade attack. |
| **Cúspide** (Negocio) | Acción sugerida | Restringir a TLS 1.2/1.3. Riesgo de degradación criptográfica. |

Recomendaciones que debe ser capaz de generar:
- Deshabilitar TLS 1.0 y TLS 1.1.
- Restringir a versiones modernas (TLS 1.2 / TLS 1.3).
- Revisar configuraciones heredadas por compatibilidad.
- Priorizar remediación en servidores con mayor exposición.
- Estandarizar configuraciones entre ambientes.

### Fase 4 — Reporte y Visualización

Mostrar como mínimo por servidor:
- Servidor analizado.
- Versiones de TLS detectadas.
- Hallazgos inseguros identificados.
- Nivel de criticidad / severidad.
- Recomendaciones específicas.

**Formato de salida esperado (ejemplo mínimo):**
```
Servidor:        api.example.com
TLS 1.0:         ENABLED   ← CRÍTICO
TLS 1.1:         ENABLED   ← ALTO
TLS 1.2:         ENABLED   ← OK
TLS 1.3:         DISABLED  ← RECOMENDADO

Riesgo:          Exposición a protocolos obsoletos
Recomendación:   Deshabilitar TLS 1.0 y TLS 1.1. Habilitar TLS 1.3.
```

Vista consolidada (comparación entre servidores) es un diferencial valorado.

---

## 5. Arsenal Técnico

### Lenguajes permitidos
- Python, Node.js, Bash

### Motores de escaneo sugeridos
- `openssl` (integración directa o vía subprocess)
- `testssl.sh`
- `nmap`
- `sslscan`
- **OpenClaw** ← integración en evaluación para esta solución

### Librerías de apoyo
- `socket`, `ssl`, `subprocess`, `requests`

### Interfaces opcionales
- CLI estructurada, HTML simple, Streamlit, dashboard básico

### Persistencia opcional
- JSON, CSV, HTML, PDF

---

## 6. Objetivo de Prueba Definido por los Organizadores

| Campo | Valor |
|---|---|
| IP objetivo | `34.45.64.235` |
| Puerto | `443` |
| Servicio | HTTPS (Nginx) |

> Este es el servidor de referencia para la demo en vivo. La solución debe poder analizarlo y generar un reporte completo sobre él.

---

## 7. Entregables Finales

| Archivo | Descripción |
|---|---|
| **El Motor** | Repositorio o script técnico con código limpio, README y ejemplos de ejecución |
| **La Inteligencia** | Reporte estructurado (JSON, CSV, HTML o PDF) con hallazgos y recomendaciones |
| **El Demo** | Prueba funcional ejecutable en vivo durante la presentación final (5 minutos) |

### Estructura esperada del repositorio
```
/
├── README.md               # Descripción, dependencias, pasos de ejecución
├── src/
│   ├── ingesta.py          # Fase 1: Validación de entrada
│   ├── motor_tls.py        # Fase 2: Análisis TLS
│   ├── motor_reglas.py     # Fase 3: Clasificación y recomendaciones
│   └── reporte.py          # Fase 4: Generación de salida
├── ejemplos/
│   ├── entrada.txt         # Ejemplo de lista de dominios
│   └── salida.json         # Ejemplo de reporte generado
└── reportes/               # Salidas generadas
```

---

## 8. Rúbrica de Evaluación

| Criterio | Descripción |
|---|---|
| Funcionamiento end-to-end | Flujo completo: entrada → análisis → hallazgos → reporte |
| Calidad del análisis técnico | Correcta identificación de configuraciones inseguras |
| Priorización del riesgo | Hallazgos clasificados y útiles para la toma de decisiones |
| Claridad del reporte | Comprensible para perfiles técnicos y de gestión |
| Estructura y documentación | Código limpio, organizado, con instrucciones claras |
| Presentación y storytelling | Explicación del problema, solución y valor de negocio generado |

---

## 9. Estructura del Pitch Final (5 minutos)

1. El problema de seguridad identificado.
2. El enfoque técnico utilizado para el análisis.
3. La herramienta desarrollada (demo en vivo).
4. Los resultados obtenidos sobre el servidor objetivo.
5. Las recomendaciones de remediación generadas.
6. El valor de la solución para fortalecer la seguridad de servicios web.

---

## 10. Notas para el Agente de Desarrollo

- **Priorizar confiabilidad sobre complejidad.** Una solución funcional, clara y explicable pesa más que una excesivamente sofisticada.
- **OpenClaw** está siendo evaluado como motor de análisis conversacional / accionable. Su integración debe alinearse con la Fase 3 (Motor de Reglas) y la Fase 4 (Reporte), dado que su fortaleza está en convertir datos técnicos crudos en narrativa de decisión.
- El diferencial de esta solución es la **experiencia de análisis natural y accionable** — no solo detección, sino storytelling de seguridad.
- Validar resultados contra el servidor objetivo `34.45.64.235:443` antes de la demo.
- Documentar supuestos y decisiones de diseño en el README.

---

## 11. Integración de OpenClaw en Byte-Shield

### ¿Qué es OpenClaw?

OpenClaw (anteriormente conocido como Clawdbot y Moltbot) es un **agente de IA autónomo de código abierto** creado por el desarrollador austriaco Peter Steinberger. Deriva de un asistente llamado "Clawd" (referencia directa a Claude de Anthropic). Permite crear agentes capaces de completar tareas complejas de múltiples pasos de forma autónoma: navegar la web, ejecutar scripts, manejar correos y flujos de trabajo.

En términos prácticos: OpenClaw actúa como un **"empleado digital"** — recibe un disparador, interpreta la situación, toma decisiones y ejecuta acciones encadenadas sin intervención humana.

### Byte-Shield MVP v1 vs MVP v2 con OpenClaw

| Dimensión | MVP v1 (sin OpenClaw) | MVP v2 (con OpenClaw) |
|---|---|---|
| Activación | Manual — alguien ejecuta el script | Autónoma — agente responde a disparadores |
| Alcance | Un escaneo por ejecución | Monitoreo continuo, multi-servidor |
| Respuesta | Genera reporte, espera acción humana | Toma acciones: alerta, bloquea pipeline, crea ticket |
| Valor de negocio | Herramienta de auditoría | Agente de seguridad autónomo |

### Arquitectura de Integración (diagrama funcional)

```
┌─────────────────────────────────────────────────────────────────┐
│           Byte-Shield + OpenClaw — agente TLS autónomo          │
└─────────────────────────────────────────────────────────────────┘

DISPARADORES
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐
│ Cron schedule│  │  CI/CD hook  │  │   Webhook /  │  │  Comando por mensaje │
│ Scan diario/ │  │ Post-deploy  │  │   evento     │  │ "Escanea cloudlabs   │
│ semanal      │  │ en Cloud Run │  │ Cambio cert  │  │  ahora"              │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘
       └──────────────────┴──────────────────┴───────────────────┘
                                    │
                                    ▼
         ┌──────────────────────────────────────────────┐
         │       Agente OpenClaw — orquestador central   │
         │  Interpreta disparadores · ejecuta            │
         │  tls_scanner.py · toma decisiones ·           │
         │  genera acciones                              │
         └──────────────────────┬───────────────────────┘
                                │
                                ▼
         ┌──────────────────────────────────────────────┐
         │     Byte-Shield — motor TLS (código base)    │
         │  tls_scanner.py · Compliance-as-Code ·       │
         │  ESTANDARES_CUMPLIMIENTO · JSON output       │
         └──────────────────────┬───────────────────────┘
                                │
              ACCIONES AUTÓNOMAS SEGÚN HALLAZGOS
       ┌──────────┬─────────────┬────────────────┬──────────────┐
       ▼          ▼             ▼                ▼              
┌──────────┐ ┌──────────┐ ┌──────────┐  ┌──────────────┐
│  Alerta  │ │ Reporte  │ │  Ticket  │  │  Bloqueo     │
│ CRÍTICA  │ │automático│ │automático│  │  CI/CD       │
│WhatsApp/ │ │HTML/JSON/│ │Jira /    │  │Exit code 2 → │
│Slack/    │ │CSV →     │ │GitHub    │  │pipeline      │
│email     │ │equipo    │ │Issue     │  │detenido      │
│TLS 1.0  │ │          │ │con recs. │  │              │
└──────────┘ └──────────┘ └──────────┘  └──────────────┘

VALOR DIRECTO:
Monitorea Cloud Run · api.cloudlabs.com · staging · microservicios
— sin intervención humana
```

### Posicionamiento de Riesgo y Ventaja Defensiva

El riesgo real de OpenClaw está en concederle **acceso sin particionar** a sistemas sensibles (correos, cuentas bancarias, credenciales). En el diseño de Byte-Shield este riesgo se elimina **por construcción**:

> **El agente OpenClaw solo tiene permiso para llamar a `tls_scanner.py`.**  
> No toca credenciales, bases de datos, ni sistemas internos.  
> Acceso mínimo → superficie de ataque mínima.

Esto convierte la limitación de seguridad de OpenClaw en el **argumento diferenciador** de la propuesta: ciberseguridad defensiva con agente de acceso mínimo.

### Flujo de Integración Técnica (implementación)

OpenClaw invoca Byte-Shield como subproceso y consume el JSON de salida:

```python
# Ejemplo conceptual — OpenClaw llama a tls_scanner.py
import subprocess
import json

def run_tls_scan(target: str) -> dict:
    result = subprocess.run(
        ["python", "tls_scanner.py", "--target", target, "--output", "json"],
        capture_output=True,
        text=True,
        timeout=60
    )
    return json.loads(result.stdout)

def decide_action(scan_result: dict) -> list[str]:
    actions = []
    if scan_result.get("tls_1_0") == "ENABLED":
        actions.append("send_critical_alert")
        actions.append("block_cicd_pipeline")   # exit code 2
        actions.append("create_jira_ticket")
    elif scan_result.get("tls_1_1") == "ENABLED":
        actions.append("send_high_alert")
        actions.append("generate_report")
    return actions
```

### Disparadores Soportados por el Agente

| Disparador | Descripción | Caso de uso concreto |
|---|---|---|
| `cron_schedule` | Scan diario o semanal programado | Monitoreo continuo de todos los dominios |
| `cicd_hook` | Post-deploy en Cloud Run | Validar TLS antes de que el servicio llegue a producción |
| `webhook_evento` | Cambio de certificado detectado | Escanear inmediatamente ante rotación de cert |
| `comando_mensaje` | Lenguaje natural vía chat | `"Escanea api.cloudlabs.com ahora"` |

### Acciones Autónomas que Puede Ejecutar el Agente

| Acción | Condición de disparo | Canal |
|---|---|---|
| **Alerta CRÍTICA** | TLS 1.0 detectado | WhatsApp / Slack / email |
| **Reporte automático** | Cualquier hallazgo | HTML, JSON o CSV enviado al equipo |
| **Ticket automático** | Hallazgo ALTO o CRÍTICO | Jira / GitHub Issue con recomendaciones |
| **Bloqueo CI/CD** | TLS inseguro en pre-producción | Exit code 2 → pipeline detenido |

### Valor de Negocio para CloudLabs (argumento de pitch)

El agente monitorea de forma continua y autónoma:
- Todos los microservicios en **Cloud Run**
- El dominio `api.cloudlabs.com`
- Ambientes de **staging y producción**

Sin intervención humana. Cada deployment es verificado. Si hay TLS 1.0 activo, el pipeline se detiene antes de llegar a producción — exactamente el objetivo declarado: **"deployments seguros sin interrupciones"**.

---

## 12. Estructura de Repositorio Actualizada (con OpenClaw)

```
/
├── README.md
├── src/
│   ├── ingesta.py              # Fase 1: Validación de entrada
│   ├── tls_scanner.py          # Fase 2: Motor TLS (núcleo Byte-Shield)
│   ├── motor_reglas.py         # Fase 3: Clasificación y recomendaciones
│   ├── report_router.py        # Fase 4a: Decisor de formato y audiencia  ← NUEVO
│   ├── ai_enrichment.py        # Fase 4b: Enriquecimiento IA por perfil    ← NUEVO
│   ├── reporte.py              # Fase 4c: Generación de salida (HTML/JSON/CSV/PDF)
│   └── openclaw_agent/
│       ├── agent.py            # Orquestador OpenClaw
│       ├── triggers.py         # Manejo de disparadores (cron, webhook, CI/CD)
│       └── actions.py          # Acciones autónomas (alertas, tickets, bloqueos)
├── compliance/
│   └── ESTANDARES_CUMPLIMIENTO.json
├── ejemplos/
│   ├── entrada.txt
│   └── salida.json
└── reportes/
```

---

## 13. Sistema de Decisión de Reportes — Diseño Completo

### Principio central

El sistema no genera un solo reporte y lo envía a todos. **Genera un reporte diferente para cada audiencia**, reformulando el mismo hallazgo técnico en el lenguaje, formato y canal que corresponde a quien lo recibe. La IA no inventa hechos — reformula el lenguaje y el nivel de abstracción.

### Pipeline de decisión: `decide_report(scan_result, context)`

El motor de reportes resuelve tres preguntas en orden antes de generar cualquier salida:

```
[Hallazgo crudo del escaneo TLS]
          ↓
  1. ¿Quién recibe?       → identifica perfil de audiencia
  2. ¿Qué formato?        → asigna tipo de documento
  3. ¿Qué le dice la IA?  → reformula el lenguaje
          ↓
  [Reporte enriquecido + canal de envío]
```

---

### Pregunta 1 — ¿Quién recibe? (perfiles de audiencia)

El perfil se deduce del **disparador** que originó el escaneo, no de una configuración manual:

| Disparador | Perfil asignado | Lógica |
|---|---|---|
| `cicd_hook` (post-deploy) | CI/CD (máquina) | Nadie lo lee, lo procesa el pipeline |
| `comando_mensaje` ("escanea X") | Técnico | Quien pidió el escaneo lo recibe |
| `cron_schedule` (diario/semanal) | Gestor | Reporte periódico de estado |
| `severidad CRÍTICA` (cualquier origen) | Todos en paralelo | Regla de emergencia, sin excepción |
| `webhook_evento` (cambio de cert) | Técnico + Gestor | Afecta operación y cumplimiento |

---

### Pregunta 2 — ¿Qué formato? (por perfil)

| Perfil | Formato nativo | Características |
|---|---|---|
| **CI/CD** | JSON + exit code | Sin prosa. Solo campos legibles por máquina. Exit 0 = seguro, exit 2 = bloquear |
| **Técnico** | HTML o JSON | Con snippets de configuración exactos, referencias RFC/CVE, comandos de validación |
| **Gestor** | PDF o HTML firmable | Sin jerga técnica, con fechas límite y responsable de remediación |
| **Ejecutivo** | PDF ejecutivo (≤2 páginas) | Semáforo ROJO/AMARILLO/VERDE, impacto regulatorio, una sola acción recomendada |

---

### Pregunta 3 — ¿Qué le dice la IA? (reformulación por perfil)

El mismo hallazgo `TLS 1.0 ENABLED · puerto 443 · host 34.45.64.235 · severidad CRÍTICA` produce cuatro mensajes distintos:

**Para CI/CD (máquina):**
```json
{
  "exit_code": 2,
  "host": "34.45.64.235",
  "findings": [{"protocol": "TLS_1_0", "severity": "CRITICAL", "port": 443}],
  "action": "BLOCK",
  "timestamp": "2024-01-15T14:32:00Z"
}
```

**Para técnico (Dev / SecEng):**
> Host `34.45.64.235:443` tiene TLS 1.0 activo. Vulnerable a POODLE (CVE-2014-3566).
> Remediación en Nginx: editar `/etc/nginx/nginx.conf` → `ssl_protocols TLSv1.2 TLSv1.3;`
> Verificar con: `openssl s_client -connect 34.45.64.235:443 -tls1`

**Para gestor (líder técnico):**
> Se detectó una configuración de seguridad crítica en el servicio `api.cloudlabs.com`.
> El protocolo de cifrado habilitado está obsoleto desde 2015 y representa un riesgo de
> interceptación de datos. Se requiere intervención del equipo de infraestructura antes
> del próximo deployment programado. Responsable sugerido: equipo DevOps.

**Para ejecutivo (CISO / directivo):**
> **Riesgo:** ALTO — Servicio expuesto a interceptación de datos en tránsito.
> **Impacto regulatorio:** Incumplimiento potencial PCI-DSS sección 6.5.4 y GDPR Art. 32.
> **Semáforo:** 🔴 CRÍTICO
> **Acción requerida:** Actualización de configuración de seguridad. Ventana recomendada: 24 horas.

---

### Regla de severidad crítica

Cuando cualquier hallazgo tiene severidad `CRÍTICA`, los cuatro perfiles se notifican **simultáneamente en paralelo**, sin esperar confirmación de ninguno. Para `ALTA` o `MEDIA`, solo recibe el perfil asignado al disparador original.

```python
def should_broadcast(finding: dict) -> bool:
    return finding.get("severity") == "CRITICAL"
```

---

### Prompts de enriquecimiento IA (plantillas base)

```python
AUDIENCE_PROMPTS = {
    "cicd": """
        Responde SOLO con JSON válido. Sin prosa. Sin markdown.
        Campos obligatorios: exit_code (0 o 2), host, findings (lista),
        action (PASS o BLOCK), timestamp ISO8601.
    """,

    "tecnico": """
        Eres un ingeniero de seguridad senior. Analiza este hallazgo TLS
        y genera un reporte técnico que incluya:
        - Descripción técnica del problema
        - CVE o referencia normativa exacta
        - Comandos exactos de remediación (con rutas de archivo reales)
        - Comando de validación post-remediación
        Usa lenguaje técnico preciso. Sin resúmenes ejecutivos.
    """,

    "gestor": """
        Explica este hallazgo de seguridad para un líder técnico no especialista
        en ciberseguridad. Incluye:
        - Qué está mal y por qué importa (sin acrónimos técnicos)
        - Qué servicio o negocio se ve afectado
        - Qué acción se requiere y en qué plazo
        - A quién se debe asignar la remediación
        Máximo 200 palabras. Tono profesional, directo.
    """,

    "ejecutivo": """
        Genera un resumen ejecutivo de máximo 150 palabras para un CISO o directivo.
        Incluye:
        - Semáforo de riesgo: ROJO (crítico), AMARILLO (alto), VERDE (normal)
        - Impacto regulatorio si aplica (PCI-DSS, GDPR, ISO 27001)
        - Una sola acción recomendada con plazo
        - Sin jerga técnica. Sin comandos. Sin CVEs.
        Formato: párrafo breve + tabla de 2 columnas (Riesgo | Acción).
    """
}
```

---

### Implementación del generador PDF (deuda técnica prioritaria)

El PDF es el único formato que sirve tanto al gestor como al ejecutivo. La solución recomendada es `weasyprint`, que convierte el HTML de reporte existente a PDF sin reescribir nada:

```python
# reporte_pdf.py
from weasyprint import HTML as WeasyprintHTML

def export_pdf(html_content: str, output_path: str) -> str:
    """
    Convierte el HTML de reporte enriquecido a PDF.
    Reutiliza el template HTML existente — no requiere rediseño.
    """
    WeasyprintHTML(string=html_content).write_pdf(output_path)
    return output_path

# Uso desde report_router.py
html = generate_html_report(findings, audience="gestor")
pdf_path = export_pdf(html, f"reportes/reporte_{host}_{timestamp}.pdf")
```

Instalación: `pip install weasyprint`

> **Nota para el agente:** `weasyprint` puede requerir dependencias del sistema (`libpango`, `libcairo`). En entornos Docker o CI/CD, añadir al Dockerfile: `RUN apt-get install -y python3-weasyprint`

---

### Flujo completo del módulo `report_router.py`

```python
def route_report(scan_result: dict, trigger: str) -> None:
    severity = get_max_severity(scan_result)
    audiences = resolve_audiences(trigger, severity)

    for audience in audiences:
        enriched = ai_enrich(scan_result, audience)   # llama a Claude/OpenClaw
        report   = render_report(enriched, audience)  # HTML, JSON, PDF según perfil
        deliver(report, audience)                     # email, Slack, exit code, etc.

def resolve_audiences(trigger: str, severity: str) -> list[str]:
    if severity == "CRITICAL":
        return ["cicd", "tecnico", "gestor", "ejecutivo"]   # broadcast total
    return {
        "cicd_hook":         ["cicd"],
        "comando_mensaje":   ["tecnico"],
        "cron_schedule":     ["gestor"],
        "webhook_evento":    ["tecnico", "gestor"],
    }.get(trigger, ["tecnico"])
```

---

## 14. Matriz de Decisión Rápida (referencia para el agente)

| Disparador | Severidad | Audiencias | Formato | Canal |
|---|---|---|---|---|
| `cicd_hook` | cualquiera | CI/CD | JSON + exit code | GitHub Actions / stdout |
| `cicd_hook` | CRÍTICA | CI/CD + Técnico + Gestor + Ejecutivo | JSON + HTML + PDF + PDF | stdout + Slack + Email + Email |
| `comando_mensaje` | MEDIA/ALTA | Técnico | HTML + JSON | Slack / consola |
| `comando_mensaje` | CRÍTICA | Todos | JSON + HTML + PDF + PDF | Todos en paralelo |
| `cron_schedule` | MEDIA | Gestor | PDF | Email |
| `cron_schedule` | ALTA | Gestor + Técnico | PDF + HTML | Email + Slack |
| `cron_schedule` | CRÍTICA | Todos | Todos | Todos en paralelo |
| `webhook_evento` | cualquiera | Técnico + Gestor | HTML + PDF | Slack + Email |

---

## 15. Mapeo de Dependencias — Diseño de Decisión

### Principio: ni siempre automático ni siempre opcional

El mapeo de dependencias es **condicional**. La regla es simple: se ejecuta solo cuando el costo de no tenerlo supera el costo de ejecutarlo.

El mapeo es más lento que el escaneo TLS principal — implica resolver qué otros servicios llaman al host afectado. Si se dispara en cada escaneo MEDIO o BAJO, añade latencia donde no aporta valor. En un CI/CD con muchos deployments diarios, eso se vuelve ruido.

Pero cuando la severidad es CRÍTICA, esperar a que el ingeniero recuerde pasar `--deps` es un riesgo operacional. El blast radius es exactamente lo que se necesita saber de inmediato.

### Árbol de decisión: `should_map_dependencies(severity, trigger, flags)`

```
Escaneo TLS completado → JSON con severidad asignada
        ↓
¿Severidad máxima del resultado?
├── CRÍTICO  → mapeo AUTOMÁTICO (sin preguntar)
├── ALTO     → ¿Quién disparó el escaneo?
│   ├── cicd_hook      → mapeo AUTOMÁTICO (bloquea pipeline con contexto completo)
│   ├── comando_manual → ¿Flag --deps presente?
│   │   ├── sí → ejecutar mapeo
│   │   └── no → omitir mapeo
│   └── cron_schedule  → SUGERIR mapeo (nota en el reporte)
└── MEDIO / BAJO → OMITIR mapeo (flag deps_map: null en JSON)
```

### Implementación en `motor_reglas.py`

```python
def should_map_dependencies(severity: str, trigger: str, flags: dict) -> bool:
    """
    Decide si ejecutar el mapeo de dependencias post-escaneo.
    Retorna True = ejecutar, False = omitir.
    """
    if severity == "CRITICAL":
        return True                               # siempre automático

    if severity == "HIGH":
        if trigger == "cicd_hook":
            return True                           # automático: el pipeline necesita contexto
        if trigger == "comando_manual":
            return flags.get("deps", False)       # solo si el usuario lo pidió explícitamente
        if trigger == "cron_schedule":
            return False                          # omitir, pero sugerir en el reporte

    return False                                  # MEDIO / BAJO: siempre omitir


def map_dependencies(host: str, source: str = "static") -> dict:
    """
    Orquesta el mapeo de dependencias según la fuente configurada.
    source: "static" | "cloudrun" | "hybrid"
    """
    if source == "static":
        return load_static_inventory(host)
    elif source == "cloudrun":
        return discover_cloudrun_services(host)   # ver Sección 16
    elif source == "hybrid":
        static = load_static_inventory(host)
        dynamic = discover_cloudrun_services(host)
        return merge_inventories(static, dynamic)
```

### Qué produce el mapeo cuando se ejecuta

El resultado del mapeo enriquece el JSON de salida con una sección `deps_map`:

```json
{
  "host": "34.45.64.235",
  "deps_map": {
    "executed": true,
    "source": "static",
    "blast_radius": ["api-gateway", "auth-service", "payments-ms"],
    "dependency_chain": {
      "api-gateway": ["auth-service"],
      "auth-service": ["payments-ms"]
    },
    "remediation_priority": "api-gateway primero — punto de entrada de todos los demás"
  }
}
```

Si el mapeo se omitió:

```json
{
  "deps_map": null,
  "deps_map_reason": "severity below threshold (MEDIUM)"
}
```

Esta transparencia es intencional: el reporte debe explicar qué se hizo y qué no, no silenciar información.

---

## 16. Fuentes de Inventario para Ingesta — Diseño Escalonado

### Nivel 1 (implementado): Inventario estático en JSON

La fuente base. Un archivo `targets.json` declara los hosts que Byte-Shield vigila permanentemente. Es la forma más simple, predecible y segura.

**Estructura de `targets.json`:**

```json
{
  "version": "1.0",
  "description": "Inventario estático de objetivos Byte-Shield",
  "targets": [
    {
      "host": "34.45.64.235",
      "port": 443,
      "alias": "api-cloudlabs-prod",
      "environment": "production",
      "owner": "equipo-infra",
      "tags": ["critical", "pci-scope"],
      "dependents": ["api-gateway", "auth-service", "payments-ms"]
    },
    {
      "host": "api.cloudlabs.com",
      "port": 443,
      "alias": "api-cloudlabs-public",
      "environment": "production",
      "owner": "equipo-backend",
      "tags": ["public-facing"],
      "dependents": ["mobile-app", "web-frontend"]
    }
  ]
}
```

**Cargador en `ingesta.py`:**

```python
import json
from pathlib import Path

def load_static_inventory(targets_file: str = "targets.json") -> list[dict]:
    """
    Carga el inventario estático de objetivos desde JSON.
    Valida formato mínimo antes de retornar.
    """
    path = Path(targets_file)
    if not path.exists():
        raise FileNotFoundError(f"Inventario no encontrado: {targets_file}")

    with open(path) as f:
        data = json.load(f)

    targets = data.get("targets", [])
    validated = []
    for t in targets:
        if "host" in t and "port" in t:
            validated.append(t)
        else:
            print(f"[WARN] Objetivo ignorado (formato inválido): {t}")

    return validated


def load_static_inventory_for_host(host: str) -> dict:
    """
    Busca un host específico en el inventario y retorna sus dependientes.
    Usado por el módulo de mapeo de dependencias.
    """
    targets = load_static_inventory()
    for t in targets:
        if t["host"] == host or t.get("alias") == host:
            return {
                "found": True,
                "host": t["host"],
                "dependents": t.get("dependents", []),
                "environment": t.get("environment", "unknown"),
                "tags": t.get("tags", [])
            }
    return {"found": False, "host": host, "dependents": [], "source": "static"}
```

---

### Nivel 2 (preparado, no implementado): Discovery vía API de Cloud Run

Esta función está diseñada para conectarse a GCP y descubrir automáticamente todos los servicios activos en Cloud Run. El agente en el IDE **no debe implementarla aún**, solo dejar el stub con la firma correcta y la documentación de qué necesita para funcionar cuando se active.

**Por qué es poderosa:** si un desarrollador despliega un microservicio nuevo con TLS 1.0, Byte-Shield lo detecta solo en el siguiente scan, sin que nadie lo agregue al `targets.json`. Esto convierte el escáner en un sistema de vigilancia autónoma de la infraestructura.

**Stub en `ingesta.py`:**

```python
def discover_cloudrun_services(project_id: str = None, region: str = "us-central1") -> list[dict]:
    """
    [STUB — NO IMPLEMENTADO AÚN]

    Descubre automáticamente servicios activos en Google Cloud Run
    y los convierte al mismo formato que load_static_inventory().

    Requiere para activarse:
      - google-cloud-run SDK: pip install google-cloud-run
      - Credenciales GCP: GOOGLE_APPLICATION_CREDENTIALS o gcloud auth
      - Permiso IAM: roles/run.viewer en el proyecto

    Cuando se implemente, retorna:
    [
        {
            "host": "app-xyz.a.run.app",
            "port": 443,
            "alias": "app-xyz",
            "environment": "production",
            "source": "cloudrun_discovery",
            "dependents": []   # Cloud Run no expone dependencias — enriquecer con static si existe
        },
        ...
    ]

    Implementación futura:
        from google.cloud import run_v2
        client = run_v2.ServicesClient()
        parent = f"projects/{project_id}/locations/{region}"
        services = client.list_services(parent=parent)
        return [_cloudrun_service_to_target(s) for s in services]
    """
    raise NotImplementedError(
        "Cloud Run discovery no implementado. "
        "Usa load_static_inventory() o activa esta función configurando credenciales GCP. "
        "Ver documentación en CONTEXTO_RETO_TLS.md § 16."
    )
```

---

### Nivel 3 (preparado): Modo híbrido

Combina ambas fuentes. Los hosts del JSON aportan el campo `dependents` (que Cloud Run no conoce). Cloud Run aporta los microservicios nuevos que aún no están en el JSON.

```python
def merge_inventories(static: list[dict], dynamic: list[dict]) -> list[dict]:
    """
    Fusiona inventario estático + descubierto por Cloud Run.
    El estático tiene precedencia en caso de conflicto (preserva dependents).
    """
    static_hosts = {t["host"] for t in static}
    new_from_cloud = [t for t in dynamic if t["host"] not in static_hosts]

    merged = static + new_from_cloud
    print(f"[INFO] Inventario híbrido: {len(static)} estáticos + {len(new_from_cloud)} nuevos de Cloud Run")
    return merged
```

---

### Tabla de decisión de fuente según contexto

| Contexto de uso | Fuente recomendada | Razón |
|---|---|---|
| Demo del reto (MVP) | `static` | Predecible, sin dependencias externas, funciona offline |
| CI/CD post-deploy local | `static` | Rápido, el inventario se gestiona en el repo |
| CI/CD en GCP con Cloud Run | `cloudrun` | Detecta servicios nuevos automáticamente |
| Producción completa | `hybrid` | Cobertura total: fijos + dinámicos |

---

### Flag de selección de fuente en CLI

```bash
# Usar inventario estático (default)
python tls_scanner.py --target targets.json --source static

# Usar Cloud Run discovery (cuando esté implementado)
python tls_scanner.py --source cloudrun --project my-gcp-project --region us-central1

# Modo híbrido
python tls_scanner.py --source hybrid --project my-gcp-project

# Forzar mapeo de dependencias independientemente de la severidad
python tls_scanner.py --target targets.json --deps
```

---

## 17. Estructura de Repositorio Final (actualizada)

```
/
├── README.md
├── targets.json                    # Inventario estático de objetivos
├── compliance/
│   └── ESTANDARES_CUMPLIMIENTO.json
├── src/
│   ├── ingesta.py                  # Fase 1: Carga estática + stub Cloud Run
│   ├── tls_scanner.py              # Fase 2: Motor TLS principal
│   ├── motor_reglas.py             # Fase 3: Clasificación, deps, recomendaciones
│   │   └── should_map_dependencies()
│   ├── report_router.py            # Fase 4: Decisión de audiencia y formato
│   ├── reporte_html.py             # Generador HTML
│   ├── reporte_pdf.py              # Generador PDF (weasyprint)
│   └── openclaw_agent/
│       ├── agent.py                # Orquestador OpenClaw / Clawbot
│       ├── triggers.py             # cron, webhook, CI/CD, comando_mensaje
│       └── actions.py             # alertas, tickets, bloqueos de pipeline
├── ejemplos/
│   ├── targets.json                # Ejemplo de inventario
│   └── salida_ejemplo.json         # Ejemplo de reporte con deps_map
└── reportes/                       # Salidas generadas (gitignored)
```

---

## 18. Decisiones de Diseño Tomadas (registro para el agente)

Este registro evita que el agente revierta decisiones ya tomadas o proponga alternativas que ya fueron descartadas.

| Decisión | Opción elegida | Alternativa descartada | Razón |
|---|---|---|---|
| Fuente de inventario inicial | JSON estático | API en tiempo real | Predecible para el MVP, sin dependencias externas |
| Cloud Run discovery | Stub preparado | No implementar | Dejar el terreno para la versión Pro sin bloquear el MVP |
| Mapeo de dependencias | Condicional por severidad+trigger | Siempre automático / Siempre opcional | Evita latencia innecesaria sin sacrificar cobertura en casos críticos |
| Generador PDF | `weasyprint` desde HTML existente | Librería PDF nativa | Reutiliza templates HTML ya construidos, sin rediseño |
| Enriquecimiento IA | Prompt por perfil de audiencia | Un solo prompt universal | Cada audiencia necesita lenguaje y nivel de abstracción distintos |
| Agente autónomo | OpenClaw / Clawbot | Integración directa API | OpenClaw permite disparadores múltiples y acciones encadenadas sin código extra |
| Acceso del agente | Solo puede llamar `tls_scanner.py` | Acceso amplio al sistema | Superficie de ataque mínima — la ventaja de seguridad es el argumento diferenciador |