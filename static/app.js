/* Byte-Shield — Dashboard Frontend */

let scanResults = [];
let isScanning = false;

// ── DOM refs ────────────────────────────────────────────────────

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const elTargetInput   = $('#target-input');
const elPortsInput    = $('#ports-input');
const elBatchInput    = $('#batch-input');
const elBtnScan       = $('#btn-scan');
const elProgressSec   = $('#progress-section');
const elProgressBar   = $('#progress-bar');
const elProgressText  = $('#progress-text');
const elSummarySec    = $('#summary-section');
const elResultsSec    = $('#results-section');
const elResultsCont   = $('#results-container');
const elExportSec     = $('#export-section');
const elLogSec        = $('#log-section');
const elLogCont       = $('#log-container');
const elTotalHosts    = $('#total-hosts');
const elTotalCritico  = $('#total-critico');
const elTotalMedio    = $('#total-medio');
const elTotalSeguro   = $('#total-seguro');

// ── Helpers ─────────────────────────────────────────────────────

function timestamp() {
  return new Date().toLocaleTimeString('es-CO', { hour12: false });
}

function log(msg, cls = 'log-info') {
  elLogSec.classList.remove('hidden');
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `<span class="log-time">[${timestamp()}]</span><span class="${cls}">${msg}</span>`;
  elLogCont.appendChild(entry);
  elLogCont.scrollTop = elLogCont.scrollHeight;
}

function parsePorts(text) {
  return text.split(/[\s,]+/)
    .map(s => parseInt(s.trim(), 10))
    .filter(n => !isNaN(n) && n > 0 && n <= 65535);
}

function parseTargets() {
  const targets = [];
  const single = elTargetInput.value.trim();
  if (single) targets.push(single);

  const batch = elBatchInput.value.trim();
  if (batch) {
    batch.split('\n').forEach(line => {
      const t = line.trim();
      if (t && !t.startsWith('#')) targets.push(t);
    });
  }

  // Deduplicar
  return [...new Set(targets)];
}

function setScanning(active) {
  isScanning = active;
  elBtnScan.disabled = active;
  if (active) {
    elBtnScan.classList.add('scanning');
    elBtnScan.innerHTML = '<span class="btn-icon">&#9632;</span> Escaneando...';
  } else {
    elBtnScan.classList.remove('scanning');
    elBtnScan.innerHTML = '<span class="btn-icon">&#9654;</span> Iniciar Análisis';
  }
}

// ── Summary update ──────────────────────────────────────────────

function updateSummary() {
  const counts = { total: scanResults.length, critico: 0, medio: 0, seguro: 0 };
  scanResults.forEach(r => {
    const n = r.nivel || '';
    if (n === 'CRÍTICO')    counts.critico++;
    else if (n === 'MEDIO') counts.medio++;
    else if (n === 'SEGURO') counts.seguro++;
  });

  elTotalHosts.textContent   = counts.total;
  elTotalCritico.textContent = counts.critico;
  elTotalMedio.textContent   = counts.medio;
  elTotalSeguro.textContent  = counts.seguro;

  elSummarySec.classList.remove('hidden');
}

// ── Card rendering ──────────────────────────────────────────────

function nivelClass(nivel) {
  if (nivel === 'CRÍTICO') return 'critico';
  if (nivel === 'MEDIO')   return 'medio';
  return 'seguro';
}

const PROTO_DANGER = ['TLS 1.0', 'TLS 1.1'];
const PROTO_WARN   = ['TLS 1.2'];

function protoClass(name, enabled) {
  if (!enabled) return 'proto-disabled';
  if (PROTO_DANGER.includes(name)) return 'proto-danger';
  if (PROTO_WARN.includes(name))   return 'proto-warn';
  return 'proto-safe';
}

function renderProtocolBox(name, info) {
  const enabled = info && info.habilitado;
  const cls    = protoClass(name, enabled);
  const status = enabled ? 'ENABLED' : 'DISABLED';
  return `<div class="protocol-box ${cls}">
    <div class="proto-name">${name}</div>
    <div class="proto-status">${status}</div>
  </div>`;
}

function renderCard(result) {
  const host = `${result.host}:${result.puerto}`;
  const nc = nivelClass(result.nivel);
  const tls = result.tls || {};

  const protos = ['TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3']
    .map(n => renderProtocolBox(n, tls[n])).join('');

  const hallazgos = (result.hallazgos || []).map(h =>
    `<div class="finding-item"><span class="icon riesgo">&#9888;</span><span class="riesgo">${h}</span></div>`
  ).join('');

  const recoms = (result.recomendaciones || []).map(r =>
    `<div class="finding-item"><span class="icon recom">&#10004;</span><span class="recom">${r}</span></div>`
  ).join('');

  return `<div class="host-card">
    <div class="host-header">
      <h3>[+] ${host}</h3>
      <span class="badge badge-${nc}">${result.nivel}</span>
    </div>
    <div class="protocol-grid">${protos}</div>
    <div class="findings-grid">
      <div class="findings-col">
        <h4>Riesgos Identificados</h4>
        ${hallazgos || '<div class="finding-item"><span class="recom">Sin riesgos detectados.</span></div>'}
      </div>
      <div class="findings-col">
        <h4>Recomendaciones</h4>
        ${recoms || '<div class="finding-item"><span class="recom">Configuración adecuada.</span></div>'}
      </div>
    </div>
  </div>`;
}

function appendResult(result) {
  elResultsSec.classList.remove('hidden');
  elResultsCont.insertAdjacentHTML('beforeend', renderCard(result));
}

// ── Scan (SSE via fetch + ReadableStream) ───────────────────────

async function iniciarScan() {
  if (isScanning) return;

  const targets = parseTargets();
  const ports = parsePorts(elPortsInput.value || '443');

  if (targets.length === 0) {
    elTargetInput.focus();
    log('Se requiere al menos un target.', 'log-error');
    return;
  }
  if (ports.length === 0) {
    elPortsInput.focus();
    log('Se requiere al menos un puerto válido.', 'log-error');
    return;
  }

  // Reset
  scanResults = [];
  elResultsCont.innerHTML = '';
  elResultsSec.classList.add('hidden');
  elExportSec.classList.add('hidden');
  elProgressBar.style.width = '0%';
  elProgressSec.classList.remove('hidden');
  elProgressText.textContent = 'Iniciando escaneo...';
  updateSummary();
  setScanning(true);

  log(`Escaneo iniciado: ${targets.length} target(s), puertos [${ports.join(', ')}]`);

  try {
    const response = await fetch('/api/scan/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targets, ports }),
    });

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let scanDone = false;

    while (true) {
      const { done, value } = await reader.read();
      if (done || scanDone) break;

      buffer += decoder.decode(value, { stream: true });

      // Parse SSE lines
      const lines = buffer.split('\n');
      buffer = lines.pop(); // keep incomplete line

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const jsonStr = line.substring(6);
        if (!jsonStr) continue;

        try {
          const event = JSON.parse(jsonStr);
          if (handleEvent(event)) { scanDone = true; reader.cancel(); break; }
        } catch (e) {
          // skip malformed
        }
      }
    }

    // Process remaining buffer
    if (buffer.startsWith('data: ')) {
      try {
        const event = JSON.parse(buffer.substring(6));
        handleEvent(event);
      } catch (e) { /* skip */ }
    }

  } catch (err) {
    log(`Error de conexión: ${err.message}`, 'log-error');
  } finally {
    setScanning(false);
    elProgressText.textContent = 'Escaneo completado.';
  }
}

function handleEvent(event) {
  switch (event.type) {
    case 'scanning':
      elProgressText.textContent = `Analizando ${event.host}:${event.puerto}...`;
      log(`Escaneando ${event.host}:${event.puerto}...`);
      break;

    case 'port_closed':
      log(`Puerto ${event.puerto} cerrado en ${event.host}`, 'log-warn');
      break;

    case 'result':
      scanResults.push(event);
      appendResult(event);
      updateSummary();
      log(`${event.host}:${event.puerto} — ${event.nivel}`,
          event.nivel === 'CRÍTICO' ? 'log-error' :
          event.nivel === 'MEDIO' ? 'log-warn' : 'log-ok');
      break;

    case 'error':
      log(`Error: ${event.host} — ${event.message}`, 'log-error');
      break;

    case 'progress':
      if (event.total > 0) {
        const pct = Math.round((event.completed / event.total) * 100);
        elProgressBar.style.width = pct + '%';
      }
      break;

    case 'done':
      elExportSec.classList.remove('hidden');
      log(`Escaneo completado: ${event.total_results} resultado(s)`, 'log-ok');
      return true;
  }
}

// ── Export ───────────────────────────────────────────────────────

async function exportar(formato) {
  if (scanResults.length === 0) {
    log('No hay resultados para exportar.', 'log-warn');
    return;
  }

  log(`Exportando reporte en formato ${formato.toUpperCase()}...`);

  try {
    const response = await fetch(`/api/export/${formato}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ resultados: scanResults }),
    });

    if (!response.ok) {
      log('Error al exportar.', 'log-error');
      return;
    }

    const blob = await response.blob();
    const disposition = response.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="?([^"]+)"?/);
    const filename = match ? match[1] : `reporte_byteshield.${formato}`;

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    log(`Reporte ${formato.toUpperCase()} descargado: ${filename}`, 'log-ok');
  } catch (err) {
    log(`Error de exportación: ${err.message}`, 'log-error');
  }
}

// ── Clear ───────────────────────────────────────────────────────

function limpiarResultados() {
  scanResults = [];
  elResultsCont.innerHTML = '';
  elResultsSec.classList.add('hidden');
  elSummarySec.classList.add('hidden');
  elExportSec.classList.add('hidden');
  elProgressSec.classList.add('hidden');
  elLogCont.innerHTML = '';
  elLogSec.classList.add('hidden');
  elProgressBar.style.width = '0%';
  updateSummary();
}

// ── Dependency Map ──────────────────────────────────────────────

const elDepsSec     = $('#deps-section');
const elDepsSpinner = $('#deps-spinner');
const elDepsContent = $('#deps-content');

function nivelDepClass(nivel) {
  if (nivel === 'CRÍTICO')     return 'critico';
  if (nivel === 'MEDIO')       return 'medio';
  if (nivel === 'SEGURO')      return 'seguro';
  return 'muted';
}

function renderDepRow(dep) {
  const nc   = nivelDepClass(dep.nivel);
  const t10  = dep.tls_1_0 ? '<span class="dep-proto dep-proto-danger">1.0</span>' : '<span class="dep-proto dep-proto-off">1.0</span>';
  const t11  = dep.tls_1_1 ? '<span class="dep-proto dep-proto-danger">1.1</span>' : '<span class="dep-proto dep-proto-off">1.1</span>';
  const t12  = dep.tls_1_2 ? '<span class="dep-proto dep-proto-warn">1.2</span>'   : '<span class="dep-proto dep-proto-off">1.2</span>';
  const t13  = dep.tls_1_3 ? '<span class="dep-proto dep-proto-safe">1.3</span>'   : '<span class="dep-proto dep-proto-off">1.3</span>';
  const badge = dep.nivel !== 'DESCONOCIDO'
    ? `<span class="badge badge-${nc}">${dep.nivel}</span>`
    : `<span class="badge" style="color:var(--muted);border-color:var(--border)">—</span>`;
  return `<tr class="dep-row">
    <td class="dep-host">${dep.host}</td>
    <td>${badge}</td>
    <td class="dep-protos">${t10}${t11}${t12}${t13}</td>
    <td class="dep-finding">${dep.hallazgos[0] || '—'}</td>
  </tr>`;
}

async function mapearDependencias() {
  if (scanResults.length === 0) {
    log('Primero ejecuta un escaneo para poder mapear dependencias.', 'log-warn');
    return;
  }

  const primer = scanResults[0];
  const host   = primer.host;
  const puerto = primer.puerto;

  elDepsSec.classList.remove('hidden');
  elDepsSpinner.classList.remove('hidden');
  elDepsContent.innerHTML = '';
  log(`Mapeando dependencias de ${host}:${puerto}...`, 'log-info');

  try {
    // #region agent log H-browser
    fetch('http://127.0.0.1:7551/ingest/e1d1fb6d-525f-4300-8155-d9973b41fef4',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'138a82'},body:JSON.stringify({sessionId:'138a82',location:'app.js:mapearDependencias',message:'before_fetch',data:{origin:window.location.origin,path:window.location.pathname},timestamp:Date.now(),hypothesisId:'H-browser'})}).catch(()=>{});
    // #endregion
    const response = await fetch('/api/dependency-map', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, puerto }),
    });

    const data = await response.json();

    if (!response.ok) {
      log(`Error en mapeo: ${data.error}`, 'log-error');
      elDepsContent.innerHTML = `<p class="ai-error">${data.error}</p>`;
      return;
    }

    const fuentes = data.fuentes.length
      ? data.fuentes.map(f => f === 'cert' ? 'Certificado TLS (SAN)' : 'Certificate Transparency (crt.sh)').join(' + ')
      : 'Sin fuentes disponibles (offline)';

    const total    = data.todos.length;
    const criticos = data.dependencias_escaneadas.filter(d => d.nivel === 'CRÍTICO').length;

    let html = `<div class="deps-meta">
      <span>Dominio base: <strong>${data.dominio_base}</strong></span>
      <span>Fuentes: <strong>${fuentes}</strong></span>
      <span>Dependencias descubiertas: <strong>${total}</strong></span>
      ${criticos > 0 ? `<span class="dep-alert">&#9888; ${criticos} con hallazgos CRÍTICOS</span>` : ''}
    </div>`;

    if (data.dependencias_escaneadas.length === 0) {
      html += '<p class="deps-empty">No se descubrieron dependencias para este host.</p>';
    } else {
      html += `<div class="deps-table-wrap"><table class="deps-table">
        <thead><tr>
          <th>Host</th><th>Nivel</th><th>Protocolos</th><th>Hallazgo principal</th>
        </tr></thead>
        <tbody>${data.dependencias_escaneadas.map(renderDepRow).join('')}</tbody>
      </table></div>`;
    }

    elDepsContent.innerHTML = html;
    log(`Mapeo completado: ${total} dependencias, ${criticos} críticas.`,
        criticos > 0 ? 'log-error' : 'log-ok');

  } catch (err) {
    log(`Error al mapear dependencias: ${err.message}`, 'log-error');
    elDepsContent.innerHTML = `<p class="ai-error">Error de conexión al mapear dependencias.</p>`;
  } finally {
    elDepsSpinner.classList.add('hidden');
  }
}

// ── AI Analysis ─────────────────────────────────────────────────

const elAISec     = $('#ai-section');
const elAISpinner = $('#ai-spinner');
const elAIText    = $('#ai-text');

function renderAIText(raw) {
  return raw
    .split('\n')
    .map(line => {
      line = line.trim();
      if (!line) return '';
      if (/^#{1,3}\s/.test(line)) {
        return `<p class="ai-heading">${line.replace(/^#+\s*/, '')}</p>`;
      }
      if (/^\d+\.\s/.test(line) || /^[-*]\s/.test(line)) {
        return `<p class="ai-bullet">${line.replace(/^[-*\d.]\s*/, '')}</p>`;
      }
      return `<p>${line}</p>`;
    })
    .join('');
}

async function analizarConIA() {
  if (scanResults.length === 0) {
    log('No hay resultados para analizar.', 'log-warn');
    return;
  }

  elAISec.classList.remove('hidden');
  elAISpinner.classList.remove('hidden');
  elAIText.innerHTML = '';
  log('Enviando hallazgos al modelo de IA...', 'log-info');

  try {
    // #region agent log H-browser
    fetch('http://127.0.0.1:7551/ingest/e1d1fb6d-525f-4300-8155-d9973b41fef4',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'138a82'},body:JSON.stringify({sessionId:'138a82',location:'app.js:analizarConIA',message:'before_fetch',data:{origin:window.location.origin},timestamp:Date.now(),hypothesisId:'H-browser'})}).catch(()=>{});
    // #endregion
    const response = await fetch('/api/ai-analysis', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ resultados: scanResults }),
    });

    const data = await response.json();

    if (!response.ok) {
      log(`Error IA: ${data.error}`, 'log-error');
      elAIText.innerHTML = `<p class="ai-error">${data.error}</p>`;
      return;
    }

    elAIText.innerHTML = renderAIText(data.analysis);
    log('Análisis IA completado.', 'log-ok');
  } catch (err) {
    log(`Error al contactar el modelo: ${err.message}`, 'log-error');
    elAIText.innerHTML = `<p class="ai-error">No se pudo conectar con el modelo de IA.</p>`;
  } finally {
    elAISpinner.classList.add('hidden');
  }
}

// ── Email Modal ──────────────────────────────────────────────────

const elEmailOverlay = $('#email-modal-overlay');
const elEmailInput   = $('#email-input');
const elEmailStatus  = $('#email-status');
const elBtnSendEmail = $('#btn-send-email');

function mostrarEmailModal() {
  if (scanResults.length === 0) {
    log('No hay resultados para enviar.', 'log-warn');
    return;
  }
  elEmailStatus.classList.add('hidden');
  elEmailStatus.textContent = '';
  elEmailInput.value = '';
  elEmailOverlay.classList.remove('hidden');
  setTimeout(() => elEmailInput.focus(), 50);
}

function cerrarEmailModal(e) {
  if (e && e.target !== elEmailOverlay) return;
  elEmailOverlay.classList.add('hidden');
}

async function enviarEmail() {
  const destinatario = elEmailInput.value.trim();
  if (!destinatario) {
    elEmailInput.focus();
    return;
  }

  elBtnSendEmail.disabled = true;
  elBtnSendEmail.textContent = 'Enviando...';
  elEmailStatus.classList.add('hidden');

  try {
    // #region agent log H-browser
    fetch('http://127.0.0.1:7551/ingest/e1d1fb6d-525f-4300-8155-d9973b41fef4',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'138a82'},body:JSON.stringify({sessionId:'138a82',location:'app.js:enviarEmail',message:'before_fetch',data:{origin:window.location.origin},timestamp:Date.now(),hypothesisId:'H-browser'})}).catch(()=>{});
    // #endregion
    const response = await fetch('/api/send-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ destinatario, resultados: scanResults }),
    });

    const data = await response.json();

    elEmailStatus.classList.remove('hidden');
    if (response.ok && data.ok) {
      elEmailStatus.className = 'email-status email-status-ok';
      elEmailStatus.textContent = `Reporte enviado a ${destinatario}`;
      log(`Reporte enviado por email a ${destinatario}`, 'log-ok');
      setTimeout(() => elEmailOverlay.classList.add('hidden'), 2000);
    } else {
      elEmailStatus.className = 'email-status email-status-error';
      elEmailStatus.textContent = data.error || 'Error al enviar el email.';
      log(`Error email: ${data.error}`, 'log-error');
    }
  } catch (err) {
    elEmailStatus.classList.remove('hidden');
    elEmailStatus.className = 'email-status email-status-error';
    elEmailStatus.textContent = 'Error de conexión al enviar el email.';
    log(`Error email: ${err.message}`, 'log-error');
  } finally {
    elBtnSendEmail.disabled = false;
    elBtnSendEmail.textContent = 'Enviar';
  }
}

// ── Keyboard shortcut ───────────────────────────────────────────

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') cerrarEmailModal();
  if (e.key === 'Enter' && !isScanning && document.activeElement !== elBatchInput) {
    iniciarScan();
  }
});
