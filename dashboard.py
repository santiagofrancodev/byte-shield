#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         BYTE-SHIELD — Dashboard Web para Demo en Vivo            ║
║         Servidor HTTP puro (stdlib) — Cero dependencias          ║
║         Uso: python3 dashboard.py [--port 8080]                  ║
║         Exponer: ngrok http 8080                                 ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import csv
import io
import os
import sys
import smtplib
import datetime
import argparse
import socket
import threading
import mimetypes
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from tls_scanner import (
    validar_objetivo,
    escanear_puerto,
    auditar_tls_en_puerto,
    calcular_criticidad,
    analizar_con_ia,
    mapear_dependencias,
    CONNECT_TIMEOUT,
)
from generar_reporte import generar_html

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


def _load_dotenv():
    """Carga variables de entorno desde .env (stdlib puro, sin dependencias).

    Si la misma clave aparece varias veces en el archivo, gana la última línea.
    No sobrescribe variables que ya existían en el entorno del proceso antes de cargar.
    """
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    parsed: dict[str, str] = {}
    with env_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                parsed[key] = value
    for key, value in parsed.items():
        if key not in os.environ:
            os.environ[key] = value


_load_dotenv()

# #region agent log startup
import time as _time
def _dbg(msg: str, data: dict = None, hypothesis_id: str = "H1") -> None:
    """Escribe una línea NDJSON al log de debug."""
    import json as _json
    entry = {
        "sessionId": "138a82",
        "timestamp": int(_time.time() * 1000),
        "location": "dashboard.py",
        "message": msg,
        "data": data or {},
        "hypothesisId": hypothesis_id,
    }
    try:
        log_path = BASE_DIR / "debug-138a82.log"
        with open(log_path, "a", encoding="utf-8") as _fh:
            _fh.write(_json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass

_dbg("SERVER_STARTUP", {
    "pid": os.getpid(),
    "endpoints_registered": [
        "/api/scan/stream", "/api/export/json", "/api/export/csv",
        "/api/export/html", "/api/ai-analysis", "/api/send-email",
        "/api/dependency-map"
    ],
    "ai_key_set": bool(os.environ.get("BYTESHIELD_AI_KEY")),
    "smtp_host_set": bool(os.environ.get("BYTESHIELD_SMTP_HOST")),
}, "H2")
# #endregion

scan_history: list[dict] = []
scan_lock = threading.Lock()


def build_scan_result(host: str, puerto: int) -> dict:
    """Ejecuta auditoría TLS y retorna el resultado estructurado."""
    resultados_tls = auditar_tls_en_puerto(host, puerto)
    nivel, hallazgos, recomendaciones = calcular_criticidad(resultados_tls)
    return {
        "host": host,
        "puerto": puerto,
        "nivel": nivel,
        "tls": resultados_tls,
        "hallazgos": hallazgos,
        "recomendaciones": recomendaciones,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def results_to_csv(resultados: list[dict]) -> str:
    """Convierte resultados a CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "host", "puerto", "nivel",
        "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3",
        "hallazgos", "recomendaciones",
    ])
    for r in resultados:
        tls = r.get("tls", {})
        writer.writerow([
            r["host"],
            r["puerto"],
            r["nivel"],
            "ENABLED" if tls.get("TLS 1.0", {}).get("habilitado") else "DISABLED",
            "ENABLED" if tls.get("TLS 1.1", {}).get("habilitado") else "DISABLED",
            "ENABLED" if tls.get("TLS 1.2", {}).get("habilitado") else "DISABLED",
            "ENABLED" if tls.get("TLS 1.3", {}).get("habilitado") else "DISABLED",
            " | ".join(r.get("hallazgos", [])),
            " | ".join(r.get("recomendaciones", [])),
        ])
    return output.getvalue()


def results_to_json_report(resultados: list[dict]) -> str:
    """Empaqueta resultados en el formato de reporte JSON."""
    reporte = {
        "generado_en": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "herramienta": "Byte-Shield — Dashboard",
        "resultados": resultados,
    }
    return json.dumps(reporte, indent=2, ensure_ascii=False)


def results_to_html_report(resultados: list[dict]) -> str:
    """Genera HTML reutilizando la lógica de generar_reporte.py."""
    data = {
        "generado_en": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "resultados": resultados,
    }
    return generar_html(data)


class DashboardHandler(BaseHTTPRequestHandler):
    """Manejador HTTP para el dashboard de Byte-Shield."""

    def log_message(self, format, *args):
        sys.stderr.write(
            f"  \033[90m[{self.log_date_time_string()}]\033[0m "
            f"{format % args}\n"
        )
        sys.stderr.flush()

    # ── GET ──────────────────────────────────────────────────────

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "":
            self._serve_file(STATIC_DIR / "index.html", "text/html")
        elif path.startswith("/static/"):
            rel = path[len("/static/"):]
            file_path = STATIC_DIR / rel
            if file_path.is_file() and STATIC_DIR in file_path.resolve().parents:
                ctype = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
                self._serve_file(file_path, ctype)
            else:
                self._send_error(404, "Archivo no encontrado")
        elif path == "/api/history":
            self._send_json(200, scan_history)
        elif path == "/api/server-info":
            # Diagnóstico: confirma que el navegador habla con ESTE proceso (mismo código que los POST nuevos).
            self._send_json(200, {
                "servicio": "byte-shield-dashboard",
                "pid": os.getpid(),
                "dashboard_py": str(Path(__file__).resolve()),
                "post_endpoints": [
                    "/api/scan/stream", "/api/export/json", "/api/export/csv",
                    "/api/export/html", "/api/ai-analysis", "/api/send-email",
                    "/api/dependency-map",
                ],
            })
        else:
            self._send_error(404, "Ruta no encontrada")

    # ── POST ─────────────────────────────────────────────────────

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        # #region agent log H4
        sys.stderr.write(f"[DBG do_POST] raw={self.path!r} parsed={path!r}\n")
        sys.stderr.flush()
        _dbg("DO_POST_CALLED", {"raw": self.path, "parsed": path}, "H1")
        # #endregion

        if path == "/api/scan/stream":
            self._handle_scan_stream()
        elif path == "/api/export/json":
            self._handle_export_json()
        elif path == "/api/export/csv":
            self._handle_export_csv()
        elif path == "/api/export/html":
            self._handle_export_html()
        elif path == "/api/ai-analysis":
            self._handle_ai_analysis()
        elif path == "/api/send-email":
            self._handle_send_email()
        elif path == "/api/dependency-map":
            self._handle_dependency_map()
        else:
            # #region agent log H4
            sys.stderr.write(f"[DBG 404] path={path!r} — no match\n")
            sys.stderr.flush()
            _dbg("DO_POST_404", {"path": path}, "H2")
            # #endregion
            self._send_error(404, "Endpoint no encontrado")

    # ── Scan con streaming SSE ───────────────────────────────────

    def _handle_scan_stream(self):
        body = self._read_body()
        if body is None:
            return

        targets_raw = body.get("targets", [])
        ports = body.get("ports", [443])
        timeout = body.get("timeout", CONNECT_TIMEOUT)

        if not targets_raw:
            self._send_error(400, "Se requiere al menos un target")
            return

        targets = []
        for t in targets_raw:
            t = t.strip()
            if t:
                targets.append(t)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        all_results = []
        total_tasks = len(targets) * len(ports)
        completed = 0

        for host in targets:
            try:
                validar_objetivo(host)
            except ValueError as e:
                event = {
                    "type": "error",
                    "host": host,
                    "message": str(e),
                }
                self._sse_write(event)
                completed += len(ports)
                self._sse_write({"type": "progress", "completed": completed, "total": total_tasks})
                continue

            for puerto in ports:
                event_scanning = {
                    "type": "scanning",
                    "host": host,
                    "puerto": puerto,
                }
                self._sse_write(event_scanning)

                port_open = escanear_puerto(host, puerto, timeout=timeout)
                if not port_open:
                    event = {
                        "type": "port_closed",
                        "host": host,
                        "puerto": puerto,
                    }
                    self._sse_write(event)
                    completed += 1
                    self._sse_write({"type": "progress", "completed": completed, "total": total_tasks})
                    continue

                result = build_scan_result(host, puerto)
                all_results.append(result)

                event = {"type": "result", **result}
                self._sse_write(event)

                completed += 1
                self._sse_write({"type": "progress", "completed": completed, "total": total_tasks})

        with scan_lock:
            scan_history.clear()
            scan_history.extend(all_results)

        done_event = {
            "type": "done",
            "total_results": len(all_results),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._sse_write(done_event)
        self.close_connection = True

    def _sse_write(self, data: dict):
        """Escribe un evento SSE y hace flush."""
        try:
            line = f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
            self.wfile.write(line.encode("utf-8"))
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    # ── Exportaciones ────────────────────────────────────────────

    def _handle_export_json(self):
        body = self._read_body()
        resultados = self._get_resultados(body)
        content = results_to_json_report(resultados)
        self._send_download(content.encode("utf-8"), "reporte_byteshield.json", "application/json")

    def _handle_export_csv(self):
        body = self._read_body()
        resultados = self._get_resultados(body)
        content = results_to_csv(resultados)
        self._send_download(content.encode("utf-8"), "reporte_byteshield.csv", "text/csv")

    def _handle_export_html(self):
        body = self._read_body()
        resultados = self._get_resultados(body)
        content = results_to_html_report(resultados)
        self._send_download(content.encode("utf-8"), "reporte_byteshield.html", "text/html")

    def _handle_ai_analysis(self):
        body = self._read_body()
        if body is None:
            return
        resultados = self._get_resultados(body)
        if not resultados:
            self._send_error(400, "No hay resultados para analizar")
            return
        try:
            analysis = analizar_con_ia(resultados)
            self._send_json(200, {"analysis": analysis})
        except RuntimeError as e:
            self._send_json(503, {"error": str(e)})

    def _handle_send_email(self):
        body = self._read_body()
        if body is None:
            return

        destinatario = (body.get("destinatario") or "").strip()
        if not destinatario:
            self._send_error(400, "El campo 'destinatario' es requerido")
            return

        smtp_host = os.environ.get("BYTESHIELD_SMTP_HOST", "smtp.gmail.com")
        smtp_port = int(os.environ.get("BYTESHIELD_SMTP_PORT", "587"))
        smtp_user = os.environ.get("BYTESHIELD_SMTP_USER", "").strip()
        smtp_pass = os.environ.get("BYTESHIELD_SMTP_PASS", "").strip()

        if not smtp_user or not smtp_pass:
            self._send_json(503, {
                "error": "Variables BYTESHIELD_SMTP_USER y BYTESHIELD_SMTP_PASS no configuradas."
            })
            return

        resultados = self._get_resultados(body)
        html_content = results_to_html_report(resultados)
        json_content = results_to_json_report(resultados)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        msg = MIMEMultipart("mixed")
        msg["From"]    = smtp_user
        msg["To"]      = destinatario
        msg["Subject"] = f"Byte-Shield — Reporte de Auditoría TLS [{ts}]"

        niveles = [r["nivel"] for r in resultados]
        criticos = niveles.count("CRÍTICO")
        medios   = niveles.count("MEDIO")
        cuerpo_texto = (
            f"Byte-Shield — Reporte de Auditoría TLS\n"
            f"Generado: {datetime.datetime.now().isoformat()}\n\n"
            f"Servidores analizados: {len(resultados)}\n"
            f"Críticos: {criticos}  |  Medios: {medios}  |  "
            f"Seguros: {len(resultados) - criticos - medios}\n\n"
            f"El reporte completo en HTML y el JSON están adjuntos.\n\n"
            f"-- Byte Security Group"
        )
        msg.attach(MIMEText(cuerpo_texto, "plain", "utf-8"))
        msg.attach(MIMEText(html_content, "html", "utf-8"))

        adjunto_json = MIMEBase("application", "json")
        adjunto_json.set_payload(json_content.encode("utf-8"))
        encoders.encode_base64(adjunto_json)
        adjunto_json.add_header(
            "Content-Disposition",
            f'attachment; filename="reporte_byteshield_{ts}.json"',
        )
        msg.attach(adjunto_json)

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, destinatario, msg.as_string())
            self._send_json(200, {"ok": True, "destinatario": destinatario})
        except smtplib.SMTPAuthenticationError:
            self._send_json(503, {"error": "Error de autenticación SMTP. Verifica usuario y contraseña."})
        except smtplib.SMTPException as e:
            self._send_json(503, {"error": f"Error SMTP: {e}"})
        except OSError as e:
            self._send_json(503, {"error": f"Error de red al conectar con {smtp_host}: {e}"})

    def _handle_dependency_map(self):
        body = self._read_body()
        if body is None:
            return

        host   = (body.get("host") or "").strip()
        puerto = int(body.get("puerto") or 443)

        if not host:
            self._send_error(400, "El campo 'host' es requerido")
            return

        try:
            validar_objetivo(host)
        except ValueError as e:
            self._send_error(400, str(e))
            return

        resultado = mapear_dependencias(host, puerto)

        # Escanear TLS de cada dependencia descubierta (máx. 10 para no bloquear)
        deps_escaneadas = []
        for dep in resultado["todos"][:10]:
            try:
                validar_objetivo(dep)
                tls = auditar_tls_en_puerto(dep, puerto)
                nivel, hallazgos, _ = calcular_criticidad(tls)
                deps_escaneadas.append({
                    "host":      dep,
                    "nivel":     nivel,
                    "tls_1_0":   tls.get("TLS 1.0", {}).get("habilitado", False),
                    "tls_1_1":   tls.get("TLS 1.1", {}).get("habilitado", False),
                    "tls_1_2":   tls.get("TLS 1.2", {}).get("habilitado", False),
                    "tls_1_3":   tls.get("TLS 1.3", {}).get("habilitado", False),
                    "hallazgos": hallazgos[:2],
                })
            except (ValueError, OSError):
                deps_escaneadas.append({
                    "host":      dep,
                    "nivel":     "DESCONOCIDO",
                    "tls_1_0":   False,
                    "tls_1_1":   False,
                    "tls_1_2":   False,
                    "tls_1_3":   False,
                    "hallazgos": ["No se pudo conectar al host"],
                })

        self._send_json(200, {
            **resultado,
            "dependencias_escaneadas": deps_escaneadas,
        })

    def _get_resultados(self, body: dict | None) -> list[dict]:
        """Extrae resultados del body o usa el historial."""
        if body and "resultados" in body:
            return body["resultados"]
        return list(scan_history)

    # ── Helpers ──────────────────────────────────────────────────

    def _read_body(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, ValueError):
            self._send_error(400, "JSON inválido en el cuerpo de la petición")
            return None

    def _serve_file(self, filepath: Path, content_type: str):
        try:
            data = filepath.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self._send_error(404, "Archivo no encontrado")

    def _send_json(self, status: int, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_download(self, data: bytes, filename: str, content_type: str):
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _send_error(self, status: int, message: str):
        self._send_json(status, {"error": message})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


class ThreadedHTTPServer(HTTPServer):
    """HTTPServer con soporte para múltiples conexiones concurrentes."""
    # En Windows, SO_REUSEADDR puede permitir que otro proceso quede escuchando el mismo
    # puerto; el tráfico entonces no llega al proceso que el usuario cree que inició.
    allow_reuse_address = False

    def process_request(self, request, client_address):
        t = threading.Thread(target=self._handle, args=(request, client_address))
        t.daemon = True
        t.start()

    def _handle(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


def main():
    parser = argparse.ArgumentParser(description="Byte-Shield Dashboard Web")
    parser.add_argument("--port", type=int, default=8080, help="Puerto del servidor (default: 8080)")
    parser.add_argument("--host", default="0.0.0.0", help="Host de escucha (default: 0.0.0.0)")
    args = parser.parse_args()

    # #region agent log
    _dbg_log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug-2bb79c.log")

    def _agent_dbg(
        hypothesis_id: str,
        location: str,
        message: str,
        data: dict | None = None,
        run_id: str = "pre-fix",
    ) -> None:
        try:
            with open(_dbg_log, "a", encoding="utf-8") as _f:
                _f.write(
                    json.dumps(
                        {
                            "sessionId": "2bb79c",
                            "timestamp": int(_time.time() * 1000),
                            "location": location,
                            "message": message,
                            "data": data or {},
                            "hypothesisId": hypothesis_id,
                            "runId": run_id,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
        except Exception:
            pass

    _agent_dbg(
        "H1-H5",
        "dashboard.py:main",
        "args_before_bind",
        {"host": args.host, "port": args.port, "pid": os.getpid()},
    )
    for _label, _addr in (
        ("H1_H2", (args.host, args.port)),
        ("H4", ("127.0.0.1", args.port)),
    ):
        try:
            _s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _s.bind(_addr)
            _s.close()
            _agent_dbg(_label, "dashboard.py:main", "probe_bind_ok", {"addr": list(_addr)})
        except OSError as _e:
            _agent_dbg(
                _label,
                "dashboard.py:main",
                "probe_bind_failed",
                {
                    "addr": list(_addr),
                    "errno": _e.errno,
                    "winerror": getattr(_e, "winerror", None),
                    "str": str(_e),
                },
            )
    # #endregion

    try:
        server = ThreadedHTTPServer((args.host, args.port), DashboardHandler)
    except OSError as e:
        # #region agent log
        _agent_dbg(
            "H1-H5",
            "dashboard.py:main",
            "ThreadedHTTPServer_failed",
            {
                "errno": e.errno,
                "winerror": getattr(e, "winerror", None),
                "str": str(e),
            },
        )
        # #endregion
        print(
            "\n\033[93m[!] No se pudo iniciar el servidor HTTP en "
            f"{args.host}:{args.port}.\033[0m\n"
            "    Suele deberse a que el puerto ya está en uso por otro programa.\n"
            "    • Comprueba con: netstat -ano | findstr :" + str(args.port) + "\n"
            "    • Prueba otro puerto: python dashboard.py --port 8765\n",
            file=sys.stderr,
        )
        sys.exit(1)

    # #region agent log
    _agent_dbg(
        "H1-H5",
        "dashboard.py:main",
        "ThreadedHTTPServer_ok",
        {"host": args.host, "port": args.port},
        run_id="post-fix",
    )
    # #endregion

    dash_path = Path(__file__).resolve()
    print(f"\n  \033[90mPID {os.getpid()} | {dash_path}\033[0m")
    print(f"  \033[90mDiagnóstico: GET http://localhost:{args.port}/api/server-info\033[0m\n")

    print(f"\n\033[1m\033[96m{'═'*60}\033[0m")
    print(f"\033[1m\033[96m  BYTE-SHIELD — Dashboard Web\033[0m")
    print(f"\033[96m  Servidor activo en: http://localhost:{args.port}\033[0m")
    print(f"\033[96m  Para exponer: ngrok http {args.port}\033[0m")
    print(f"\033[1m\033[96m{'═'*60}\033[0m\n")
    print(f"  \033[90mPresiona Ctrl+C para detener.\033[0m\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n\033[93m[!] Servidor detenido.\033[0m")
        server.server_close()


if __name__ == "__main__":
    main()
