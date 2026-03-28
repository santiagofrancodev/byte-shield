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
import datetime
import argparse
import threading
import mimetypes
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from tls_scanner import (
    validar_objetivo,
    escanear_puerto,
    auditar_tls_en_puerto,
    calcular_criticidad,
    CONNECT_TIMEOUT,
)
from generar_reporte import generar_html

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

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
        else:
            self._send_error(404, "Ruta no encontrada")

    # ── POST ─────────────────────────────────────────────────────

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/scan/stream":
            self._handle_scan_stream()
        elif path == "/api/export/json":
            self._handle_export_json()
        elif path == "/api/export/csv":
            self._handle_export_csv()
        elif path == "/api/export/html":
            self._handle_export_html()
        else:
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
    allow_reuse_address = True

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

    server = ThreadedHTTPServer((args.host, args.port), DashboardHandler)

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
