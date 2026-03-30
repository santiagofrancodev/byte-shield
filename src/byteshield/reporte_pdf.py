"""Exportación PDF opcional vía WeasyPrint (extra ``[pdf]``)."""

from __future__ import annotations


def export_pdf(html_content: str, output_path: str) -> str:
    """
    Convierte HTML en PDF. Requiere: pip install weasyprint
    y dependencias de sistema (libcairo, pango) en Linux/Docker.
    """
    try:
        from weasyprint import HTML as WeasyprintHTML
    except ImportError as e:
        raise RuntimeError(
            "weasyprint no está instalado. Instala con: pip install weasyprint"
        ) from e

    WeasyprintHTML(string=html_content).write_pdf(output_path)
    return output_path
