"""PDF report generation — converts the HTML report to PDF via WeasyPrint."""
from __future__ import annotations

import sqlite3

from .report_gen import generate_html_report

_PRINT_CSS = """\
@page { size: A4; margin: 0; }
.no-print { display: none !important; }
.rpt-header { -weasy-background-paint-area: border-box; }
"""


def generate_pdf_report(conn: sqlite3.Connection, scan_id: int) -> bytes | None:
    """Return PDF bytes for the given scan, or None if scan not found."""
    html = generate_html_report(conn, scan_id)
    if html is None:
        return None
    from weasyprint import HTML, CSS
    return HTML(string=html, base_url="about:blank").write_pdf(
        stylesheets=[CSS(string=_PRINT_CSS)]
    )
