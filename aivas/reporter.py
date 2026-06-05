from __future__ import annotations

import importlib
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _render(findings: list[dict], meta: dict) -> str:
    env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)
    template = env.get_template("report.html.j2")
    return template.render(findings=findings, meta=meta)


def generate_report(
    findings: list[dict],
    output_path: str | Path,
    meta: dict | None = None,
) -> Path:
    output_path = Path(output_path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    resolved_meta = {"title": "AIVAS Vulnerability Report", "generated_at": now, "target": None}
    if meta:
        resolved_meta.update(meta)

    html = _render(findings, resolved_meta)

    if output_path.suffix.lower() == ".pdf":
        weasyprint = importlib.import_module("weasyprint")
        weasyprint.HTML(string=html).write_pdf(str(output_path))
    else:
        output_path.write_text(html, encoding="utf-8")

    return output_path
