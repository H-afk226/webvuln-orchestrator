"""HTML report generation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.correlate import Correlation

TEMPLATE_DIR = Path(__file__).parent / "templates"


def render(corr: Correlation, out_path: Path) -> Path:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    tpl = env.get_template("report.html.j2")

    toolnames = sorted({r.tool for r in corr.results})
    html = tpl.render(
        c=corr,
        sev=corr.by_severity(),
        owasp=corr.by_owasp(),
        tools=corr.by_tool(),
        toolnames=toolnames,
        matrix=corr.agreement_matrix(),
        coverage=corr.owasp_coverage_by_tool(),
        top=corr.top_findings(25),
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)
    return out_path
