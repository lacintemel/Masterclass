from __future__ import annotations

import html

from .base import BaseReporter
from ..core.models import AnalysisResult


class HTMLReporter(BaseReporter):
    """Render a self-contained analyst report as HTML."""

    format_name = "html"
    file_extension = ".html"

    def generate(self, result: AnalysisResult) -> str:
        findings = "\n".join(self._finding_row(finding.to_dict()) for finding in result.findings)
        iocs = "\n".join(self._ioc_row(ioc.to_dict()) for ioc in result.iocs)
        metadata = "\n".join(
            self._kv_row(key, value) for key, value in result.metadata.items() if value is not None
        )
        recommendations = "\n".join(
            f"<li>{html.escape(item)}</li>" for item in result.recommendations
        )

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MODA Report - {html.escape(result.file_name)}</title>
  <style>
    :root {{
      --bg: #11110f;
      --panel: #1f1f1b;
      --line: #39382f;
      --text: #f4efe4;
      --muted: #aaa08f;
      --gold: #d6b46a;
      --red: #e05a47;
      --green: #6fcf97;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--text);
      background: var(--bg);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    main {{ width: min(1180px, calc(100% - 32px)); margin: 24px auto; }}
    header, section {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      margin-bottom: 14px;
      padding: 18px;
    }}
    h1, h2, p {{ margin: 0; }}
    h1 {{ font-size: 2rem; }}
    h2 {{ font-size: 1rem; margin-bottom: 12px; color: var(--gold); text-transform: uppercase; }}
    .subtitle, .muted {{ color: var(--muted); }}
    .risk {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      margin-top: 18px;
    }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      overflow-wrap: anywhere;
    }}
    .metric span {{ display: block; color: var(--muted); font-size: .78rem; text-transform: uppercase; }}
    .metric strong {{ display: block; margin-top: 4px; font-size: 1.15rem; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-size: .78rem; text-transform: uppercase; }}
    .badge {{
      display: inline-block;
      border-radius: 8px;
      padding: 3px 8px;
      background: var(--gold);
      color: #15120c;
      font-size: .75rem;
      font-weight: 800;
      text-transform: uppercase;
    }}
    .badge.high, .badge.critical {{ background: var(--red); color: white; }}
    .badge.low {{ background: var(--green); color: #07130c; }}
    code {{ overflow-wrap: anywhere; }}
    @media print {{ body {{ background: white; color: #111; }} header, section {{ break-inside: avoid; }} }}
  </style>
</head>
<body>
  <main>
    <header>
      <p class="subtitle">MODA - Malicious Office Document Analyzer</p>
      <h1>{html.escape(result.file_name)}</h1>
      <div class="risk">
        <div class="metric"><span>Risk</span><strong>{html.escape(result.risk_level.upper())}</strong></div>
        <div class="metric"><span>Score</span><strong>{result.risk_score}/100</strong></div>
        <div class="metric"><span>Findings</span><strong>{len(result.findings)}</strong></div>
        <div class="metric"><span>IOCs</span><strong>{len(result.iocs)}</strong></div>
      </div>
    </header>
    <section>
      <h2>File</h2>
      <table>
        {self._kv_row("Path", result.file_path)}
        {self._kv_row("Type", result.file_type)}
        {self._kv_row("MIME", result.mime_type)}
        {self._kv_row("Size", f"{result.file_size} bytes")}
        {self._kv_row("MD5", result.file_hash_md5)}
        {self._kv_row("SHA1", result.file_hash_sha1)}
        {self._kv_row("SHA256", result.file_hash_sha256)}
      </table>
    </section>
    <section>
      <h2>Findings</h2>
      <table>
        <thead><tr><th>Severity</th><th>Title</th><th>Description</th><th>Analyzer</th></tr></thead>
        <tbody>{findings or '<tr><td colspan="4" class="muted">No findings</td></tr>'}</tbody>
      </table>
    </section>
    <section>
      <h2>Indicators</h2>
      <table>
        <thead><tr><th>Type</th><th>Value</th><th>Source</th></tr></thead>
        <tbody>{iocs or '<tr><td colspan="3" class="muted">No indicators</td></tr>'}</tbody>
      </table>
    </section>
    <section>
      <h2>Metadata</h2>
      <table>{metadata or '<tr><td class="muted">No metadata extracted</td></tr>'}</table>
    </section>
    <section>
      <h2>Recommendations</h2>
      <ul>{recommendations}</ul>
    </section>
  </main>
</body>
</html>
"""

    def _finding_row(self, finding: dict[str, object]) -> str:
        severity = html.escape(str(finding.get("severity", "info")))
        return (
            "<tr>"
            f'<td><span class="badge {severity}">{severity}</span></td>'
            f"<td>{html.escape(str(finding.get('title', '')))}</td>"
            f"<td>{html.escape(str(finding.get('description', '')))}</td>"
            f"<td>{html.escape(str(finding.get('analyzer', '')))}</td>"
            "</tr>"
        )

    def _ioc_row(self, ioc: dict[str, object]) -> str:
        return (
            "<tr>"
            f"<td>{html.escape(str(ioc.get('ioc_type', '')))}</td>"
            f"<td><code>{html.escape(str(ioc.get('value', '')))}</code></td>"
            f"<td>{html.escape(str(ioc.get('source', '')))}</td>"
            "</tr>"
        )

    def _kv_row(self, key: str, value: object) -> str:
        return (
            "<tr>"
            f"<th>{html.escape(str(key))}</th>"
            f"<td><code>{html.escape(str(value))}</code></td>"
            "</tr>"
        )
