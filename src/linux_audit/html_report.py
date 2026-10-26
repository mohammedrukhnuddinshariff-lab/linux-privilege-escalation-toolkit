
import html
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INPUT_FILE = PROJECT_ROOT / "reports" / "unified_report.json"
OUTPUT_FILE = PROJECT_ROOT / "reports" / "security_report.html"


def render_report(report):
    summary = report.get("summary", {})
    findings = report.get("findings", [])

    rows = []

    for finding in findings:
        evidence = json.dumps(
            finding.get("evidence", {}),
            indent=2,
            ensure_ascii=False,
        )

        rows.append(
            "<tr>"
            f"<td>{html.escape(str(finding.get('category', 'Unknown')))}</td>"
            f"<td>{html.escape(str(finding.get('severity', 'Unassessed')))}</td>"
            f"<td>{html.escape(str(finding.get('title', 'Finding')))}</td>"
            f"<td><pre>{html.escape(evidence)}</pre></td>"
            "</tr>"
        )

    if not rows:
        rows.append(
            '<tr><td colspan="4">No findings in the loaded report. '
            'This does not prove the system is secure.</td></tr>'
        )

    total = summary.get("total_findings", len(findings))
    generated = report.get("generated_at_utc", "Unknown")
    scan_status = report.get("scan_status", {})

    status_items = "".join(
        "<li>"
        f"{html.escape(str(name))}: "
        f"{html.escape(str(status))}"
        "</li>"
        for name, status in scan_status.items()
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Linux Security Audit Report</title>
<style>
body {{
    font-family: system-ui, sans-serif;
    max-width: 1100px;
    margin: 35px auto;
    padding: 0 20px;
    background: #101827;
    color: #e5e7eb;
}}
h1, h2 {{ color: #7dd3fc; }}
.card {{
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 18px;
    margin: 18px 0;
}}
table {{
    border-collapse: collapse;
    width: 100%;
    background: #1e293b;
}}
th, td {{
    padding: 12px;
    text-align: left;
    border: 1px solid #334155;
    vertical-align: top;
}}
th {{ background: #263449; }}
pre {{
    white-space: pre-wrap;
    overflow-wrap: anywhere;
}}
.muted {{ color: #94a3b8; }}
@media print {{
    body {{ background: white; color: black; }}
    .card, table {{ background: white; color: black; }}
    h1, h2 {{ color: black; }}
}}
</style>
</head>
<body>
<h1>Linux Privilege Escalation Audit Toolkit</h1>
<p class="muted">Detection-only security assessment</p>

<section class="card">
<h2>Executive Summary</h2>
<p>Total recorded findings: <strong>{html.escape(str(total))}</strong></p>
<p>Report generated: {html.escape(str(generated))}</p>
<p>Severity counts: {html.escape(json.dumps(summary.get("by_severity", {})))}</p>
</section>

<section class="card">
<h2>Scanner Status</h2>
<ul>{status_items or '<li>No scanner status recorded</li>'}</ul>
</section>

<section class="card">
<h2>Findings</h2>
<table>
<thead><tr><th>Category</th><th>Severity</th>
<th>Finding</th><th>Evidence</th></tr></thead>
<tbody>
{"".join(rows)}
</tbody>
</table>
</section>

<section class="card">
<h2>Limitations</h2>
<ul>
{"".join("<li>" + html.escape(str(item)) + "</li>" for item in report.get("limitations", []))}
</ul>
<p>Review the evidence before making security decisions.
Missing or inaccessible scan data must not be interpreted as proof
that the system is secure.</p>
</section>
</body>
</html>"""


def main():
    if not INPUT_FILE.exists():
        print("Unified report not found:", INPUT_FILE)
        print("Run the scanners and reporting module first.")
        raise SystemExit(1)

    try:
        report = json.loads(INPUT_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print("Could not read unified report:", exc)
        raise SystemExit(1)

    if not isinstance(report, dict):
        print("Invalid report format: expected a JSON object.")
        raise SystemExit(1)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(render_report(report), encoding="utf-8")

    print("HTML report generated:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
