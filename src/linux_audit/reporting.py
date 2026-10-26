
import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = PROJECT_ROOT / "reports"

REPORT_FILES = {
    "suid_sgid": "suid_sgid_report.json",
    "permissions": "permissions_report.json",
    "capabilities": "capabilities_report.json",
    "services": "services_report.json",
    "cron": "cron_report.json",
}


def load_json(path):
    try:
        with path.open(encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        return {"_load_error": str(exc)}


def normalize_findings(category, report):
    findings = report.get("findings", [])

    if not isinstance(findings, list):
        return []

    normalized = []

    for item in findings:
        if not isinstance(item, dict):
            continue

        normalized.append({
            "category": category,
            "finding_type": item.get(
                "finding_type", category
            ),
            "title": (
                f"{category.replace('_', ' ').title()} finding"
            ),
            "severity": item.get(
                "severity", "requires_review"
            ),
            "confidence": "unassessed",
            "evidence": item,
            "remediation": (
                "Review the evidence and apply the appropriate "
                "security hardening guidance."
            ),
        })

    return normalized


def main():
    findings = []
    scan_status = {}

    for category, filename in REPORT_FILES.items():
        path = REPORTS_DIR / filename

        if not path.exists():
            scan_status[category] = "report_missing"
            continue

        report = load_json(path)

        if "_load_error" in report:
            scan_status[category] = "report_unreadable"
            continue

        scan_status[category] = "report_loaded"
        findings.extend(normalize_findings(category, report))

    summary = {}

    for finding in findings:
        severity = finding["severity"]
        summary[severity] = summary.get(severity, 0) + 1

    unified = {
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "tool": "Linux Privilege Escalation Audit Toolkit",
        "mode": "detection-only",
        "scan_status": scan_status,
        "summary": {
            "total_findings": len(findings),
            "by_severity": summary,
        },
        "findings": findings,
        "limitations": [
            "Only existing reports were processed.",
            "Missing reports do not mean a system is secure.",
            "Findings require manual validation.",
            "Severity labels from early scanner versions "
            "are preliminary and not validated risk scores.",
        ],
    }

    output = REPORTS_DIR / "unified_report.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(unified, indent=2),
        encoding="utf-8",
    )

    print("Unified report generated:", output)
    print("Total findings:", len(findings))
    print("Report status:", scan_status)


if __name__ == "__main__":
    main()
