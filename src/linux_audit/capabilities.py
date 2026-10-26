import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def scan_capabilities(root="/usr/bin"):
    findings = []
    errors = []

    executable = shutil.which("getcap")

    if executable is None:
        return findings, ["getcap is not installed"]

    try:
        result = subprocess.run(
            [executable, "-r", root],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return findings, [str(exc)]

    for line in result.stdout.splitlines():
        if "=" not in line:
            continue

        path, capabilities = line.split("=", 1)

        findings.append({
            "path": path.strip(),
            "capabilities": capabilities.strip(),
            "severity": "requires_review",
            "reason": (
                "Review whether these capabilities are "
                "necessary for this executable."
            ),
        })

    if result.returncode != 0:
        errors.append(
            result.stderr.strip()
            or f"getcap exited with code {result.returncode}"
        )

    return findings, errors


def main():
    root = "/usr/bin"
    findings, errors = scan_capabilities(root)

    report = {
        "scan_time_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "scan_type": "Linux file capabilities audit",
        "mode": "detection-only",
        "scope": root,
        "findings_count": len(findings),
        "errors": errors,
        "findings": findings,
        "note": (
            "Capabilities require contextual review; their "
            "presence alone does not prove a vulnerability."
        ),
    }

    output = Path("reports/capabilities_report.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("=" * 45)
    print(" LINUX CAPABILITIES AUDIT")
    print("=" * 45)
    print("Findings:", len(findings))
    print("Errors:", len(errors))
    print("Report saved to:", output)


if __name__ == "__main__":
    main()
