
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def inspect_services():
    systemctl = shutil.which("systemctl")

    if systemctl is None:
        return [], ["systemctl is not installed"]

    try:
        result = subprocess.run(
            [
                systemctl,
                "list-unit-files",
                "--type=service",
                "--no-legend",
                "--no-pager",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], [str(exc)]

    if result.returncode != 0:
        return [], [
            result.stderr.strip() or "Unable to list service files"
        ]

    findings = []
    errors = []

    for line in result.stdout.splitlines():
        parts = line.split()

        if not parts or not parts[0].endswith(".service"):
            continue

        unit = parts[0]

        try:
            details = subprocess.run(
                [
                    systemctl,
                    "show",
                    unit,
                    "--property=User",
                    "--property=Group",
                    "--property=ExecStart",
                    "--property=FragmentPath",
                    "--no-pager",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            errors.append(f"Could not inspect {unit}")
            continue

        if details.returncode != 0:
            errors.append(f"Could not inspect {unit}")
            continue

        properties = {}

        for item in details.stdout.splitlines():
            if "=" in item:
                key, value = item.split("=", 1)
                properties[key] = value

        user = properties.get("User", "")
        exec_start = properties.get("ExecStart", "")
        fragment = properties.get("FragmentPath", "")

        # An empty User property generally means systemd's default
        # service user, usually root for system services.
        runs_as_root = user in ("", "root")

        if runs_as_root:
            findings.append({
                "service": unit,
                "configured_user": user or "(default)",
                "exec_start": exec_start,
                "unit_file": fragment,
                "finding_type": "root_service_review",
                "severity": "informational",
                "reason": (
                    "Review executable ownership, file permissions, "
                    "and referenced paths. A root service alone "
                    "does not prove a vulnerability."
                ),
            })

    return findings, errors


def main():
    findings, errors = inspect_services()

    report = {
        "scan_time_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "scan_type": "systemd service configuration audit",
        "mode": "detection-only",
        "findings_count": len(findings),
        "errors": errors,
        "findings": findings,
    }

    output = Path("reports/services_report.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("=" * 45)
    print(" SYSTEMD SERVICE AUDIT")
    print("=" * 45)
    print("Services requiring review:", len(findings))
    print("Inspection errors:", len(errors))
    print("Report saved to:", output)


if __name__ == "__main__":
    main()
