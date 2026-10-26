import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def audit_sudo():
    sudo_path = shutil.which("sudo")

    if sudo_path is None:
        return {
            "status": "unavailable",
            "rules": [],
            "error": "sudo command was not found",
        }

    try:
        result = subprocess.run(
            [sudo_path, "-n", "-l"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        output = result.stdout.strip()
        error = result.stderr.strip()

        if result.returncode == 0:
            status = "completed"
        elif "password" in error.lower():
            status = "authentication_required"
        else:
            status = "incomplete"

        return {
            "status": status,
            "return_code": result.returncode,
            "rules": output.splitlines() if output else [],
            "error": error or None,
            "note": (
                "Rules are recorded for review. "
                "No privileged commands were executed."
            ),
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "rules": [],
            "error": "sudo listing exceeded the time limit",
        }
    except OSError as exc:
        return {
            "status": "error",
            "rules": [],
            "error": str(exc),
        }


def main():
    report = {
        "scan_time_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "scan_type": "sudo configuration audit",
        "mode": "detection-only",
        "result": audit_sudo(),
    }

    output = Path("reports/sudo_audit_report.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("=" * 45)
    print(" SUDO CONFIGURATION AUDIT")
    print("=" * 45)
    print("Status:", report["result"]["status"])
    print("Report saved to:", output)
    print("Mode: Detection-only")


if __name__ == "__main__":
    main()
