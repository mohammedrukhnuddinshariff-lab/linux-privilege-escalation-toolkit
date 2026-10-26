
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCANNERS = {
    "system": "collector.py",
    "suid": "suid_sgid.py",
    "permissions": "permissions.py",
    "capabilities": "capabilities.py",
    "sudo": "sudo_audit.py",
    "services": "services.py",
    "cron": "cron_audit.py",
    "kernel": "kernel_cve.py",
}


def run_scanner(name, filename):
    scanner_path = Path(__file__).parent / filename

    env = os.environ.copy()
    source_dir = str(PROJECT_ROOT / "src")
    existing_path = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        source_dir + os.pathsep + existing_path
        if existing_path else source_dir
    )

    try:
        result = subprocess.run(
            [sys.executable, str(scanner_path)],
            cwd=PROJECT_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )

        return {
            "scanner": name,
            "status": (
                "completed" if result.returncode == 0
                else "failed"
            ),
            "return_code": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }

    except subprocess.TimeoutExpired:
        return {
            "scanner": name,
            "status": "timeout",
            "error": "Scanner exceeded 90 seconds",
        }
    except OSError as exc:
        return {
            "scanner": name,
            "status": "error",
            "error": str(exc),
        }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Linux Privilege Escalation Audit Toolkit "
            "(detection-only)"
        )
    )
    parser.add_argument(
        "--scan",
        choices=["all", *SCANNERS.keys()],
        default="all",
        help="Choose a scanner to run",
    )
    args = parser.parse_args()

    selected = (
        SCANNERS.items()
        if args.scan == "all"
        else [(args.scan, SCANNERS[args.scan])]
    )

    print("=" * 60)
    print(" LINUX PRIVILEGE ESCALATION AUDIT TOOLKIT")
    print(" Mode: Detection-only")
    print("=" * 60)

    results = []

    for name, filename in selected:
        print(f"\n[*] Running {name} audit...")
        result = run_scanner(name, filename)
        results.append(result)
        print(f"[{result['status'].upper()}] {name}")

        if result.get("stdout"):
            print(result["stdout"])

        if result.get("stderr"):
            print("Diagnostic:", result["stderr"])

    report = {
        "scan_time_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "mode": "detection-only",
        "results": results,
        "completed": sum(
            item["status"] == "completed"
            for item in results
        ),
        "total_scanners": len(results),
    }

    output = PROJECT_ROOT / "reports" / "toolkit_report.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("\n" + "=" * 60)
    print(
        f"Scanners completed: "
        f"{report['completed']}/{report['total_scanners']}"
    )
    print(f"Combined report: {output}")
    print("=" * 60)


if __name__ == "__main__":
    main()
