import getpass
import os
import platform
import json
from datetime import datetime, timezone
from pathlib import Path


def collect_system_info():
    return {
        "tool_name": "Linux Privilege Escalation Audit Toolkit",
        "version": "0.1.0",
        "scan_mode": "detection-only",
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "system": {
            "operating_system": platform.system(),
            "kernel_version": platform.release(),
            "architecture": platform.machine(),
        },
        "user": {
            "username": getpass.getuser(),
            "user_id": os.getuid(),
            "is_root": os.getuid() == 0,
        },
    }


def main():
    report = collect_system_info()

    output = Path("reports/system_info.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("=" * 50)
    print(" LINUX SECURITY AUDIT TOOLKIT")
    print("=" * 50)
    print("Operating system:", report["system"]["operating_system"])
    print("Kernel:", report["system"]["kernel_version"])
    print("Username:", report["user"]["username"])
    print("User ID:", report["user"]["user_id"])
    print("Running as root:", report["user"]["is_root"])
    print("Report saved to:", output)
    print("Scan mode: Detection-only")


if __name__ == "__main__":
    main()
