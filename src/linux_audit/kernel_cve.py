import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def get_os_release():
    """Collect distribution information from /etc/os-release."""
    info = {}

    try:
        with open("/etc/os-release", encoding="utf-8") as file:
            for line in file:
                if "=" in line:
                    key, value = line.rstrip().split("=", 1)
                    info[key] = value.strip().strip('"')
    except OSError as exc:
        return {"error": str(exc)}

    return {
        "name": info.get("PRETTY_NAME", "Unknown"),
        "id": info.get("ID", "unknown"),
        "version": info.get("VERSION_ID", "unknown"),
    }


def get_kernel_information():
    """Collect kernel information without running any exploits."""
    return {
        "kernel_release": platform.release(),
        "architecture": platform.machine(),
        "operating_system": get_os_release(),
    }


def main():
    system_info = get_kernel_information()

    report = {
        "scan_time_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "scan_type": "kernel vulnerability assessment",
        "mode": "detection-only",
        "system": system_info,
        "cve_assessment": {
            "status": "not_performed",
            "matched_cves": [],
            "note": (
                "No CVE database matching has been performed yet. "
                "Kernel version information alone cannot establish "
                "whether a vulnerability is present."
            ),
        },
    }

    output = Path("reports/kernel_report.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("=" * 45)
    print(" KERNEL SECURITY ASSESSMENT")
    print("=" * 45)
    print("Kernel:", system_info["kernel_release"])
    print("Architecture:", system_info["architecture"])
    print("OS:", system_info["operating_system"]["name"])
    print("CVE matching: Not implemented yet")
    print("Report saved to:", output)


if __name__ == "__main__":
    main()
