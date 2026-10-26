import os
import json
import stat
from pathlib import Path
from datetime import datetime, timezone


def scan_suid_sgid(root="/usr/bin"):
    findings = []

    base = Path(root)

    if not base.exists():
        return findings

    for current_dir, dirs, files in os.walk(
        base, followlinks=False
    ):
        dirs[:] = [
            name for name in dirs
            if not (Path(current_dir) / name).is_symlink()
        ]

        for name in files:
            path = Path(current_dir) / name

            try:
                file_stat = path.lstat()

                if not stat.S_ISREG(file_stat.st_mode):
                    continue

                permissions = file_stat.st_mode
                special_bits = []

                if permissions & stat.S_ISUID:
                    special_bits.append("SUID")

                if permissions & stat.S_ISGID:
                    special_bits.append("SGID")

                if special_bits:
                    findings.append({
                        "path": str(path),
                        "permissions": oct(
                            stat.S_IMODE(permissions)
                        ),
                        "special_bits": special_bits,
                        "owner_uid": file_stat.st_uid,
                        "group_gid": file_stat.st_gid,
                        "finding_type": "special_permission_binary",
                        "severity": "requires_review",
                    })

            except (OSError, PermissionError):
                continue

    return findings


def main():
    findings = scan_suid_sgid()

    report = {
        "scan_time_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "scan_type": "SUID/SGID discovery",
        "mode": "detection-only",
        "scope": "/usr/bin",
        "total_findings": len(findings),
        "findings": findings,
        "note": (
            "Special permission bits require review; "
            "their presence alone does not prove a vulnerability."
        ),
    }

    output = Path("reports/suid_sgid_report.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2))

    print("SUID/SGID scan completed.")
    print("Files requiring review:", len(findings))
    print("Report saved to:", output)


if __name__ == "__main__":
    main()
