import json
import os
import stat
from pathlib import Path
from datetime import datetime, timezone


def scan_world_writable(root="/tmp"):
    findings = []
    scanned_files = 0
    errors = 0

    base = Path(root)

    if not base.exists():
        return findings, scanned_files, 1

    for current_dir, dirs, files in os.walk(
        base, followlinks=False
    ):
        # Do not follow symbolic links to other directories.
        dirs[:] = [
            name for name in dirs
            if not (Path(current_dir) / name).is_symlink()
        ]

        for name in files:
            path = Path(current_dir) / name

            try:
                info = path.lstat()
                scanned_files += 1

                # Inspect regular files only.
                if not stat.S_ISREG(info.st_mode):
                    continue

                # Check whether the "others" write bit is set.
                if info.st_mode & stat.S_IWOTH:
                    findings.append({
                        "path": str(path),
                        "permissions": oct(
                            stat.S_IMODE(info.st_mode)
                        ),
                        "owner_uid": info.st_uid,
                        "group_gid": info.st_gid,
                        "severity": "requires_review",
                        "reason": (
                            "The file is writable by all users. "
                            "Review its purpose and usage."
                        ),
                    })

            except OSError:
                errors += 1

    return findings, scanned_files, errors


def main():
    findings, scanned, errors = scan_world_writable()

    report = {
        "scan_time_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "scan_type": "world-writable file audit",
        "mode": "detection-only",
        "scope": "/tmp",
        "files_scanned": scanned,
        "findings_count": len(findings),
        "errors_count": errors,
        "findings": findings,
        "note": (
            "World-writable permissions alone do not prove "
            "a privilege escalation vulnerability."
        ),
    }

    output = Path("reports/permissions_report.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2))

    print("=" * 45)
    print(" FILE PERMISSION AUDIT")
    print("=" * 45)
    print("Files inspected:", scanned)
    print("Findings:", len(findings))
    print("Inspection errors:", errors)
    print("Report saved to:", output)


if __name__ == "__main__":
    main()
