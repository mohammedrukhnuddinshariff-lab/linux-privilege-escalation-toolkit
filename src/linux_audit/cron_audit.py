
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path


CRON_PATHS = [
    Path("/etc/crontab"),
    Path("/etc/cron.d"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
]


def inspect_path(path):
    """Inspect a cron path without executing or modifying it."""
    findings = []
    errors = []

    try:
        info = path.lstat()
    except FileNotFoundError:
        return findings, errors
    except OSError as exc:
        return findings, [f"{path}: {exc}"]

    if stat.S_ISLNK(info.st_mode):
        return findings, errors

    if stat.S_ISREG(info.st_mode):
        candidates = [path]
    elif stat.S_ISDIR(info.st_mode):
        candidates = []

        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        continue
                    if entry.is_file(follow_symlinks=False):
                        candidates.append(Path(entry.path))
        except OSError as exc:
            errors.append(f"{path}: {exc}")
    else:
        return findings, errors

    for candidate in candidates:
        try:
            item = candidate.lstat()

            if not stat.S_ISREG(item.st_mode):
                continue

            # A world-writable cron file deserves review.
            if item.st_mode & stat.S_IWOTH:
                findings.append({
                    "path": str(candidate),
                    "permissions": oct(
                        stat.S_IMODE(item.st_mode)
                    ),
                    "owner_uid": item.st_uid,
                    "group_gid": item.st_gid,
                    "severity": "high_review",
                    "reason": (
                        "Cron configuration or script is "
                        "world-writable. Verify whether it "
                        "can affect a privileged scheduled task."
                    ),
                })

        except OSError as exc:
            errors.append(f"{candidate}: {exc}")

    return findings, errors


def main():
    findings = []
    errors = []

    for path in CRON_PATHS:
        path_findings, path_errors = inspect_path(path)
        findings.extend(path_findings)
        errors.extend(path_errors)

    report = {
        "scan_time_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "scan_type": "cron permission audit",
        "mode": "detection-only",
        "paths_checked": [str(path) for path in CRON_PATHS],
        "findings_count": len(findings),
        "errors": errors,
        "findings": findings,
        "note": (
            "This initial version checks permissions only. "
            "It does not execute cron jobs or verify every "
            "script referenced by scheduled tasks."
        ),
    }

    output = Path("reports/cron_report.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("=" * 45)
    print(" CRON SECURITY AUDIT")
    print("=" * 45)
    print("Findings:", len(findings))
    print("Inspection errors:", len(errors))
    print("Report saved to:", output)


if __name__ == "__main__":
    main()
