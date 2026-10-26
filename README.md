# Linux Privilege Escalation Automation Toolkit

A Python-based Linux security auditing toolkit that automates the discovery of selected configuration risks that may contribute to local privilege escalation.

## Overview

The toolkit collects system information, performs selected filesystem and configuration checks, and generates JSON and HTML reports. It is designed for authorized security auditing, learning, and defensive assessment.

## Features

- **System Information:** Collects OS, kernel, architecture, and current-user details.
- **SUID/SGID Discovery:** Identifies selected SUID/SGID files for review.
- **File Permissions Audit:** Checks selected locations for world-writable files.
- **Linux Capabilities:** Collects available capability information.
- **Sudo Audit:** Reports the current user's sudo permissions when available without prompting for a password.
- **Systemd Service Review:** Collects selected service configuration details.
- **Cron Permissions Audit:** Checks selected cron locations for risky file permissions.
- **Kernel Information:** Records kernel details. Automated CVE matching is not currently implemented.
- **Reporting:** Generates JSON reports, a unified findings report, and an HTML report.

## Technology Stack

- Python 3
- Linux / Kali Linux
- Bash and standard Linux utilities
- JSON
- HTML
- pytest

## Project Structure

```text
linux-privilege-escalation-toolkit/
├── src/
│   └── linux_audit/
│       ├── collector.py
│       ├── suid_sgid.py
│       ├── permissions.py
│       ├── capabilities.py
│       ├── sudo_audit.py
│       ├── services.py
│       ├── cron_audit.py
│       ├── kernel_cve.py
│       ├── reporting.py
│       ├── html_report.py
│       └── main.py
├── tests/
│   └── test_reporting.py
├── reports/
├── docs/
└── README.md
```

## Setup

Tested development environment: Kali Linux with Python 3.

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd linux-privilege-escalation-toolkit

python3 -m venv .venv
source .venv/bin/activate

python -m pip install pytest
```

The repository URL above is a placeholder. Replace it with your actual repository URL before publishing.

## Usage

Run all available scan modules:

```bash
PYTHONPATH=src python -m linux_audit.main --scan all
```

Run an individual module, for example:

```bash
PYTHONPATH=src python -m linux_audit.main --scan system
PYTHONPATH=src python -m linux_audit.main --scan suid
PYTHONPATH=src python -m linux_audit.main --scan permissions
```

Generate the unified findings report:

```bash
PYTHONPATH=src python -m linux_audit.reporting
```

Generate the HTML report:

```bash
PYTHONPATH=src python -m linux_audit.html_report
```

Open the report:

```bash
xdg-open reports/security_report.html
```

Run tests:

```bash
PYTHONPATH=src python -m pytest -v
```

## Output

Reports are written to the `reports/` directory in JSON and HTML formats. Review the generated findings and scanner status before drawing security conclusions.

## Safety

- Use only on systems you own or have explicit permission to audit.
- The toolkit is designed for detection and reporting, not exploitation.
- Do not execute discovered binaries or attempt to obtain elevated privileges.
- Review commands and results before running the toolkit on production systems.

## Limitations

This is a learning and portfolio project, not a complete vulnerability scanner. Checks cover selected paths and configurations, so findings may be incomplete. A discovered configuration is not automatically exploitable. Kernel CVE matching is not implemented, and results require manual verification.

## Testing

Run the automated tests with:

```bash
PYTHONPATH=src python -m pytest -v
```

## Future Improvements

- Expand unit tests and add safe fixture-based scanner tests.
- Improve coverage of cron jobs and referenced script permissions.
- Add evidence and remediation guidance to findings.
- Implement verified kernel version-to-CVE matching using a trusted data source.
- Add severity classification and machine-readable report schemas.

## Disclaimer

This project is intended for authorized security auditing, defensive education, and research in controlled environments. The author is not responsible for unauthorized use.
