import json

from linux_audit.reporting import (
    load_json,
    normalize_findings,
)


def test_normalize_finding():
    sample = {
        "findings": [
            {
                "path": "/tmp/example.txt",
                "severity": "requires_review",
            }
        ]
    }

    result = normalize_findings("permissions", sample)

    assert len(result) == 1
    assert result[0]["category"] == "permissions"
    assert result[0]["severity"] == "requires_review"
    assert result[0]["evidence"]["path"] == "/tmp/example.txt"


def test_load_json(tmp_path):
    report_file = tmp_path / "sample.json"
    report_file.write_text(
        json.dumps({"findings": []}),
        encoding="utf-8",
    )

    result = load_json(report_file)

    assert result == {"findings": []}
