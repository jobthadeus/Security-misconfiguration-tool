"""
JSON report export.

Structured output suitable for SIEM ingestion, diffing scans over time,
or integration with other security tooling.
"""

from __future__ import annotations

import json
from pathlib import Path

from utils.models import ScanResult


def export_json_report(result: ScanResult, output_path: str | Path | None = None) -> str:
    """
    Serialize a ScanResult to JSON.

    Returns the JSON string. Optionally writes to disk.
    """
    payload = json.dumps(result.to_dict(), indent=2)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")

    return payload
