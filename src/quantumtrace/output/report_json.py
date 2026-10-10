"""Native ScanResult JSON and atomic JSON file persistence."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from quantumtrace.models import ScanResult


def render_json_document(document: dict[str, Any]) -> str:
    """Serialize one JSON document exactly as the report files contain it."""
    return json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2) + "\n"


def write_json_document(document: dict[str, Any], path: str | Path) -> None:
    """Serialize before touching the destination, then replace it atomically.

    File failures propagate as OSError with destination context. An unsuccessful
    write leaves the previous destination intact and cleans the temporary file.
    """
    payload = render_json_document(document)
    target = Path(path)
    temporary: Path | None = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except OSError as exc:
        raise OSError(f"cannot write JSON report {target}: {exc}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_report_json(result: ScanResult, path: str | Path) -> None:
    """Write the frozen native contract, retaining errors and optional roadmap."""
    write_json_document(result.model_dump(mode="json"), path)
