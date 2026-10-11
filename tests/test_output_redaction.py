"""Private key bodies and unresolved assets in the served outputs (M3M4-05, M4 promise: no key material).

Key files are generated per run and are throwaways. The API routes are called directly, as in
test_api_result.py, because httpx is not installed.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import api.main as main
from quantumtrace import pipeline
from quantumtrace.models import Finding, KindHint, Location, ScanResult, SourceType
from quantumtrace.output.cyclonedx import build_cbom, redact_result, redact_snippet, validate_cbom
from quantumtrace.output.markdown import render_markdown_summary

ROOT = Path(__file__).resolve().parent.parent
HEADER = "-----BEGIN PRIVATE KEY-----"


def _write_keys(directory: Path) -> list[str]:
    """Throwaway private keys in four spellings; returns every body line (the text that must never be served)."""
    rsa_key = rsa.generate_private_key(65537, 2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    files = {
        "server.key": rsa_key.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()),
        "legacy.pem": rsa_key.private_bytes(
            s.Encoding.PEM, s.PrivateFormat.TraditionalOpenSSL, s.NoEncryption()
        ),
        "enc.key": rsa_key.private_bytes(
            s.Encoding.PEM, s.PrivateFormat.PKCS8, s.BestAvailableEncryption(b"throwaway")
        ),
        "id_ecdsa": ec_key.private_bytes(s.Encoding.PEM, s.PrivateFormat.OpenSSH, s.NoEncryption()),
    }
    bodies: list[str] = []
    for name, data in files.items():
        (directory / name).write_bytes(data)
        bodies += [line for line in data.decode().splitlines() if line and not line.startswith("-----")]
    return bodies


@pytest.fixture(scope="module")
def keys_result(tmp_path_factory: pytest.TempPathFactory) -> tuple[ScanResult, list[str]]:
    repo = tmp_path_factory.mktemp("keys")
    bodies = _write_keys(repo)
    return pipeline.run([repo]), bodies


def _everything(result: ScanResult) -> str:
    return "\n".join(
        [
            result.model_dump_json(),
            json.dumps(build_cbom(result)),
            render_markdown_summary(result),
            redact_result(result).model_dump_json(),
        ]
    )


def test_scanned_key_files_report_the_header_line_only(keys_result) -> None:
    result, bodies = keys_result
    keyfile = [f for f in result.findings if f.location.source_type == SourceType.KEYFILE]
    assert len(keyfile) == 4
    assert all((f.location.snippet or "").startswith("-----BEGIN ") for f in keyfile if f.location.snippet)
    assert all("\n" not in (f.location.snippet or "") for f in keyfile)
    text = _everything(result)
    assert len(bodies) > 20
    assert not [line for line in bodies if line in text]


def test_encrypted_key_is_unresolved_and_not_a_cbom_component(keys_result) -> None:
    result, _ = keys_result
    unresolved = [a for a in result.assets if a.canonical_name == "unresolved"]
    assert len(unresolved) == 1 and unresolved[0].tier.value == "UNKNOWN"
    cbom = build_cbom(result)
    assert validate_cbom(cbom) == []
    assert "unresolved" not in {c["name"] for c in cbom["components"]}
    assert unresolved[0].asset_id not in {c["bom-ref"] for c in cbom["components"]}
    # The other three key files are real inventory entries.
    assert sum(c["name"] == "RSA" for c in cbom["components"]) >= 1


def test_nothing_refers_to_an_unresolved_asset() -> None:
    """A container that lists an unresolved component keeps a valid CBOM with no dangling dependsOn."""
    result = ScanResult.model_validate_json((ROOT / "tests/fixtures/scan_result_sample.json").read_text())
    container = next(a for a in result.assets if a.components)
    ghost = container.model_copy(
        update={"asset_id": "asset-unresolved-ghost", "canonical_name": "unresolved", "components": []}
    )
    container.components = [ghost.asset_id, *container.components]
    result.assets.append(ghost)
    cbom = build_cbom(result)
    assert validate_cbom(cbom) == []
    assert ghost.asset_id not in json.dumps(cbom)
    assert all(ghost.asset_id not in d["dependsOn"] and d["dependsOn"] for d in cbom["dependencies"])


def _leaky(result: ScanResult) -> tuple[ScanResult, str]:
    """A result in which a scanner broke the promise: whole PEM blocks in snippets and in extra."""
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDleakedbodyline"
    block = f"{HEADER}\n{body}\n{body[::-1]}\n-----END PRIVATE KEY-----"
    leaky = result.model_copy(deep=True)
    code = next(f for f in leaky.findings if f.location.source_type == SourceType.CODE and f.location.file)
    code.location = code.location.model_copy(update={"snippet": f"key = '''{block}'''  # code"})
    key = Finding(
        id="leak-key",
        raw_name="RSA",
        kind_hint=KindHint.KEY,
        detector="config.keyfile",
        location=Location(source_type=SourceType.KEYFILE, file="keys/leak.key", line=1, snippet=block),
        extra={"note": block, "nested": [{"pem": block}]},
    )
    leaky.findings.append(key)
    asset = next(a for a in leaky.assets if code.id in a.finding_ids)
    asset.finding_ids = [*asset.finding_ids, key.id]
    asset.occurrences = [*asset.occurrences, key.location, code.location]
    return leaky, body


def test_redact_snippet_keeps_the_header_line_only() -> None:
    block = f"{HEADER}\nAAAA\nBBBB\n-----END PRIVATE KEY-----"
    assert redact_snippet(block, SourceType.KEYFILE) == HEADER
    assert redact_snippet(f"x = '''{block}'''", SourceType.CODE) == f"x = '''{HEADER}'''"
    assert redact_snippet(f"{HEADER}\nAAAA\nBBBB", SourceType.CODE) == HEADER
    assert redact_snippet("ssh-ed25519\nsecond", SourceType.KEYFILE) == "ssh-ed25519"
    assert redact_snippet("", SourceType.KEYFILE) == ""
    assert redact_snippet(None, SourceType.KEYFILE) is None
    assert redact_snippet("h = hashlib.md5(<redacted>)", SourceType.CODE) == "h = hashlib.md5(<redacted>)"


def test_a_leaking_scanner_never_reaches_a_served_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sample = ScanResult.model_validate_json((ROOT / "tests/fixtures/scan_result_sample.json").read_text())
    leaky, body = _leaky(sample)
    assert body in leaky.model_dump_json()

    report = tmp_path / "out" / "report.json"
    report.parent.mkdir()
    report.write_text(leaky.model_dump_json())
    monkeypatch.setattr(main, "REPORT", report)

    served = {
        "result": main.result().model_dump_json(),
        "cbom": json.dumps(main.cbom()),
        "report.md": main.report_md().body.decode(),
        "build_cbom": json.dumps(build_cbom(leaky)),
    }
    for name, text in served.items():
        assert body not in text, name
        assert body[::-1] not in text, name
    assert HEADER in served["result"]
    assert main.validate().valid

    # /api/scan stores what it returns: the stored report is redacted too.
    module = types.ModuleType("quantumtrace.pipeline")
    module.run = lambda inputs: leaky  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quantumtrace.pipeline", module)
    report.unlink()
    returned = main.scan(main.ScanRequest(paths=["sample-repos"]))
    assert body not in returned.model_dump_json()
    assert body not in report.read_text()
