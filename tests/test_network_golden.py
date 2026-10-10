"""Network golden rows (owner M2) in tests/golden/expected.yaml: shape, provenance and reproducibility.

The rows are produced by tests/fixtures/pcap/gen_golden_rows.py from tshark observations and the
specification, not from scanner output. These tests keep the committed section valid, independent of
scanner code and reproducible. They are not an accuracy result: M1's evaluator (scripts/eval.py)
measures the scanner against the rows.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import shutil
import sys
from collections import Counter
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden" / "expected.yaml"
SCHEMA = ROOT / "docs" / "golden.schema.json"
GENERATOR = ROOT / "tests" / "fixtures" / "pcap" / "gen_golden_rows.py"
SOURCE = "network-capture/network.pcap"


@pytest.fixture(scope="module")
def gen():
    spec = importlib.util.spec_from_file_location("gen_golden_rows", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module  # dataclasses resolve their module through sys.modules
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def text() -> str:
    return GOLDEN.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def section(gen, text) -> str:
    assert gen.BEGIN in text and gen.END in text, "network section missing from expected.yaml"
    return gen.BEGIN + text.split(gen.BEGIN, 1)[1].split(gen.END, 1)[0] + gen.END + "\n"


@pytest.fixture(scope="module")
def rows(section):
    return yaml.safe_load(section)


def test_section_rows_validate_against_the_schema(rows):
    Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(rows)


def test_rows_use_portable_selectors_only(rows):
    assert all(row["source"] == SOURCE for row in rows)
    assert not any("session_id" in row for row in rows)  # the id hashes the scan path (GOLDEN.md)


def test_row_counts_match_appendix_d(rows):
    counts = {
        (r["metric"], r.get("transport"), r.get("kind_hint")): r["count"]
        for r in rows
        if r["kind"] == "count"
    }
    assert counts == {
        ("sessions", "tls", None): 97,
        ("sessions", "ssh", None): 24,
        ("occurrences", None, "plaintext"): 14,
    }
    kinds = Counter(r["kind"] for r in rows)
    assert kinds["asset"] == sum(1 for r in rows if r["kind"] == "asset") > 0
    assert kinds["session"] > 0 and kinds["finding"] > 0


def test_hybrid_sessions_are_present_and_safe_kex(rows):
    hybrid = [r for r in rows if r["kind"] == "session" and r.get("negotiated_group") == "X25519MLKEM768"]
    assert hybrid, "no hybrid session rows"
    assert all(r["tier_kex"] == "SAFE" and r["tier_session"] == "UNKNOWN" for r in hybrid)


def test_rows_carry_no_key_material(section):
    for needle in ("BEGIN CERTIFICATE", "PRIVATE KEY", "b'", 'b"'):
        assert needle not in section


def test_generator_imports_no_scanner_code():
    tree = ast.parse(GENERATOR.read_text(encoding="utf-8"))
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    assert not [m for m in imported if m.split(".")[0] == "quantumtrace"], imported


def test_splice_touches_only_the_network_block(gen, text):
    marker = "\n# --- code section (owner M3) begin ---\n- kind: asset\n"
    probe = gen.splice(marker + text, "NEW\n")
    assert probe.startswith(marker)
    head, rest = text.split(gen.BEGIN, 1)
    tail = rest.split(gen.END, 1)[1]
    assert gen.splice(text, "NEW\n") == head.rstrip("\n") + "\n\nNEW" + tail


@pytest.mark.skipif(
    shutil.which("tshark") is None, reason="tshark not installed: network golden drift check not run"
)
def test_section_equals_generator_output(gen, section):
    assert section == gen.render(gen.build()), "run gen_golden_rows.py --write (rows are not hand-edited)"
