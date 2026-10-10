"""Generate ``kb/tls_registry.yaml`` from committed IANA CSVs and an OpenSSL snapshot.

Offline and deterministic: ``build_registry`` reads only the files in ``kb/iana/``. The one
step that runs OpenSSL is ``snapshot_openssl`` (``--snapshot-openssl``); its result is
committed as ``kb/iana/openssl.json`` so tests and regeneration never execute openssl.

    python -m quantumtrace.scanners.network.gen_registry [--snapshot-openssl] [--check]

The registry holds names, aliases and PQC facts only. No tier, threat or verdict.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from quantumtrace.scanners.network.registry import SIGNALLING_SUITES, format_code

KB_DIR = Path(__file__).resolve().parents[2] / "kb"
IANA_DIR = KB_DIR / "iana"
OUTPUT = KB_DIR / "tls_registry.yaml"
OPENSSL_SNAPSHOT = IANA_DIR / "openssl.json"
IANA_BASE = "https://www.iana.org/assignments/tls-parameters/"
IANA_SOURCES = {
    "cipher_suites": ("tls-cipher-suites.csv", IANA_BASE + "tls-parameters-4.csv"),
    "groups": ("tls-supported-groups.csv", IANA_BASE + "tls-parameters-8.csv"),
    "signature_schemes": ("tls-signature-schemes.csv", IANA_BASE + "tls-signaturescheme.csv"),
}

# PQC facts from PLAN 7.4. The expected IANA name is a guard: if the CSV disagrees the
# generator stops instead of silently renaming. Entries absent from the CSV get `verify`.
GROUP_PQC: dict[int, dict[str, Any]] = {
    0x0200: {"name": "MLKEM512", "pqc": True, "hybrid": False},
    0x0201: {"name": "MLKEM768", "pqc": True, "hybrid": False},
    0x0202: {"name": "MLKEM1024", "pqc": True, "hybrid": False},
    0x11EB: {
        "name": "SecP256r1MLKEM768",
        "pqc": True,
        "hybrid": True,
        "components": ["secp256r1", "MLKEM768"],
    },
    0x11EC: {
        "name": "X25519MLKEM768",
        "pqc": True,
        "hybrid": True,
        "components": ["x25519", "MLKEM768"],
    },
    0x11ED: {
        "name": "SecP384r1MLKEM1024",
        "pqc": True,
        "hybrid": True,
        "components": ["secp384r1", "MLKEM1024"],
    },
    0x6399: {
        "name": "X25519Kyber768Draft00",
        "pqc": True,
        "hybrid": True,
        "deprecated_draft": True,
    },
    0x639A: {
        "name": "SecP256r1Kyber768Draft00",
        "pqc": True,
        "hybrid": True,
        "deprecated_draft": True,
    },
}
# PLAN 7.4 marks these codepoints (verify): registered, but the IANA reference is an IETF draft.
DRAFT_VERIFY = "PLAN 7.4 verify: IANA reference is an IETF draft; codepoint not confirmed final"
SIGNATURE_PQC: dict[int, dict[str, Any]] = {
    0x0904: {"name": "mldsa44", "pqc": True, "verify": [DRAFT_VERIFY]},
    0x0905: {"name": "mldsa65", "pqc": True, "verify": [DRAFT_VERIFY]},
    0x0906: {"name": "mldsa87", "pqc": True, "verify": [DRAFT_VERIFY]},
}
VERSIONS = {  # PLAN 7.4; labels follow M2M4-02
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

_PLACEHOLDER = re.compile(r"^(reserved|unassigned)", re.IGNORECASE)
_DRAFT_REF = re.compile(r"RFC-ietf|draft-", re.IGNORECASE)
_OBSOLETE = re.compile(r"\s*\(OBSOLETE\)\s*$")
_OPENSSL_CIPHER = re.compile(r"^\s*0x([0-9A-Fa-f]{2}),0x([0-9A-Fa-f]{2})\s+-\s+(\S+)")


class RegistryError(Exception):
    """Inputs disagree or are malformed; the registry is not written."""


# --- parsers (pure functions) ----------------------------------------------------------


def _clean_ref(ref: str) -> str:
    return re.sub(r"\]\[", "], [", ref.strip())


def _rows(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text, newline="")))


def _single(row: dict[str, str], code: int | None) -> dict[str, Any] | None:
    """One IANA row as an entry, or None for ranges and Reserved/Unassigned rows."""
    name = (row.get("Description") or "").strip()
    if code is None or not name or _PLACEHOLDER.match(name):
        return None
    entry: dict[str, Any] = {"iana": _OBSOLETE.sub("", name)}
    if _OBSOLETE.search(name):
        entry["obsolete"] = True
    ref = _clean_ref(row.get("Reference") or "")
    if ref:
        entry["ref"] = ref
    return entry


def parse_iana_cipher_suites(text: str) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for row in _rows(text):
        match = re.fullmatch(r"0x([0-9A-Fa-f]{2}),0x([0-9A-Fa-f]{2})", (row.get("Value") or "").strip())
        code = int(match.group(1) + match.group(2), 16) if match else None
        entry = _single(row, code)
        if entry is not None and code is not None:
            out[code] = entry
    return out


def parse_iana_groups(text: str) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for row in _rows(text):
        value = (row.get("Value") or "").strip()
        code = int(value) if value.isdigit() else None
        entry = _single(row, code)
        if entry is not None and code is not None:
            out[code] = entry
    return out


def parse_iana_signature_schemes(text: str) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for row in _rows(text):
        value = (row.get("Value") or "").strip()
        code = int(value, 16) if re.fullmatch(r"0x[0-9A-Fa-f]{4}", value) else None
        entry = _single(row, code)
        if entry is not None and code is not None:
            out[code] = entry
    return out


def parse_openssl_ciphers(text: str) -> dict[int, list[str]]:
    """``openssl ciphers -V`` lines to {codepoint: [openssl names]}; unparseable lines are ignored."""
    out: dict[int, list[str]] = {}
    for line in text.splitlines():
        match = _OPENSSL_CIPHER.match(line)
        if not match:
            continue
        code = int(match.group(1) + match.group(2), 16)
        names = out.setdefault(code, [])
        if match.group(3) not in names:
            names.append(match.group(3))
    return out


def parse_openssl_groups(text: str) -> list[str]:
    """``openssl list -all-tls-groups`` (colon separated, one line) to names in OpenSSL order."""
    names: list[str] = []
    for token in re.split(r"[:\s]+", text.strip()):
        if token and token not in names:
            names.append(token)
    return names


def parse_ecparam_oid(text: str) -> str | None:
    """The ``ASN1 OID:`` value of ``openssl ecparam -noout -text`` output."""
    match = re.search(r"^ASN1 OID:\s*(\S+)", text, re.MULTILINE)
    return match.group(1) if match else None


# --- build -----------------------------------------------------------------------------


def _resolve_groups(
    iana: dict[int, dict[str, Any]], group_names: list[str], curves: dict[str, str | None]
) -> tuple[dict[int, list[str]], dict[int, list[str]], list[str]]:
    """Pair OpenSSL group names with codepoints.

    Returns (aliases, oid_aliases, unresolved). A name matches the IANA name case-insensitively;
    otherwise it is paired through the curve OID that ``openssl ecparam`` reports, when exactly
    one directly matched group shares that OID. OID spellings that differ from every listed name
    (``prime256v1``) go to ``oid_aliases`` so the caller can mark them ``verify``.
    """
    by_name: dict[str, int] = {}
    for known, entry in sorted(iana.items()):
        by_name.setdefault(entry["iana"].lower(), known)
    aliases: dict[int, list[str]] = {}
    oid_aliases: dict[int, list[str]] = {}
    direct: dict[str, int] = {}
    pending: list[str] = []
    for name in group_names:
        code = by_name.get(name.lower())
        if code is None:
            pending.append(name)
            continue
        direct[name] = code
        aliases.setdefault(code, []).append(name)
    by_oid: dict[str, set[int]] = {}
    for name, code in direct.items():
        oid = curves.get(name)
        if oid:
            by_oid.setdefault(oid, set()).add(code)
    unresolved: list[str] = []
    for name in pending:
        oid = curves.get(name)
        codes = by_oid.get(oid, set()) if oid else set()
        if len(codes) == 1:
            aliases.setdefault(next(iter(codes)), []).append(name)
        else:
            unresolved.append(name)
    for oid, codes in by_oid.items():
        if len(codes) != 1:
            continue
        code = next(iter(codes))
        if oid not in aliases.get(code, []) and oid.lower() != iana[code]["iana"].lower():
            oid_aliases.setdefault(code, []).append(oid)
    return aliases, oid_aliases, unresolved


def _apply_pqc(
    entries: dict[int, dict[str, Any]], overrides: dict[int, dict[str, Any]], namespace: str
) -> None:
    for code, fact in overrides.items():
        entry = entries.get(code)
        if entry is None:
            raise RegistryError(
                f"{namespace} {format_code(code)} ({fact['name']}) missing from the IANA snapshot"
            )
        if entry["iana"] != fact["name"]:
            raise RegistryError(
                f"{namespace} {format_code(code)}: override name {fact['name']!r} "
                f"differs from IANA {entry['iana']!r}"
            )
        entry.update({key: value for key, value in fact.items() if key != "name"})
        # A PQC codepoint whose IANA reference is still an IETF draft is flagged from the CSV itself.
        if fact.get("pqc") and not fact.get("deprecated_draft") and _DRAFT_REF.search(entry.get("ref", "")):
            entry["draft"] = True


def build_registry(
    iana_texts: dict[str, str],
    iana_sha256: dict[str, str],
    openssl: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the registry document from CSV texts and an OpenSSL snapshot dict."""
    suites = parse_iana_cipher_suites(iana_texts["cipher_suites"])
    groups = parse_iana_groups(iana_texts["groups"])
    schemes = parse_iana_signature_schemes(iana_texts["signature_schemes"])
    for namespace, parsed in (("cipher_suites", suites), ("groups", groups), ("signature_schemes", schemes)):
        if not parsed:
            raise RegistryError(f"no usable rows in the IANA {namespace} CSV")

    for entry in suites.values():
        entry["openssl"] = []
    for code, names in parse_openssl_ciphers(openssl["ciphers"]).items():
        if code in suites:
            suites[code]["openssl"] = sorted(names)
        else:
            suites[code] = {"iana": None, "openssl": sorted(names), "verify": ["not in IANA snapshot"]}
    for code in SIGNALLING_SUITES:
        if code not in suites:
            raise RegistryError(f"signalling suite {format_code(code)} missing from the IANA snapshot")
        suites[code]["signalling"] = True

    for entry in groups.values():
        entry["openssl"] = []
    aliases, oid_aliases, unresolved = _resolve_groups(
        groups, parse_openssl_groups(openssl["groups"]), openssl.get("curves", {})
    )
    for code, names in aliases.items():
        groups[code]["openssl"] = list(names)
    for code, names in oid_aliases.items():
        groups[code]["openssl"] += names
        groups[code]["verify"] = [f"openssl alias {name} paired via openssl ecparam" for name in names]
    _apply_pqc(groups, GROUP_PQC, "groups")
    _apply_pqc(schemes, SIGNATURE_PQC, "signature_schemes")

    meta: dict[str, Any] = {
        "schema": 1,
        "generator": "quantumtrace.scanners.network.gen_registry",
        "note": "Names and PQC facts only; no tier. Entries with `verify` are not confirmed.",
        "iana_sources": [
            {"namespace": ns, "file": file, "url": url, "sha256": iana_sha256[ns]}
            for ns, (file, url) in IANA_SOURCES.items()
        ],
        "openssl_version": openssl.get("version"),
        "unresolved_openssl_groups": sorted(unresolved),
        "counts": {"cipher_suites": len(suites), "groups": len(groups), "signature_schemes": len(schemes)},
    }

    def keyed(entries: dict[int, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        return {format_code(code): entries[code] for code in sorted(entries)}

    return {
        "meta": meta,
        "cipher_suites": keyed(suites),
        "groups": keyed(groups),
        "signature_schemes": keyed(schemes),
        "versions": {format_code(code): {"label": label} for code, label in sorted(VERSIONS.items())},
    }


def dump_registry(registry: dict[str, Any]) -> str:
    return yaml.safe_dump(registry, sort_keys=False, allow_unicode=True, width=110)


# --- files and openssl -----------------------------------------------------------------


def load_inputs(iana_dir: Path = IANA_DIR) -> tuple[dict[str, str], dict[str, str], dict[str, Any]]:
    texts: dict[str, str] = {}
    digests: dict[str, str] = {}
    for namespace, (file, _url) in IANA_SOURCES.items():
        raw = (iana_dir / file).read_bytes()
        texts[namespace] = raw.decode("utf-8")
        digests[namespace] = hashlib.sha256(raw).hexdigest()
    openssl = json.loads((iana_dir / "openssl.json").read_text(encoding="utf-8"))
    return texts, digests, openssl


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)


def snapshot_openssl() -> dict[str, Any]:
    """Run openssl once and return the snapshot dict. Only called by ``--snapshot-openssl``."""
    version = _run(["openssl", "version"])
    ciphers = _run(["openssl", "ciphers", "-V", "ALL:COMPLEMENTOFALL"])
    groups = _run(["openssl", "list", "-all-tls-groups"])
    if version.returncode or ciphers.returncode or groups.returncode:
        raise RegistryError("openssl did not run successfully")
    curves: dict[str, str | None] = {}
    for name in parse_openssl_groups(groups.stdout):
        result = _run(["openssl", "ecparam", "-name", name, "-noout", "-text"])
        curves[name] = parse_ecparam_oid(result.stdout) if result.returncode == 0 else None
    return {
        "version": version.stdout.strip(),
        "ciphers": ciphers.stdout,
        "groups": groups.stdout.strip(),
        "curves": dict(sorted(curves.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--snapshot-openssl", action="store_true", help="refresh kb/iana/openssl.json")
    parser.add_argument("--check", action="store_true", help="fail if tls_registry.yaml is out of date")
    args = parser.parse_args(argv)
    try:
        if args.snapshot_openssl:
            snap = snapshot_openssl()
            OPENSSL_SNAPSHOT.write_text(json.dumps(snap, indent=2) + "\n", encoding="utf-8")
        text = dump_registry(build_registry(*load_inputs()))
    except (RegistryError, OSError, subprocess.SubprocessError) as exc:
        print(f"gen_registry: {exc}", file=sys.stderr)
        return 1
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != text:
            print("gen_registry: tls_registry.yaml is out of date", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
