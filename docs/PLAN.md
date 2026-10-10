# QuantumTrace — Implementation Plan

> **Cryptographic Agility & Post-Quantum Readiness Scanner**
> Hackathon build plan · 4 members · **24h** · Python (FastAPI) + React · All four challenge vectors

This document is the **single source of truth** for the team and every coding-agent session working on the repo. Read sections 1–6 and **Appendix D** (what the starter kit really contains, with golden expectations) before writing code. Your personal work package is in section 8. If something here conflicts with a later team decision, update this file in the same commit.

**M1 local execution:** M1 keeps root `AGENTS.md` and `agents/` (implementation checklist, status, skills, individual plans, and handoffs) local-only and Git-ignored. These files are not distributed in repository checkouts; other members use this shared plan and their own local instructions. Shared workflow and contract refinements are recorded in this plan and `communication/`. The optional local `docs/DECISIONS.md` ledger is Git-ignored and is not distributed. Each M1 task ends with a local contextual handoff; the next task starts in a fresh user-opened session.

---

## Table of Contents

1. [Goals & How We Win](#1-goals--how-we-win)
2. [Scope & Priorities (P0/P1/P2)](#2-scope--priorities)
3. [Architecture](#3-architecture)
4. [Tech Stack](#4-tech-stack)
5. [Repository Layout](#5-repository-layout)
6. [Data Contracts (FROZEN after H1)](#6-data-contracts-frozen-after-h1)
7. [Domain Knowledge: Classification Rules, TLS Codepoints, Scoring](#7-domain-knowledge)
8. [Work Packages per Member](#8-work-packages-per-member)
9. [Timeline & Checkpoints](#9-timeline--checkpoints)
10. [Testing & Accuracy Evaluation](#10-testing--accuracy-evaluation)
11. [Git Workflow & Conventions](#11-git-workflow--conventions)
12. [Working with coding agents](#12-working-with-coding-agents)
13. [Demo & Pitch](#13-demo--pitch)
14. [Risks & Mitigations](#14-risks--mitigations)
15. [Appendix B — Starter prompts for each member](#appendix-b--starter-prompts)
16. [Appendix C — Reference links](#appendix-c--reference-links)
17. [Appendix D — Starter-kit analysis & golden ground truth](#appendix-d--starter-kit-analysis--golden-ground-truth)

---

## 1. Goals & How We Win

**What we build:** a single tool, `qtrace`, that ingests PCAPs, code repos, config files and cloud dumps (KMS / load balancer), detects every cryptographic primitive, classifies its quantum risk, computes an enterprise **Quantum Risk Score**, and exports a **CycloneDX 1.6 CBOM** plus a JSON audit report, visualised in a React dashboard (FastAPI backend).

**Evaluation weights → what we optimise:**

| Criterion | Weight | Our strategy |
|---|---|---|
| Detection accuracy & risk scoring | **40%** | One central, data-driven classification engine (YAML knowledge base). Scanners only *detect*; they never classify. A golden ground-truth set + `make eval` that prints precision/recall — we show this number in the demo. |
| Data ingestion & coverage | 25% | All four vectors: PCAP, code (Python/Java/Go), config files, KMS/LB/ACM JSON, SSH key exchange, optional live probe. Auto-routing of any input folder. |
| Standardisation & traceability | 20% | Schema-valid CycloneDX 1.6 CBOM with `cryptoProperties`, OIDs, NIST quantum security levels, explicit FIPS 203/204/205 replacement mapping, evidence (file/line/flow) for every asset. |
| Usability & demo | 15% | `docker run` one-liner, `qtrace scan <dir>` CLI with Rich output, polished React dashboard, rehearsed 3-minute pitch. |

**Guiding principles**

1. **Detection ≠ classification.** Scanners emit raw `Finding`s. Only the engine turns them into classified `CryptoAsset`s. This keeps accuracy logic in one place and lets 4 people work in parallel.
2. **Data over code.** Algorithm knowledge, TLS codepoints and scoring weights live in YAML so they can be fixed without touching logic.
3. **Every claim has evidence.** Each asset carries its occurrences (file + line + snippet, or pcap flow + SNI, or resource ARN).
4. **End-to-end first, depth later.** By H6 the whole pipeline must run on the starter kit, even if shallow.

---

## 2. Scope & Priorities

- **P0 — must ship** (required for a credible demo)
- **P1 — should ship** (big score impact)
- **P2 — stretch** (only after the H12 feature freeze)

| Area | P0 | P1 | P2 |
|---|---|---|---|
| Network | Parse TLS ClientHello/ServerHello from pcap/pcapng: version, cipher suites, groups, key_share, signature schemes, SNI. Offered vs negotiated. Non-443 ports and upgrades (SMTP STARTTLS 587, Postgres SSLRequest 5432, LDAPS 636, IMAPS 993). SSH KEXINIT (kex, host key, cipher, MAC). | TLS 1.2 certificate extraction (key type/size, sig alg, expiry). ServerKeyExchange curve. Session-level verdict. | Live probing of sandbox endpoints; keylog-file decryption; QUIC. |
| Code | Regex rule engine for Python, Java, Go with key-size capture **and file-scope constant resolution** (key sizes sit behind constants in the kit); insecure-RNG rules; SAFE-decoy discipline. | Python AST pass; PEM/DER keys & certs in repos; library detection from manifests (requirements.txt, pom.xml, go.mod). | Binary/JAR string scanning; SARIF export. |
| Config | KMS, LB/TLS-policy and ACM-certificate adapters (cert↔listener join); plaintext (HTTP) listener flagging. | generic JSON walker. | nginx/Apache/HAProxy/Spring `ssl_*` settings and PEM/DER key files (no sample data in the kit); Terraform/CloudFormation. |
| Engine | Normalise → classify (3 tiers + UNKNOWN), cipher-suite decomposition, dedupe, scoring. | HNDL exposure, forward secrecy, classically-broken flag, migration recommendations. | Configurable policy profiles (CNSA 2.0 vs NIST). |
| Output | Native JSON report + CycloneDX 1.6 CBOM (schema-validated). | Markdown executive summary; migration roadmap. | SARIF; PDF. |
| UX | CLI `qtrace scan`; React overview + findings table (FastAPI backend); Dockerfile. | Network / Code / Cloud / CBOM / Roadmap pages; file upload in UI. | Diff between two scans. |

---

## 3. Architecture

### 3.1 High-level flow

```
                     ┌───────────────────────────────────────────────┐
  inputs/            │                 qtrace pipeline               │
  ├─ *.pcap(ng) ──┐  │                                               │
  ├─ repos/     ──┤  │  ┌──────────┐   ┌────────────┐   ┌──────────┐  │   ┌──────────────────┐
  ├─ *.json     ──┼──┼─▶│  Router  │──▶│  Scanners  │──▶│ Findings │──┼──▶│  Engine (M1)     │
  ├─ *.conf     ──┤  │  │ (sniff   │   │ network/M2 │   │ (raw)    │  │   │ normalize        │
  ├─ *.pem/.crt ──┤  │  │  by ext/ │   │ code/M3    │   └──────────┘  │   │ decompose        │
  └─ host:port  ──┘  │  │  content)│   │ config/M3  │                 │   │ classify (KB)    │
                     │  └──────────┘   │ cloud/M4   │                 │   │ aggregate/dedupe │
                     │                 └────────────┘                 │   │ score            │
                     └───────────────────────────────────────────────┘   └────────┬─────────┘
                                                                                   │ ScanResult
                                    ┌──────────────────────────────────────────────┼───────────────┐
                                    ▼                         ▼                    ▼               ▼
                           report.json (native)     cbom.cdx.json (CycloneDX)   summary.md   React UI via FastAPI (M4)
                                                                                              + Rich CLI (M1)
```

### 3.2 Layers and responsibilities

| Layer | Module | Owner | Input → Output |
|---|---|---|---|
| Router | `pipeline.py` | M1 | paths / targets → (scanner, path) jobs |
| Scanners | `scanners/**` | M2 (network), M3 (code/config), M4 (cloud) | file → `Iterator[Finding]` |
| Knowledge base | `kb/*.yaml` + `kb/loader.py` | M1 (TLS registry: M2, cloud registry: M4) | YAML → in-memory lookup tables |
| Engine | `engine/**` | M1 | `list[Finding]` → `list[CryptoAsset]` + `RiskSummary` |
| Output | `output/**` | M1 (report/roadmap), M4 (CBOM), M3 (markdown/SARIF) | `ScanResult` → JSON / CBOM / Markdown |
| API + UI | `api/**`, `frontend/**`, `cli.py` | M4 (M3: one page), M1 | `ScanResult` → FastAPI JSON → React screens |

### 3.3 Key design decisions

- **Scanners are pure and stateless:** `scan(path) -> Iterator[Finding]`. No classification, no scoring, no printing. Errors are logged and yielded as `ScanError` entries, never raised to the pipeline.
- **Engine is deterministic:** same input → same output, same IDs (IDs are hashes of content, not UUIDs) so diffs and tests are stable.
- **`ScanResult` JSON is the integration boundary for the UI.** The dashboard only reads `ScanResult` (or calls `pipeline.run()` and gets one). M4 can build the entire UI against a hand-written sample `ScanResult` from hour 1.
- **Composite names are decomposed before classification.** `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` → ECDHE (key exchange) + RSA (authentication) + AES-128-GCM (encryption) + SHA-256 (PRF). `SHA1withRSA` → RSA (signature) + SHA-1 (hash). Each component becomes its own asset; the protocol/cipher suite becomes a `protocol` asset referencing them.
- **Offered vs negotiated.** ClientHello lists are *offered* (low weight, agility signal); ServerHello choices are *negotiated* (full weight, actual exposure). A client offering X25519MLKEM768 while the server picks x25519 is a key demo insight: "the server is the blocker".

---

## 4. Tech Stack

| Concern | Choice | Notes |
|---|---|---|
| Language | Python 3.12 | Everyone uses the same version (`.python-version`). |
| Packaging | `pyproject.toml` + `uv` (or pip) | `pip install -e .[dev]`. |
| Models / validation | **Pydantic v2** | All contracts in `models.py`. |
| CLI | **Typer** + **Rich** | Coloured tables, progress bars, score panel. |
| PCAP parsing | **`tshark`** (Wireshark ≥ 4.0) via `subprocess`, `-T json` | Handles TCP reassembly & TLS dissection reliably. Use numeric codepoints, never rely on Wireshark's names (older versions don't know ML-KEM). |
| PCAP fallback | **Pure-Python** pcap/TLS-hello parser (`purepy.py`, ~100 lines) | Used if tshark is missing; also carries SSH. Prototype logic in Appendix D.1. |
| Certificates / keys | **cryptography** | Parse DER/PEM certs & keys: key type, size, curve, sig alg, validity. |
| Code scanning | Own regex rule engine (YAML rules) + Python `ast` | Semgrep is an option but adds weight; regex is faster to iterate in 48h. |
| CBOM | Hand-built dict → validated with **cyclonedx-python-lib** `JsonStrictValidator(SchemaVersion.V1_6)` | Hand-building gives full control over `cryptoProperties`. |
| API | **FastAPI** + uvicorn | Thin layer over `pipeline.run()`; `response_model=ScanResult` gives OpenAPI → generated TS types. |
| Dashboard | **React 18 + TypeScript + Vite**, Tailwind, Recharts (or Plotly.js), TanStack Table | SPA built in Docker stage 1 and served by FastAPI; dev via Vite proxy. |
| Live probe (P2) | `openssl s_client` (OpenSSL ≥ 3.5 has ML-KEM hybrids) + optional `sslyze` | Put sslyze in an optional extra (it pins `cryptography`). |
| Tests | pytest, pytest-cov | No network in tests. |
| Lint/format | ruff (lint + format), mypy (optional) | `make lint`. |
| Container | Docker, base `python:3.12-slim-trixie` (verify tag) | Debian trixie ships Wireshark 4.4 and OpenSSL 3.5. |

**`pyproject.toml` dependencies (starting point):**

```toml
[project]
name = "quantumtrace"
requires-python = ">=3.12"
dependencies = [
  "pydantic>=2.12,<3", "typer>=0.12", "rich>=13", "pyyaml>=6",
  "cryptography>=43",
  "cyclonedx-python-lib[json-validation]>=8", "jsonschema>=4",
  "fastapi>=0.115", "uvicorn[standard]>=0.30", "python-multipart>=0.0.9",
]
[project.optional-dependencies]
probe = ["sslyze>=6"]
dev = ["pytest>=8", "pytest-cov", "ruff>=0.6", "mypy"]
[project.scripts]
qtrace = "quantumtrace.cli:app"
```

**Dockerfile (sketch — M4 owns):** multi-stage; the React build is served by FastAPI on one port.

```dockerfile
# ---- stage 1: build the React app ----
FROM node:22-slim AS ui
WORKDIR /ui
COPY frontend/package*.json ./
RUN npm ci
COPY frontend ./
RUN npm run build                      # -> /ui/dist

# ---- stage 2: python + tshark + openssl ----
FROM python:3.12-slim-trixie
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update && apt-get install -y --no-install-recommends tshark openssl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY api ./api
COPY --from=ui /ui/dist ./frontend/dist
RUN pip install --no-cache-dir -e .
EXPOSE 8000
# default: API + dashboard; override with `qtrace scan ...`
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Usage target for the README:
```bash
docker build -t quantumtrace .
docker run --rm -v $PWD:/data -v $PWD/out:/out quantumtrace qtrace scan /data --out /out
docker run --rm -p 8000:8000 -v $PWD/out:/out quantumtrace   # dashboard at http://localhost:8000
```

Dev loop (no Docker): `make api` (uvicorn --reload on :8000) and `npm --prefix frontend run dev` (Vite on :5173, proxies `/api` to :8000).

**Foundation development (task 1.1):** run `make install` with uv to sync the
committed `uv.lock` and dev extra into a local Python 3.12 `.venv`. Alternatively,
create a Python 3.12 environment and use `pip install -e '.[dev]'` (pip does not
consume the uv lock). Run `make test`, `make lint` (Ruff lint and format checks),
and `make check`. `make help` lists all targets. YAML package data is included
for future KB and scanner rule files. The `qtrace` console entry point is added
with the CLI in task 1.10. Evaluation, scan-demo, API, UI, and Docker targets fail
explicitly until their owning implementations exist.

---

---

## 5. Repository Layout

Ownership is marked `[M1]`…`[M4]`. **Only the owner edits a file** unless coordinated in chat. `models.py` changes need agreement from all. The starter kit (`sample-repos/`, `cloud-posture/`, `network-capture/`) lives at the repo root and is **read-only**.

```
quantumtrace/
├── pyproject.toml                 [M1]
├── Makefile                       [M1]   install, test, lint, eval, scan-demo, api, ui, docker
├── Dockerfile  .dockerignore      [M4]
├── README.md                      [M4]
├── sample-repos/ cloud-posture/ network-capture/   starter kit (provided, read-only)
├── docs/
│   ├── PLAN.md                    (this file)
│   └── GOLDEN.md                  [M1]   golden expectation format for owner contributions
├── src/quantumtrace/
│   ├── __init__.py
│   ├── models.py                  [M1]   FROZEN contracts (section 6)
│   ├── pipeline.py                [M1]   router + orchestration: run(inputs) -> ScanResult
│   ├── cli.py                     [M1]   Typer app: scan, report, eval, ui
│   ├── kb/
│   │   ├── algorithms.yaml        [M1]   algorithm knowledge base (section 7.2)
│   │   ├── tls_registry.yaml      [M2]   TLS + SSH codepoints / names
│   │   ├── cloud_registry.yaml    [M4]   KMS key specs, ACM key algs, ELB policy → ciphers
│   │   ├── scoring.yaml           [M1]   weights & multipliers (section 7.5)
│   │   └── loader.py              [M1]
│   ├── engine/
│   │   ├── normalize.py           [M1]   raw_name -> canonical algorithm id (+ params)
│   │   ├── decompose.py           [M1]   cipher suites, "SHA256withECDSA", JCA transforms, SSH names
│   │   ├── classify.py            [M1]   tier, threat, flags, recommendation
│   │   ├── aggregate.py           [M1]   dedupe findings -> assets with occurrences
│   │   └── score.py               [M1]   asset risk points, enterprise score, grade
│   ├── scanners/
│   │   ├── base.py                [M1]   Scanner protocol, registry, helpers (finding_id)
│   │   ├── network/
│   │   │   ├── tshark.py          [M2]   run tshark, yield handshake records
│   │   │   ├── purepy.py          [M2]   pure-Python pcap+TLS hello parser (fallback, no tshark needed)
│   │   │   ├── tls_session.py     [M2]   assemble client/server hello per flow (+STARTTLS/pgsql)
│   │   │   ├── ssh.py             [M2]   SSH banner + KEXINIT parsing, negotiated kex/hostkey/cipher
│   │   │   ├── certs.py           [M2]   TLS 1.2 certificate parsing (P1)
│   │   │   ├── pcap_scanner.py    [M2]   Scanner implementation -> Findings
│   │   │   └── probe.py           [M2]   P2 live probing
│   │   ├── cloud/                 [M4]   ALL cloud adapters under one owner
│   │   │   ├── kms.py             [M4]   KMS dumps (AWS ListKeys/DescribeKey shape)
│   │   │   ├── loadbalancer.py    [M4]   ELB listeners + SslPolicy; HTTP:80 -> plaintext finding
│   │   │   ├── acm.py             [M4]   ACM certificates; join to listeners via ARN
│   │   │   └── generic_json.py    [M4]   fallback walker for unknown JSON
│   │   ├── code/
│   │   │   ├── engine.py          [M3]   regex rule runner + file-scope constant resolution
│   │   │   ├── rules/python.yaml  [M3]
│   │   │   ├── rules/java.yaml    [M3]
│   │   │   ├── rules/go.yaml      [M3]
│   │   │   ├── python_ast.py      [M3]   P1 (alias resolution)
│   │   │   └── manifests.py       [M3]   P1 requirements.txt / pom.xml / go.mod
│   │   └── config/                [M3]   P2 — no sample data in the kit
│   │       ├── webserver.py       [M3]   nginx/apache/haproxy/spring ssl settings
│   │       └── keyfiles.py        [M3]   PEM/DER keys & certs on disk
│   └── output/
│       ├── report_json.py         [M1]   native report + roadmap builder
│       ├── cyclonedx.py           [M4]   CBOM builder + validation
│       ├── markdown.py            [M3]   executive summary
│       └── sarif.py               [M3]   P2
├── api/
│   └── main.py                    [M4]   FastAPI: /api/result, /api/scan, /api/cbom, /api/report.md
├── frontend/                      [M4]   React + TypeScript + Vite (Code & Config page: M3)
│   ├── package.json  vite.config.ts
│   └── src/
│       ├── api/                   types generated from FastAPI /openapi.json
│       ├── pages/{Overview,Network,CodeConfig,Cloud,Cbom,Roadmap}.tsx
│       └── components/            ScoreGauge, TierBadge, FindingsTable, SessionTable...
├── tests/
│   ├── fixtures/
│   │   ├── pcap/                  [M2]   own generated captures (scripts/gen_pcaps.sh)
│   │   ├── code/{python,java,go}/ [M3]
│   │   ├── config/                [M3]
│   │   ├── cloud/                 [M4]
│   │   └── scan_result_sample.json[M4]   hand-made sample for UI dev
│   ├── golden/expected.yaml       [all]  ground truth for accuracy eval (section 10, Appendix D)
│   ├── test_engine_*.py           [M1]
│   ├── test_network_*.py          [M2]
│   ├── test_code_*.py test_config_*.py [M3]
│   └── test_cloud_*.py test_output_*.py test_api_*.py [M4]
└── scripts/
    ├── gen_pcaps.sh               [M2]
    ├── eval.py                    [M1]
    └── demo.sh                    [M4]
```

---

## 6. Data Contracts (FROZEN after H1)

Initial contracts are established in task 1.2 (2026-10-10). Import the shared
models from `quantumtrace.models`; scanner integration lives in
`quantumtrace.scanners.base`. The model snapshot below includes the approved
ScanOptions and typed roadmap additions. After this initial freeze, all contract
changes, including optional additions, require AGREED replies from all four members
in communication/; existing fields must not be renamed or removed.

```python
# src/quantumtrace/models.py
"""Frozen shared contracts for QuantumTrace scanner and consumer integration."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator


class SourceType(str, Enum):
    """Evidence source identifiers shared by scanners and reports."""

    PCAP = "pcap"
    LIVE = "live"
    CODE = "code"
    CONFIG = "config"
    KMS = "kms"
    LOADBALANCER = "loadbalancer"
    KEYFILE = "keyfile"
    BINARY = "binary"
    SSH = "ssh"
    ACM = "acm"


class KindHint(str, Enum):
    """Raw detected object kinds; classification belongs to the engine."""

    CIPHER_SUITE = "cipher_suite"
    GROUP = "group"
    SIGNATURE_SCHEME = "signature_scheme"
    ALGORITHM = "algorithm"
    KEY = "key"
    CERTIFICATE = "certificate"
    PROTOCOL_VERSION = "protocol_version"
    POLICY = "policy"
    LIBRARY = "library"
    PLAINTEXT = "plaintext"


class Usage(str, Enum):
    """The cryptographic purpose observed by a scanner."""

    KEY_EXCHANGE = "key_exchange"
    SIGNATURE = "signature"
    ENCRYPTION = "encryption"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    RNG = "rng"
    AUTHENTICATION = "authentication"
    UNKNOWN = "unknown"


class Tier(str, Enum):
    """Quantum risk verdict assigned by the central engine."""

    CRITICAL = "CRITICAL"
    MEDIUM = "MEDIUM"
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"


class Threat(str, Enum):
    """The quantum attack associated with an engine verdict."""

    SHOR = "shor"
    GROVER = "grover"
    NONE = "none"
    UNKNOWN = "unknown"


class Location(BaseModel):
    """File, network, or resource evidence for a detected occurrence."""

    source_type: SourceType
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    flow: str | None = None
    sni: str | None = None
    frame: int | None = None
    resource_id: str | None = None
    target: str | None = None


class Finding(BaseModel):
    """Raw scanner evidence, without engine-assigned risk or recommendations."""

    id: str
    raw_name: str
    kind_hint: KindHint
    usage: Usage = Usage.UNKNOWN
    key_size: int | None = None
    curve: str | None = None
    mode: str | None = None
    padding: str | None = None
    library: str | None = None
    language: str | None = None
    protocol: str | None = None
    negotiated: bool | None = None
    in_test_code: bool = False
    detector: str
    confidence: float = Field(1.0, ge=0, le=1)
    location: Location
    session_id: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class ScanError(BaseModel):
    """A recoverable scanner failure retained alongside usable evidence."""

    detector: str
    path: str | None = None
    message: str


class Recommendation(BaseModel):
    """A migration action assigned by the engine."""

    action: str
    target_algorithm: str | None
    standard: str | None
    priority: int


class CryptoAsset(BaseModel):
    """A classified asset with traceable evidence and component relationships."""

    asset_id: str
    canonical_name: str
    family: str
    asset_type: Literal["algorithm", "certificate", "protocol", "related-crypto-material"]
    primitive: str
    usage: Usage
    key_size: int | None = None
    curve: str | None = None
    mode: str | None = None
    parameter_set: str | None = None
    oid: str | None = None
    tier: Tier
    threat: Threat
    classically_broken: bool = False
    hndl_exposed: bool = False
    forward_secrecy: bool | None = None
    deprecated_pqc_draft: bool = False
    classical_security_bits: int | None = None
    nist_quantum_level: int | None = None
    pqc_standard: str | None = None
    rationale: str
    recommendations: list[Recommendation] = Field(default_factory=list)
    occurrences: list[Location] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    component_of: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)
    negotiated: bool | None = None
    in_test_code_only: bool = False
    risk_points: float = 0.0
    max_points: float = 0.0


class TLSSession(BaseModel):
    """TLS or SSH session view, including unobservable authentication."""

    session_id: str
    flow: str
    sni: str | None
    version: str | None
    offered_groups: list[str] = Field(default_factory=list)
    negotiated_group: str | None = None
    offered_cipher_suites: list[str] = Field(default_factory=list)
    negotiated_cipher_suite: str | None = None
    offered_sig_schemes: list[str] = Field(default_factory=list)
    cert_key: str | None = None
    cert_sig_alg: str | None = None
    pq_status: Literal["pq_hybrid", "pq_pure", "classical", "unknown"]
    verdict_tier: Tier
    source: str
    transport: Literal["tls", "ssh"] = "tls"
    service: str | None = None
    peer_banners: list[str] = Field(default_factory=list)


class RiskSummary(BaseModel):
    """Enterprise and per-source risk computed by the scoring engine."""

    score: int
    grade: Literal["A", "B", "C", "D", "E", "F"]
    readiness_pct: float
    counts_by_tier: dict[str, int]
    counts_by_source: dict[str, dict[str, int]]
    score_by_source: dict[str, int]
    hndl_exposed_count: int
    top_risks: list[str]


class RoadmapItem(BaseModel):
    """A phased migration action linking affected assets and evidence counts."""

    phase: Literal[0, 1, 2, 3]
    action: str
    asset_ids: list[str] = Field(default_factory=list)
    occurrence_count: int = Field(ge=0)


class ScanOptions(BaseModel):
    """Directory exclusions and optional scanner selection for a scan."""

    model_config = ConfigDict(extra="forbid")

    exclude_dirs: list[Annotated[str, StringConstraints(min_length=1)]] = Field(
        default_factory=lambda: [".git", "node_modules", "venv", ".venv", "vendor", "out", "agents"]
    )
    scanner_names: list[Annotated[str, StringConstraints(min_length=1)]] | None = None

    @field_validator("exclude_dirs")
    @classmethod
    def validate_directory_names(cls, names: list[str]) -> list[str]:
        """Require individual directory names instead of ambiguous path patterns."""
        if any(name in {".", ".."} or not name.strip() or "/" in name or "\\" in name for name in names):
            raise ValueError("exclude_dirs must contain nonempty directory names, not paths")
        return names

    @field_validator("scanner_names")
    @classmethod
    def validate_scanner_names(cls, names: list[str] | None) -> list[str] | None:
        """Validate names structurally; registry selection validates availability."""
        if names is not None and any(not name.strip() for name in names):
            raise ValueError("scanner_names must contain nonempty names")
        return names


class ScanResult(BaseModel):
    """Versioned serialized integration boundary for reports, API, and UI."""

    schema_version: str = "1.0"
    tool_version: str
    scan_id: str
    started_at: str
    finished_at: str
    inputs: list[str]
    findings: list[Finding]
    assets: list[CryptoAsset]
    sessions: list[TLSSession] = Field(default_factory=list)
    summary: RiskSummary
    errors: list[ScanError] = Field(default_factory=list)
    roadmap: list[RoadmapItem] | None = Field(default=None, exclude_if=lambda value: value is None)
```

**Scanner protocol** (`scanners/base.py`, M1):

```python
class Scanner(Protocol):
    name: str                                   # "network.pcap"
    source_type: SourceType
    def can_handle(self, path: Path) -> bool: ...
    def scan(self, path: Path, root: Path) -> Iterator[Finding | ScanError]: ...

def finding_id(detector: str, raw_name: str, loc: Location) -> str:
    """sha1 of detector|raw_name|file|line|flow|frame|resource_id, first 12 hex chars."""

REGISTRY: list[Scanner] = []        # scanners self-register via @register decorator
```

**Engine public API** (`engine/__init__.py`, M1):

```python
def analyze(findings: list[Finding]) -> tuple[list[CryptoAsset], RiskSummary]
```

**Pipeline public API** (`pipeline.py`, M1):

```python
def run(inputs: list[str | Path], probes: list[str] | None = None, options: ScanOptions | None = None) -> ScanResult
```

`ScanOptions.exclude_dirs` defaults to `.git`, `node_modules`, `venv`, `.venv`,
`vendor`, `out`, and `agents`; entries are directory names, not path patterns.
`scanner_names=None` selects all registered adapters, while `[]` selects none.
Unknown option fields and empty names are rejected. After loading owner adapters,
the pipeline uses `select_scanners(options.scanner_names)`; requested unknown names
raise an explicit `ValueError`. Selection deduplicates names and returns adapters
sorted by name. Unavailable requested probes must also produce explicit errors
when the pipeline is implemented in task 1.9; probes default to `None`.

`RoadmapItem` has `phase` (0–3), `action`, `asset_ids` (default empty list), and
nonnegative `occurrence_count`. `ScanResult.roadmap=None` is omitted from both
`model_dump()` and `model_dump_json()`; an explicit empty list remains `[]`.
Existing nullable evidence such as unobservable certificate keys remains `null`.
This uses Pydantic's `Field(exclude_if=...)`, requiring Pydantic >=2.12,<3
([release documentation](https://pydantic.dev/articles/pydantic-v2-12-release#exclude_if-field-option)).
The lock already resolves Pydantic 2.14.0. Validation and serialization JSON schemas
retain typed roadmap fields, so M4 can generate API types from the shared model.

`@register` decorates a no-argument scanner class, registers one instance, and
returns the original class. Duplicate and empty names raise `ValueError` without
changing the registry. `REGISTRY` and selections are sorted by scanner name.
`finding_id` hashes the UTF-8 string
`detector|raw_name|file|line|flow|frame|resource_id` using SHA1 for identity only,
with missing values rendered as empty strings and the first 12 lowercase hex
characters retained. Timestamp metadata never participates. `is_test_path` matches
singular/plural test, example, and mock path segments (including `_`/`-` suffixes),
plus `test_*.py`/`*_test.py` conventions; unrelated substrings such as `contest` and
`mockery` do not match. Windows separators are supported.

**Network session ownership (M1M2-01..05):** M2 pairs transport observations and
emits Finding/ScanError only. M1 task 1.9 constructs classified TLSSession views by
session_id from raw extra.session and central engine results; analyze/run signatures
remain unchanged. Raw TLS lists retain hex codepoints and client order; output
uses verified registry iana names, retaining hex spellings for unresolved codes.
Resolve cipher-suite/group/signature namespaces through kind_hint. SSH keeps wire
names and each Finding's actual source type. Preserve unknown authentication,
actual packet evidence frames, and offered versus selected observations; offers
alone never prove negotiation. Optional repeatable --probe uses existing run(probes)
and the M2 probe_endpoints adapter after file scanning, with explicit failures and
no network access unless probes are requested. See communication/M1M2agreement.md.

**Finding.extra evidence conventions (initial freeze):** this dictionary remains
an extensible, JSON-compatible evidence payload. Keys below are optional; omit
unobserved values or represent them as `None`, and do not infer observations from
algorithm names. Scanners supply facts only; the engine owns their interpretation.

| Key | Evidence value and meaning |
|---|---|
| `origin` | String copied from observed key/certificate origin or type; do not invent a provider mapping. |
| `state` | String copied from observed resource state/status, e.g. the dump's key state. |
| `public_exposure` | Boolean observed from listener/load-balancer scheme or equivalent evidence. |
| `source_timestamp` | ISO 8601 timestamp with timezone from the source dump; engine expiry uses this, otherwise the supplied scan start time. |
| `hygiene_only` | Boolean marking a separate hygiene-only warning, rather than a cryptographic primitive. |
| `hygiene_flags` | List of observed hygiene facts as strings; crypto findings can retain flags without becoming hygiene-only. |
| `authentication_observable` | Boolean recording whether session authentication was actually observed; absence/None means unobserved or unknown, never an assumed key. |
| `session` | Dictionary of raw session observations matching TLSSession evidence names: version, offered/negotiated groups and cipher suites, offered signature schemes, certificate key/signature, transport, service, and peer banners. No engine verdict or pq_status supplied by scanners. |

The engine must retain each original Finding (including arbitrary owner extension
keys) through decomposition and aggregation. Per-finding confidence, source,
offered/negotiated status, and metadata remain available for scoring; Location
alone is insufficient. Missing authentication keeps an otherwise SAFE hybrid
session UNKNOWN unless an observed component is CRITICAL or MEDIUM.

M2–M4 integration: import these models and helpers, emit Finding or ScanError,
use `finding_id` for identity and `@register` for no-argument adapters. M4's sample
payload and generated UI types must validate against ScanResult; use the JSON schema
or API OpenAPI rather than redefining types. Engine/pipeline/output functions above
are contracts for later tasks, not callable implementations in task 1.2.

**Output public API** (native JSON: M1; CBOM: M4; Markdown: M3):

```python
def write_report_json(result: ScanResult, path: Path) -> None
def build_cbom(result: ScanResult) -> dict          # CycloneDX 1.6 JSON dict
def validate_cbom(cbom: dict) -> list[str]          # [] if valid
def write_markdown_summary(result: ScanResult, path: Path) -> None
```

**HTTP API** (`api/main.py`, M4 — thin; no business logic):

| Endpoint | Returns |
|---|---|
| `GET /api/result` | latest `ScanResult` (from `out/report.json`, or the bundled sample if none) |
| `POST /api/scan` | multipart upload (zip or files) or `{"path": "..."}` → runs `pipeline.run()` → `ScanResult` |
| `GET /api/cbom` / `GET /api/validate` | CycloneDX 1.6 JSON / `{valid: bool, errors: [...]}` |
| `GET /api/report.md` | executive summary |
| `GET /api/health` | `{status, tshark: bool, openssl_version}` |

React types are generated from `/openapi.json` (`openapi-typescript`); the frontend never hand-redefines `ScanResult`.

---

## 7. Domain Knowledge

> This section is what makes or breaks the 40% accuracy score. Treat it as the specification for `algorithms.yaml`, `tls_registry.yaml` and `scoring.yaml`. Values marked **(verify)** must be checked against the primary source before the demo.

### 7.1 Tier rules (canonical)

| Family / algorithm | Tier | Threat | Flags / notes | Recommended replacement |
|---|---|---|---|---|
| RSA (any size: encryption, signature, key transport) | **CRITICAL** | Shor | `classically_broken` if < 2048 bits. Larger RSA is **not** a fix. | KEM: ML-KEM-768 (FIPS 203); Sig: ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) |
| DSA | **CRITICAL** | Shor | classically deprecated | ML-DSA / SLH-DSA |
| DH / DHE / FFDHE (finite field) | **CRITICAL** | Shor | `classically_broken` if < 2048 | ML-KEM (hybrid) |
| ECDH / ECDHE (P-256/384/521, secp256k1, brainpool) | **CRITICAL** | Shor | | X25519MLKEM768 / SecP256r1MLKEM768 |
| X25519 / X448 | **CRITICAL** | Shor | Modern ≠ quantum safe! Common judge trap. | X25519MLKEM768 |
| ECDSA, EdDSA (Ed25519/Ed448), SM2 | **CRITICAL** | Shor | | ML-DSA-65 / SLH-DSA |
| ElGamal, ECIES | **CRITICAL** | Shor | | ML-KEM |
| AES-128 (any mode) | **MEDIUM** | Grover | ECB mode → extra warning | AES-256-GCM |
| AES-192 | **MEDIUM** (default, conservative) | Grover | configurable in scoring.yaml; CNSA 2.0 requires AES-256 | AES-256 |
| AES-256 | **SAFE** | Grover (negligible) | | — |
| AES with unknown key size | **MEDIUM**, confidence 0.5 | Grover | rationale: "key size not determinable" | AES-256 |
| ChaCha20-Poly1305 (256-bit key) | **SAFE** | | | — |
| 3DES / TDEA | **MEDIUM** | Grover | `classically_broken` (Sweet32, disallowed by NIST) | AES-256-GCM |
| DES, RC4, RC2, Blowfish, IDEA | **MEDIUM** | Grover | `classically_broken` (raise score multiplier) | AES-256-GCM / ChaCha20 |
| MD5, SHA-1 (hash, HMAC, in signatures) | **MEDIUM** | Grover | `classically_broken` for MD5 and SHA-1 collision use | SHA-384 / SHA3-384 |
| SHA-224, SHA-512/224 | **MEDIUM** | Grover | | SHA-384 |
| SHA-256, SHA-512/256, SHA3-256 | **SAFE** | Grover (adequate) | NIST still considers 128-bit post-quantum preimage security adequate | (SHA-384 for CNSA 2.0) |
| SHA-384, SHA-512, SHA3-384/512, SHAKE256 | **SAFE** | | | — |
| HMAC-SHA256+ | **SAFE** | | | — |
| ML-KEM-512/768/1024 (Kyber) | **SAFE** | | `pqc_standard: FIPS 203` | — |
| ML-DSA-44/65/87 (Dilithium) | **SAFE** | | `pqc_standard: FIPS 204` | — |
| SLH-DSA (SPHINCS+) | **SAFE** | | `pqc_standard: FIPS 205` | — |
| FN-DSA (Falcon) | **SAFE** | | `pqc_standard: FIPS 206 (draft)` (verify status) | — |
| LMS / HSS / XMSS | **SAFE** | | `pqc_standard: NIST SP 800-208` | — |
| HQC | **SAFE** | | selected by NIST as backup KEM (standard pending — verify) | — |
| Hybrids: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 | **SAFE** | | rationale must say: classical half is Shor-vulnerable, security holds as long as ML-KEM holds | — |
| Kyber draft hybrids (X25519Kyber768Draft00) | **SAFE** + `deprecated_pqc_draft` | | pre-standard codepoint | migrate to X25519MLKEM768 |
| PBKDF2 / HKDF / scrypt / Argon2 | follow underlying hash; else **SAFE** | | iterations < 100k for PBKDF2 → warning | — |
| Insecure RNG (`random`, `math/rand`, `java.util.Random` used for keys) | **UNKNOWN** tier, separate `classically_broken` warning | | Not a quantum issue; show but exclude from quantum score | `secrets` / `crypto/rand` / `SecureRandom` |
| TLS 1.0 / 1.1 / SSLv3 (protocol asset) | protocol tier = worst component; `classically_broken` | | | TLS 1.3 with hybrid KEX |

**Composite / session rules**

- A **cipher suite** or **TLS session** is a `protocol` asset; its tier follows negotiated components with precedence **CRITICAL > MEDIUM > UNKNOWN > SAFE**. Unobservable authentication prevents an overall SAFE verdict. Derived protocol containers summarize components and are excluded from quantum scoring to prevent double counting.
- **TLS_RSA_WITH_*** (static RSA key transport): key exchange = RSA, `forward_secrecy=false`, `hndl_exposed=true`. Highest risk: one future break of the server key decrypts *all* recorded sessions. Call this out in rationale.
- **HNDL exposure** = `true` for any Shor-vulnerable **key exchange / key transport** observed in transit (pcap, live, LB policy). Signatures are not HNDL-exposed (authentication can't be retroactively broken for past sessions) — say so in the rationale; this nuance impresses judges.
- **TLS 1.3**: the certificate and CertificateVerify are encrypted. Cert key type is `unknown` unless a keylog file is provided. Do **not** guess; set `cert_key=None` and emit an UNKNOWN authentication note at session level.
- **Hybrid KEX + unobservable authentication**: KEX is SAFE, authentication is UNKNOWN, and the overall verdict is UNKNOWN unless an observed component is CRITICAL or MEDIUM. Never report vulnerable certificate authentication that was not observed.
- **Hybrid KEX + RSA/ECDSA cert**: KEX is SAFE (HNDL protected), authentication still CRITICAL → session verdict CRITICAL with rationale "confidentiality PQ-protected, authentication not". `pq_status = pq_hybrid`.
- **GREASE values** (`0x0A0A, 0x1A1A, …, 0xFAFA` — pattern `(v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)`) must be **dropped** from cipher suites, groups, sig schemes, versions, extensions. Reporting them is a false positive.
- **TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF)** and **TLS_FALLBACK_SCSV (0x5600)** are signalling values, not ciphers — drop.

**SSH rules (starter pcap has 24 SSH sessions)**

- Negotiated algorithm = first client-listed algorithm that the server also lists (per category: kex, host key, cipher, MAC).
- `diffie-hellman-group1-sha1` = 1024-bit DH + SHA-1 → CRITICAL, `classically_broken`. `diffie-hellman-group14-sha1` = DH-2048 (CRITICAL) with SHA-1. `diffie-hellman-group16-sha512` = DH-4096 (CRITICAL). `curve25519-sha256` = X25519 (CRITICAL). `mlkem768x25519-sha256` / `sntrup761x25519-sha512` = SAFE hybrid *(verify names)*.
- `ssh-rsa` host key = RSA + **SHA-1** signature → CRITICAL + `classically_broken`; `rsa-sha2-256/512` = RSA (CRITICAL, not broken); `ssh-ed25519` = CRITICAL.
- Ciphers: `3des-cbc` MEDIUM + broken; `aes128-cbc` MEDIUM; `aes256-gcm@openssh.com`, `chacha20-poly1305@openssh.com` SAFE.
- Key exchange is HNDL-exposed like TLS KEX; host-key signatures are not.

**Cleartext & hygiene rules**

- A `plaintext` finding (HTTP:80 listener/flow, STARTTLS that never upgrades) is shown and counted separately; it is **excluded from the quantum score** (nothing to migrate to PQC, but it is the worst case for HNDL).
- Cloud hygiene flags (shown, not scored as quantum risk): certificate expired but `ISSUED`/in use; expiry < 90 days; imported certificate; KMS rotation disabled; key `PendingDeletion`; key `Origin: EXTERNAL`; SHA-1 certificate signature.
- HSM-backed (`AWS_CLOUDHSM`) or multi-region keys keep their tier; they raise impact in the rationale only.

### 7.2 `algorithms.yaml` schema & seed entries (M1)

Normalisation: lowercase, strip spaces/underscores/hyphens/slashes for matching, then try `aliases` exact match, then `patterns` (regex with named groups `size`, `curve`, `mode`, `param`). Decomposition (7.3) happens *before* this.

```yaml
# kb/algorithms.yaml
- id: RSA
  family: RSA
  primitive_by_usage: {encryption: pke, signature: signature, key_exchange: pke, unknown: pke}
  tier: CRITICAL
  threat: shor
  oid: 1.2.840.113549.1.1.1
  aliases: [rsa, rsaencryption, rsassapkcs1v15, rsassapss, rsaoaep, rsapss, rsakeytransport]
  patterns: ['^rsa(?P<size>\d{3,5})?$', '^rsa(sign|decrypt)?(pss|oaep|pkcs1)?(?P<size>\d{3,5})', '^rsa_(?P<size>\d{3,5})$']
  classically_broken_if: {key_size_lt: 2048}
  classical_security_bits: {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 15360: 256}
  nist_quantum_level: 0
  replacement:
    key_exchange: {target: ML-KEM-768, standard: NIST FIPS 203}
    encryption:   {target: ML-KEM-768, standard: NIST FIPS 203}
    signature:    {target: ML-DSA-65, standard: NIST FIPS 204}

- id: ECDH
  family: ECDH
  primitive_by_usage: {default: key-agree}
  tier: CRITICAL
  threat: shor
  aliases: [ecdh, ecdhe, ecdhephemeral]
  curves_bits: {secp256r1: 128, prime256v1: 128, p256: 128, secp384r1: 192, p384: 192, secp521r1: 256, p521: 256, secp256k1: 128}
  nist_quantum_level: 0
  replacement: {default: {target: X25519MLKEM768 (hybrid ML-KEM-768), standard: NIST FIPS 203}}

- id: X25519
  family: ECDH
  tier: CRITICAL
  threat: shor
  oid: 1.3.101.110
  aliases: [x25519, curve25519]
  classical_security_bits: 128
  replacement: {default: {target: X25519MLKEM768, standard: NIST FIPS 203}}

- id: ECDSA
  family: ECDSA
  primitive_by_usage: {default: signature}
  tier: CRITICAL
  threat: shor
  oid: 1.2.840.10045.2.1   # id-ecPublicKey
  aliases: [ecdsa, ec, ecc]
  replacement: {default: {target: ML-DSA-65, standard: NIST FIPS 204}}

- id: Ed25519
  family: EdDSA
  tier: CRITICAL
  threat: shor
  oid: 1.3.101.112
  aliases: [ed25519, eddsa]
  replacement: {default: {target: ML-DSA-65, standard: NIST FIPS 204}}

- id: AES
  family: AES
  primitive_by_mode: {GCM: ae, CCM: ae, SIV: ae, default: block-cipher}
  tier_by_key_size: {128: MEDIUM, 192: MEDIUM, 256: SAFE, unknown: MEDIUM}
  threat: grover
  nist_quantum_level_by_key_size: {128: 1, 192: 3, 256: 5}
  oids: {AES-128-GCM: 2.16.840.1.101.3.4.1.6, AES-256-GCM: 2.16.840.1.101.3.4.1.46}
  patterns: ['^aes(?P<size>128|192|256)?(?P<mode>gcm|cbc|ctr|ecb|ccm|cfb|ofb|siv)?', '^aes(?P<mode>gcm|cbc|ctr|ecb)(?P<size>128|192|256)?']
  replacement: {default: {target: AES-256-GCM, standard: NIST SP 800-38D}}

- id: SHA-1
  family: SHA-1
  primitive_by_usage: {mac: mac, default: hash}
  tier: MEDIUM
  threat: grover
  classically_broken: true
  oid: 1.3.14.3.2.26
  aliases: [sha1, sha, hmacsha1]
  replacement: {default: {target: SHA-384, standard: NIST FIPS 180-4}}

- id: SHA-256
  family: SHA-2
  tier: SAFE
  threat: grover
  oid: 2.16.840.1.101.3.4.2.1
  aliases: [sha256, sha2256, hmacsha256]
  nist_quantum_level: 2

- id: ML-KEM
  family: ML-KEM
  primitive_by_usage: {default: kem}
  tier: SAFE
  threat: none
  pqc_standard: NIST FIPS 203
  aliases: [mlkem, kyber]
  patterns: ['^(mlkem|kyber)(?P<param>512|768|1024)$']
  nist_quantum_level_by_param: {512: 1, 768: 3, 1024: 5}
  oids: {512: 2.16.840.1.101.3.4.4.1, 768: 2.16.840.1.101.3.4.4.2, 1024: 2.16.840.1.101.3.4.4.3}
  note_if_alias: {kyber: "Pre-standard name; confirm implementation follows final FIPS 203"}

- id: ML-DSA
  family: ML-DSA
  primitive_by_usage: {default: signature}
  tier: SAFE
  threat: none
  pqc_standard: NIST FIPS 204
  aliases: [mldsa, dilithium]
  patterns: ['^(mldsa|dilithium)(?P<param>44|65|87|2|3|5)$']
  param_map: {"2": "44", "3": "65", "5": "87"}
  nist_quantum_level_by_param: {44: 2, 65: 3, 87: 5}
  oids: {44: 2.16.840.1.101.3.4.3.17, 65: 2.16.840.1.101.3.4.3.18, 87: 2.16.840.1.101.3.4.3.19}

- id: SLH-DSA
  family: SLH-DSA
  primitive_by_usage: {default: signature}
  tier: SAFE
  threat: none
  pqc_standard: NIST FIPS 205
  aliases: [slhdsa, sphincs, sphincsplus]
  patterns: ['^(slhdsa|sphincs\+?)(sha2|shake)?(?P<param>128|192|256)(?P<variant>s|f)?']
  nist_quantum_level_by_param: {128: 1, 192: 3, 256: 5}

- id: X25519MLKEM768
  family: Hybrid-KEM
  primitive_by_usage: {default: kem}   # CycloneDX also has "combiner"; use kem + note
  tier: SAFE
  threat: none
  pqc_standard: NIST FIPS 203 (hybrid with X25519)
  aliases: [x25519mlkem768]
  components: [X25519, ML-KEM-768]
  nist_quantum_level: 3
```

Complete list M1 must cover: RSA, DSA, DH/FFDHE, ECDH, ECDHE, X25519, X448, ECDSA, Ed25519, Ed448, SM2, ElGamal, ECIES, AES(128/192/256 × modes), ChaCha20(-Poly1305), 3DES, DES, RC4, RC2, Blowfish, IDEA, Camellia (same as AES by key size), SEED, MD5, MD4, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256, SHA3-*, SHAKE*, BLAKE2/3, HMAC-*, Poly1305, CMAC, GMAC, PBKDF2, HKDF, scrypt, bcrypt, Argon2, ML-KEM-*, ML-DSA-*, SLH-DSA-*, FN-DSA/Falcon, LMS, XMSS, HQC, all hybrid groups in 7.4.

### 7.3 Decomposition rules (M1, `engine/decompose.py`)

| Input pattern | Output components |
|---|---|
| `TLS_<KX>_<AU>_WITH_<CIPHER>_<MAC>` (TLS ≤1.2) e.g. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | KX=ECDHE (key_exchange), AU=RSA (authentication/signature), CIPHER=AES-128-GCM (encryption), MAC/PRF=SHA-256 (mac). If `<KX>_<AU>` is a single token `RSA` → KX=RSA key transport, AU=RSA, `forward_secrecy=false`. `ECDH_`/`DH_` (static) → `forward_secrecy=false`. `PSK`, `anon` → note. |
| `TLS_<CIPHER>_<HASH>` (TLS 1.3) e.g. `TLS_AES_128_GCM_SHA256` | AES-128-GCM (encryption) + SHA-256 (hash/HKDF). **Key exchange comes from the negotiated group, not the suite.** |
| OpenSSL names `ECDHE-RSA-AES128-GCM-SHA256` | same as above (map via `tls_registry.yaml` openssl_name column) |
| JCA signature `SHA256withECDSA`, `SHA1withRSA`, `SHA256withRSA/PSS`, `Ed25519` | hash + signature algorithm |
| JCA transform `AES/CBC/PKCS5Padding`, `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`, `DESede/CBC/NoPadding` | algorithm + mode + padding (+ hash for OAEP) |
| TLS sig scheme `ecdsa_secp256r1_sha256`, `rsa_pss_rsae_sha256`, `ed25519`, `mldsa65` | signature algorithm (+curve) + hash |
| JWT/JOSE `RS256`, `PS256`, `ES256`, `EdDSA`, `HS256`, `A128GCM`, `RSA-OAEP`, `ECDH-ES` | RSA+SHA-256, RSA-PSS+SHA-256, ECDSA-P256+SHA-256, Ed25519, HMAC-SHA256, AES-128-GCM, RSA-OAEP, ECDH |
| KMS key specs `RSA_2048`, `ECC_NIST_P256`, `ECC_SECG_P256K1`, `SYMMETRIC_DEFAULT`, `HMAC_256`, `ML_DSA_65` | per `cloud_registry.yaml` |
| SSH (**P0**) `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, `ecdh-sha2-nistp256`, `curve25519-sha256`, `mlkem768x25519-sha256`, `sntrup761x25519-sha512`, `ssh-rsa`, `rsa-sha2-512`, `ssh-ed25519`, `3des-cbc`, `aes128-cbc`, `aes256-gcm@openssh.com` | kex / host-key / cipher algorithms (see 7.1 SSH rules) |
| ACM `KeyAlgorithm` `RSA_2048`, `EC_prime256v1`, `EC_secp384r1`; `SignatureAlgorithm` `SHA256WITHRSA`, `ECDSA_WITH_SHA256`, `SHA1WITHRSA` | key + signature hash (per `cloud_registry.yaml`) |

Unit-test every row with at least 2 examples.

### 7.4 TLS codepoints (`tls_registry.yaml`, M2)

**Do not hand-type the whole IANA table.** Download the IANA TLS parameters CSVs once (cipher suites, supported groups, signature schemes), commit them to `kb/iana/`, and generate `tls_registry.yaml` with a script. Then add/override PQC entries below (the IANA CSV snapshot may lag).

Named groups (hex) — the ones that matter:

| Code | Name | Tier |
|---|---|---|
| 0x0017 | secp256r1 | CRITICAL |
| 0x0018 | secp384r1 | CRITICAL |
| 0x0019 | secp521r1 | CRITICAL |
| 0x001D | x25519 | CRITICAL |
| 0x001E | x448 | CRITICAL |
| 0x0100–0x0104 | ffdhe2048 … ffdhe8192 | CRITICAL |
| 0x0200 | MLKEM512 | SAFE |
| 0x0201 | MLKEM768 | SAFE |
| 0x0202 | MLKEM1024 | SAFE |
| 0x11EB | SecP256r1MLKEM768 | SAFE (hybrid) |
| 0x11EC | X25519MLKEM768 | SAFE (hybrid) — today's browser/Cloudflare default |
| 0x11ED | SecP384r1MLKEM1024 | SAFE (hybrid) |
| 0x6399 | X25519Kyber768Draft00 | SAFE + deprecated draft |
| 0x639A | SecP256r1Kyber768Draft00 | SAFE + deprecated draft |

Signature schemes:

| Code | Name | Tier |
|---|---|---|
| 0x0201 | rsa_pkcs1_sha1 | CRITICAL (+SHA-1 broken) |
| 0x0203 | ecdsa_sha1 | CRITICAL (+SHA-1 broken) |
| 0x0401 / 0x0501 / 0x0601 | rsa_pkcs1_sha256/384/512 | CRITICAL |
| 0x0403 / 0x0503 / 0x0603 | ecdsa_secp256r1_sha256 / secp384r1_sha384 / secp521r1_sha512 | CRITICAL |
| 0x0804–0x0806 | rsa_pss_rsae_sha256/384/512 | CRITICAL |
| 0x0809–0x080B | rsa_pss_pss_sha256/384/512 | CRITICAL |
| 0x0807 / 0x0808 | ed25519 / ed448 | CRITICAL |
| 0x0904 / 0x0905 / 0x0906 | mldsa44 / mldsa65 / mldsa87 | SAFE (IETF draft codepoints — verify) |

TLS 1.3 cipher suites: `0x1301 TLS_AES_128_GCM_SHA256` (MEDIUM), `0x1302 TLS_AES_256_GCM_SHA384` (SAFE), `0x1303 TLS_CHACHA20_POLY1305_SHA256` (SAFE), `0x1304 TLS_AES_128_CCM_SHA256` (MEDIUM), `0x1305 TLS_AES_128_CCM_8_SHA256` (MEDIUM).

Common TLS 1.2 suites to test: `0xC02F TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `0xC030 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `0xC02B/0xC02C` ECDHE_ECDSA AES-GCM, `0xCCA8/0xCCA9` ECDHE ChaCha20, `0x009C/0x009D TLS_RSA_WITH_AES_128/256_GCM_*` (static RSA!), `0x002F/0x0035 TLS_RSA_WITH_AES_128/256_CBC_SHA`, `0x000A TLS_RSA_WITH_3DES_EDE_CBC_SHA`, `0x0005 TLS_RSA_WITH_RC4_128_SHA`, `0x009E/0x009F TLS_DHE_RSA_WITH_AES_*_GCM_*`.

Versions: `0x0300 SSLv3, 0x0301 TLS1.0, 0x0302 TLS1.1, 0x0303 TLS1.2, 0x0304 TLS1.3`. In TLS 1.3 the real version is in the `supported_versions` extension (legacy_version field still says 0x0303).

### 7.5 Scoring model (`scoring.yaml`, M1)

Per asset:

```
tier_weight:      CRITICAL=10, MEDIUM=4, UNKNOWN=2, SAFE=0
exposure (pick the max that applies):
  in-transit negotiated key exchange (pcap/live)     1.5   # HNDL
  public load balancer policy                        1.5
  in-transit negotiated other (cipher, auth)         1.2
  KMS key enabled                                    1.2   # long-lived keys
  production code / config / key file                1.0
  in-transit offered-only (not negotiated)           0.4
  KMS key disabled / pending deletion                0.3
  test / example / mock code only                    0.3
broken_multiplier: 1.5 if classically_broken else 1.0
occurrence_factor: 1 + log2(1 + min(occurrences, 31)) / 5     # more places = more work/risk, but bounded

risk_points = tier_weight * exposure * broken_multiplier * occurrence_factor * confidence
max_points  = 10 * exposure * 1.5 * occurrence_factor * confidence
```

Enterprise score:

```
base   = 100 * Σ risk_points / Σ max_points
floor  = 60 if any (hndl_exposed and negotiated) else 0    # an active HNDL exposure can't look "fine"
score  = round(max(base, floor))                            # 0..100, higher = worse
grade  = A (0–10) B (11–25) C (26–40) D (41–60) E (61–80) F (81–100)
readiness_pct = % of eligible classified assets with tier SAFE (excluding UNKNOWN)
score_by_source = same formula restricted to each source_type
```

Insecure-RNG, plaintext/hygiene-only warnings, libraries, and derived protocol containers are shown but excluded from quantum score/readiness denominators. Unknown cryptographic assets remain scoreable. Preserve per-finding confidence, source, exposure, state, and offered/negotiated status through aggregation. Use maximum applicable exposure and maximum confidence among relevant findings; count unique evidence for occurrences. For source summaries, restrict evidence to that source before applying the same formula and floor. Zero eligible point totals yield score 0/grade A; readiness is 0 when no eligible classified assets exist. All numbers live in `scoring.yaml`; the formula is shown on the dashboard under "How is this calculated?" (transparency scores points).

### 7.6 CycloneDX 1.6 CBOM mapping (M4, `output/cyclonedx.py`)

- `bomFormat: "CycloneDX"`, `specVersion: "1.6"`, `serialNumber: "urn:uuid:…"`, `metadata.tools.components[]` = QuantumTrace, `metadata.timestamp`.
- One component per `CryptoAsset`: `type: "cryptographic-asset"`, `bom-ref: asset_id`, `name: canonical_name`.
- `cryptoProperties`:
  - `assetType`: `algorithm` | `certificate` | `protocol` | `related-crypto-material`
  - `algorithmProperties`: `primitive` (one of `drbg, mac, block-cipher, stream-cipher, signature, hash, pke, xof, kdf, key-agree, kem, ae, combiner, other, unknown`), `parameterSetIdentifier`, `curve`, `mode` (`cbc, ecb, ccm, gcm, cfb, ofb, ctr, other, unknown`), `padding`, `cryptoFunctions` (`generate, keygen, encrypt, decrypt, digest, tag, keyderive, sign, verify, encapsulate, decapsulate, other, unknown`), `executionEnvironment`, `implementationPlatform`, `classicalSecurityLevel`, `nistQuantumSecurityLevel`.
  - `protocolProperties` for TLS: `type: "tls"`, `version`, `cipherSuites: [{name, algorithms: [bom-refs], identifiers: ["0xC0","0x2F"]}]`.
  - `certificateProperties` for certs: `subjectName`, `issuerName`, `notValidBefore`, `notValidAfter`, `signatureAlgorithmRef`, `subjectPublicKeyRef`, `certificateFormat`.
  - `relatedCryptoMaterialProperties` for KMS keys / PEM keys: `type` (`public-key`, `private-key`, `secret-key`…), `id`, `state`, `algorithmRef`, `size`, `creationDate`.
  - `oid`.
- `evidence.occurrences[]`: `{location: "src/app/crypto.py", line: 42, additionalContext: snippet}`; for pcap use `location: "captures/legacy.pcap#frame=17 10.0.0.5:51234->…:443 sni=…"`.
- QuantumTrace-specific data in `properties[]` with a namespace: `quantumtrace:tier`, `quantumtrace:threat`, `quantumtrace:hndlExposed`, `quantumtrace:classicallyBroken`, `quantumtrace:riskPoints`, `quantumtrace:recommendation`, `quantumtrace:replacementStandard` (e.g. `NIST FIPS 203`).
- `dependencies[]`: protocol asset `dependsOn` its algorithm assets; library components (`type: library`, purl) `dependsOn` algorithms they use (P1, from manifests).
- **Validate** in tests: `JsonStrictValidator(SchemaVersion.V1_6).validate_str(json)` must return `None`. Run on every fixture.

### 7.7 Native report (`report.json`) and `summary.md`

`report.json` is the JSON serialization of `ScanResult`, including its optional typed `roadmap` field established in initial task 1.2. It must round-trip through `ScanResult.model_validate`; do not append an untyped report-only block. Roadmap phases follow:

```
Phase 0 (this week): classically broken items — RSA-1024, MD5, SHA-1, 3DES/CBC suites, TLS ≤ 1.1, SSH group1/ssh-rsa, plaintext HTTP listeners, expired-but-serving certs
Phase 1 (now):    in-transit key exchange with HNDL exposure → enable hybrid X25519MLKEM768 (FIPS 203) on LBs/servers; kill static-RSA suites
Phase 2 (≤2027):  signatures & PKI (certs, code signing, JWT, KMS signing keys) → ML-DSA (FIPS 204) / SLH-DSA (FIPS 205); inventory cert expiry beyond 2030
Phase 3 (≤2030):  symmetric/hash hardening → AES-256, SHA-384; remove 3DES/RC4/MD5/SHA-1 now (classically broken)
Regulatory note:  NIST IR 8547 (draft) — quantum-vulnerable algorithms deprecated after 2030, disallowed after 2035 (verify current text); CNSA 2.0 timelines for NSS.
```

`summary.md` = one-page executive summary: score, grade, counts, top 10 risks with evidence, roadmap.

---

## 8. Work Packages per Member

All four are generalists, so the split is by **module ownership** with balanced load. Each member owns their tests and fixtures. **M1 is also the integrator** (merges, keeps `main` green). Timings are for the **24h** event (see section 9). The starter kit was pre-analysed — read **Appendix D** first; it replaces the "inspect the kit" tasks and gives you the expected results.

**Split rationale.** Code scanning carries the most accuracy weight and is the hardest (key sizes live behind constants), so M3 does *only* code (+ P2 config/key files). All three cloud JSON dumps (KMS, load balancers, ACM) are small, clean and share one registry and one UI page, so they belong to a single owner: M4. M2 keeps everything that touches packets (TLS + SSH).

### M1 — Core, Knowledge Base & Risk Engine (+ CLI, integration, native report)

**Owns:** `models.py`, `pipeline.py`, `cli.py`, `kb/algorithms.yaml`, `kb/scoring.yaml`, `kb/loader.py`, `engine/**`, `scanners/base.py`, `output/report_json.py`, `scripts/eval.py`, `Makefile`.

| # | Task | Priority | Done when |
|---|---|---|---|
| 1.1 | Repo skeleton, pyproject, Makefile, ruff, pytest | P0 | `make install test lint` pass on empty project (H0.5) |
| 1.2 | `models.py` exactly as section 6 + `scanners/base.py` (protocol, registry, `finding_id`, `is_test_path`) | P0 | committed & announced at **H1** (contract freeze) |
| 1.3 | `algorithms.yaml` full family list (7.2) incl. SSH names + `loader.py` with validation | P0 | loader test checks every entry has tier/threat/replacement |
| 1.4 | `normalize.py` (aliases + regex patterns, param extraction) | P0 | ≥ 60 parametrised tests incl. tricky ones (`prime256v1`, `P-256`, `secp256r1` → same; `Kyber768` → ML-KEM-768; `ssh-rsa` → RSA + SHA-1; `diffie-hellman-group14-sha1`) |
| 1.5 | `decompose.py` (all rows of 7.3) | P0 | tests per row |
| 1.6 | `classify.py` (tier, threat, flags, rationale, recommendations, OIDs, levels; `plaintext` findings → "no encryption" note, excluded from quantum score) | P0 | golden subset passes |
| 1.7 | `aggregate.py` dedupe: same canonical asset + same usage → one asset with many occurrences; protocol assets link components | P0 | |
| 1.8 | `score.py` (7.5) | P0 | unit tests with hand-computed values |
| 1.9 | `pipeline.py` router: walk inputs, dispatch by `can_handle`, collect findings/errors, call engine, build `sessions` from M2's data | P0 | end-to-end on starter kit at **H6** |
| 1.10 | `cli.py`: `qtrace scan <paths…> [--probe host:port] [--out dir] [--format json,cbom,md]`, Rich tables + score panel; `qtrace eval`; `qtrace ui`. Unavailable requested adapters/writers give explicit errors; `--fail-on` is task 1.13 | P0 | |
| 1.11 | `output/report_json.py` + roadmap builder (7.7) *(moved from M4)* | P0 | H8 |
| 1.12 | `scripts/eval.py` precision/recall vs `tests/golden/expected.yaml` (seeded from Appendix D) | P1 | `make eval` prints table per source + overall |
| 1.13 | `--fail-on` exit codes for CI use; JSON to stdout option | P2 | |

### M2 — Network Layer (PCAP, TLS sessions, SSH, live probe)

**Owns:** `scanners/network/**`, `kb/tls_registry.yaml` (+ `kb/iana/`), `scripts/gen_pcaps.sh`, `tests/fixtures/pcap/`.

| # | Task | Priority | Done when |
|---|---|---|---|
| 2.1 | Install tshark; confirm Appendix D numbers (97 TLS sessions, 24 SSH, 14 HTTP) with `tshark -r network.pcap -Y tls.handshake`; note differences in communication/ agreements | P0 | H1 |
| 2.2 | `purepy.py`: pure-Python classic-pcap + Ethernet/IPv4/TCP reader and TLS ClientHello/ServerHello parser (≈ 100 lines; a working prototype logic is described in Appendix D.1). Used when tshark is missing, and as the SSH transport | P0 | parses starter pcap without tshark |
| 2.3 | `tls_registry.yaml` generator from IANA CSVs + PQC overrides (7.4) + GREASE filter helper | P0 | |
| 2.4 | `tshark.py`: run `tshark -r <file> -Y "tls.handshake.type==1 or tls.handshake.type==2 or tls.handshake.type==11 or tls.handshake.type==12" -T json`; verify field names with `tshark -G fields \| grep tls.handshake`; request **numeric** values. Ports 587 (SMTP STARTTLS), 5432 (Postgres SSLRequest), 636 (LDAPS), 993 (IMAPS) must all be decoded — add `-d tcp.port==N,tls` and check STARTTLS/pgsql dissectors; otherwise fall back to `purepy.py` | P0 | all 97 sessions found |
| 2.5 | `tls_session.py`: pair ClientHello/ServerHello by TCP stream, produce raw session evidence in `Finding.extra["session"]` + Findings (M1 constructs classified `TLSSession` views in task 1.9): offered (negotiated=False) and selected (negotiated=True) cipher suite, group, version, sig schemes; `service` label from port (`https`, `ldaps`, `imaps`, `smtp-starttls`, `postgres`); `session_id` on all findings. TLS 1.3 version comes from `supported_versions`, not `legacy_version` | P0 | |
| 2.6 | `ssh.py`: SSH banner + `SSH_MSG_KEXINIT` (msg 20) name-lists: kex, host key, cipher c→s, MAC. Negotiated = first client algorithm also in the server list. Findings with `source_type=SSH`, offered vs negotiated. 24 sessions in the kit (14 legacy / 10 modern); note OpenSSH banner versions as evidence | P0 | |
| 2.7 | Plaintext detection: TCP flows on port 80 with `HTTP/1.1` and STARTTLS flows that never upgrade → `KindHint.PLAINTEXT` finding (14 HTTP sessions in the kit) | P1 | |
| 2.8 | Generate own fixtures (`gen_pcaps.sh`, OpenSSL ≥ 3.5 + `tcpdump -i lo`) for what the kit **lacks**: (a) TLS 1.2 ECDHE-ECDSA P-256 with certificate, (b) client offers `X25519MLKEM768` but server only x25519 ("the server is the blocker"), (c) TLS 1.0 3DES (`DES-CBC3-SHA@SECLEVEL=0`), (d) TLS 1.3 hybrid with a keylog file | P0 | 4 small pcaps committed |
| 2.9 | `certs.py`: TLS 1.2 Certificate message → `cryptography.x509` → key type/size/curve, signature algorithm, validity. **The kit capture appears to contain no Certificate messages — verify in 2.1; test on own fixture 2.8(a).** Flag certs valid beyond 2030 | P1 | |
| 2.10 | TLS 1.2 ServerKeyExchange: named curve + signature algorithm used | P2 | |
| 2.11 | `probe.py`: `host:port` → `openssl s_client -groups X25519MLKEM768` etc. Endpoints are **not provided yet**; keep behind `--probe`, timeouts 10s, never crash | P2 | |
| 2.12 | Keylog support `--tls-keylog file`; QUIC | P2 | |

### M3 — Code Inspection (Python / Java / Go) + P2 config & key files

**Owns:** `scanners/code/**`, `scanners/config/**`, `output/markdown.py`, `output/sarif.py`, code/config fixtures, and the **Code & Config** React page.

| # | Task | Priority | Done when |
|---|---|---|---|
| 3.1 | Read the 24 starter files against Appendix D.4; add corrections and the `tests/golden/expected.yaml` code section | P0 | H1.5 |
| 3.2 | `code/engine.py`: YAML rule runner. Rule = `{id, language, pattern (regex, multiline ok), raw_name (template), kind_hint, usage, key_size_group?, curve_group?, mode_group?, confidence}`. Skip comment lines. Mark `in_test_code` by path. **File-scope constant resolution (P0):** collect `NAME = literal` / `static final … NAME = literal` / Go `const`/`var` and substitute when a call uses an identifier (`key_size=KEY_LEN`, `generator.init(KEY_BITS…)`, `Cipher.getInstance(TRANSFORMATION)`, `aes.NewCipher(exportKey)` → 16-byte string literal ⇒ AES-128). Generic ±5-line look-ahead is only the fallback | P0 | all 24 kit files match Appendix D.4 |
| 3.3 | `rules/python.yaml`: `cryptography` (`rsa.generate_private_key(…key_size=N)`, `ec.*`, `x25519`, `ed25519`, `padding.*`, `Cipher(algorithms.AES(key), modes.*)`, `AESGCM`, `ChaCha20Poly1305`, `PBKDF2HMAC(algorithm=hashes.X)`, `hashes.SHA1/MD5/…`), `hashlib.md5/sha1/sha256/sha384/new("…")`, `hmac.new(…, hashlib.X)`, PyCryptodome, `random.*` for tokens/keys, `jwt` algorithms, `ssl` options, PQC libs (`oqs`) | P0 | ≥ 1 fixture + test per rule |
| 3.4 | `rules/java.yaml`: `KeyPairGenerator.getInstance("RSA"/"EC"/"Ed25519"/"ML-KEM"…)` + `.initialize(N)`, `Cipher.getInstance("AES/ECB/…")` (bare `"AES"` = ECB default — flag), `Signature.getInstance("SHA1withRSA"/"Ed25519")`, `MessageDigest.getInstance("MD5"/"SHA-1"/"SHA-384")`, `Mac.getInstance("HmacSHA256")`, `KeyGenerator` + `.init(N)`, `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")`, `new Random()` vs `SecureRandom`, BouncyCastle | P0 | |
| 3.5 | `rules/go.yaml`: imports + calls: `rsa.GenerateKey(rand.Reader, N)`, `ed25519.GenerateKey`, `aes.NewCipher` (+ `cipher.NewGCM` ⇒ GCM; manual `block.Encrypt` loop ⇒ ECB), `sha1.Sum`, `md5.Sum`, `sha512.Sum384`, `hmac.New(sha256.New, …)`, `crypto.SHA1`, hand-rolled PBKDF2 (HMAC-SHA256 in a loop; no pbkdf2 import), `math/rand` vs `crypto/rand`, `tls.Config{…}` | P0 | |
| 3.6 | Import-only findings (`confidence 0.6`) deduped against call findings in the same file (call wins) — critical because `crypto/sha256` is imported in files that only use it for HMAC/PBKDF2 | P0 | no double counting |
| 3.7 | **SAFE decoy discipline:** AES-256-GCM, SHA-384, HMAC-SHA256, PBKDF2-SHA256, `SecureRandom`, `crypto/rand`, `os.urandom` must come out SAFE (or no finding), never MEDIUM/CRITICAL. Every decoy has a test | P0 | |
| 3.8 | Hard-coded key material (`EXPORT_KEY = b"0123456789ABCDEF"`) → extra `related-crypto-material` finding "hard-coded symmetric key" (not a quantum issue; shown as a warning) | P1 | |
| 3.9 | `python_ast.py`: import-alias resolution, keyword args, module-level constants | P1 | |
| 3.10 | `manifests.py`: `requirements.txt` (kit: `cryptography==46.0.5` only), pom.xml, go.mod → `library` findings | P1 | |
| 3.11 | `output/markdown.py` executive summary (7.7) *(moved from M4)* | P1 | |
| 3.12 | React **Code & Config** page (findings grouped by file, snippet + line, tier badge, recommendation, filters) — built against M4's API/components once available | P1 | H12 |
| 3.13 | `config/webserver.py` (nginx/Apache/HAProxy/Spring/openssl.cnf/java.security), `config/keyfiles.py` (PEM/DER/SSH keys; never print private key material) — **no sample data in the kit; build only with own tiny fixtures** | P2 | |
| 3.14 | `output/sarif.py`; binary/JAR scanning | P2 | |

### M4 — Cloud, Output (CBOM), FastAPI, React Dashboard, Packaging & Demo

**Owns:** `scanners/cloud/**`, `kb/cloud_registry.yaml`, `output/cyclonedx.py`, `api/**`, `frontend/**` (shared with M3 for one page), `Dockerfile`, `README.md`, `scripts/demo.sh`, `tests/fixtures/{cloud,scan_result_sample.json}`, pitch deck.

| # | Task | Priority | Done when |
|---|---|---|---|
| 4.1 | Hand-write `scan_result_sample.json` (≈ 30 assets across all sources & tiers, 5 TLS sessions, 2 SSH sessions) that validates against `ScanResult` — lets UI work start immediately | P0 | H1.5 |
| 4.2 | Scaffold: Vite + React + TypeScript + Tailwind + Recharts (or Plotly.js); `api/main.py` FastAPI with `/api/result` serving the sample; TS types generated from `/openapi.json` (`openapi-typescript`) | P0 | `npm run dev` shows the sample at H3 |
| 4.3 | `cloud/kms.py`: AWS `ListKeys/DescribeKey` shape (`Keys[]`: `KeySpec`, `KeyUsage`, `KeyState`, `Origin`, `SigningAlgorithms`, `EncryptionAlgorithms`, `KeyRotationStatus`, `DeletionDate`, `ValidTo`, `MultiRegion`); evidence `resource_id=KeyArn`; one `key` Finding per key + algorithm Findings. State feeds exposure (PendingDeletion 0.3) | P0 | 10 kit keys match Appendix D.5 |
| 4.4 | `cloud/loadbalancer.py` + `cloud_registry.yaml`: per listener `Protocol`/`Port`/`SslPolicy` → protocols + cipher suites + groups (hand-built from the AWS ELB security-policy table, items marked verify; unknown policy → UNKNOWN, confidence 0.5). `HTTP:80` listeners with no policy → `plaintext` finding. `Scheme: internet-facing` ⇒ public exposure 1.5 | P0 | 7 listeners match Appendix D.5 |
| 4.5 | `cloud/acm.py`: `KeyAlgorithm` (`RSA_2048`, `EC_prime256v1`, `EC_secp384r1`), `SignatureAlgorithm` (`SHA256WITHRSA`, `ECDSA_WITH_SHA256`, `SHA1WITHRSA`), `NotAfter`, `Type`, `InUseBy`; join to LB listeners by ARN; anomaly flags (expired but ISSUED and in use; expires < 90 days; imported cert; SHA-1 signature) | P0 | 5 certs match Appendix D.5 |
| 4.6 | `output/cyclonedx.py` (7.6) + `validate_cbom` + test that strict-validates every fixture's CBOM | P0 | strict validator passes |
| 4.7 | API: `POST /api/scan` (upload zip/files or `{path}` → `pipeline.run`), `GET /api/cbom`, `GET /api/report.md`, `GET /api/validate`; CORS for Vite dev; static serving of `frontend/dist` | P0 | |
| 4.8 | **Overview** page: score gauge (0–100, colour by grade), readiness %, tier donut, stacked bar by source, HNDL counter, top-10 risks, "How is the score calculated?" panel; upload + download buttons (CBOM, JSON, MD) | P0 | |
| 4.9 | **Network** page: TLS + SSH sessions table (service, SNI/host, version, negotiated group/kex, suite, PQ-status badge 🟢 hybrid / 🔴 classical), offered-vs-negotiated view, filter by service/port | P1 | |
| 4.10 | **Cloud** page: KMS keys table, LB listeners → policy → certificate (joined), plaintext listeners callout, cert expiry timeline | P1 | |
| 4.11 | **CBOM** page (component explorer, raw JSON, validation ✅, FIPS 203/204/205 mapping table) and **Roadmap** page (phases from 7.7, effort = occurrence count) | P1 | |
| 4.12 | Dockerfile (multi-stage) + README (one-command setup, screenshots, architecture diagram) | P0 | clean-machine `docker build && docker run` works by **H18** |
| 4.13 | `scripts/demo.sh` — deterministic demo run on starter kit producing `out/` | P1 | |
| 4.14 | Pitch deck (5–6 slides) + backup screen recording | P0 | H22 |
| 4.15 | `cloud/generic_json.py`: recursive fallback walker for unknown JSON dumps | P2 | |

**Load balance check:** M1 is heavy on logic until H6, then takes `report_json`, eval and bug fixing. M2 is heavy throughout (TLS + SSH + fixtures) but has the best-defined data. M3 is a single-language-family, accuracy-critical job with the lightest "plumbing", so it also gets markdown/SARIF and one React page. M4 has the widest surface (cloud + CBOM + API + React + Docker + deck); to protect them, `report_json`/roadmap went to M1 and the Code & Config page to M3, and the three cloud adapters share one pattern (one JSON → Findings). **If M4 falls behind at H6, M1 takes the CBOM validator tests and M3 takes the Roadmap page.** Anyone ahead of schedule picks P1/P2 items from others **after** asking the owner.

---

## 9. Timeline & Checkpoints

**24-hour event.** Times are hours from kickoff (H0). All P2 items are dropped unless everything above them is green.

| Block | M1 | M2 | M3 | M4 |
|---|---|---|---|---|
| **H0–H1** Kickoff | Skeleton, `models.py`, `base.py` → **contract freeze H1** | Install tshark; verify Appendix D numbers | Verify Appendix D.4 on the 24 files; seed golden list | Sample `ScanResult` JSON; Vite + FastAPI skeleton |
| **H1–H4** MVP | KB core families, normalise, decompose | `purepy.py` + `tshark.py`; hellos → Findings; SSH KEXINIT | Rule engine + **constant resolution**; Python & Java rules | KMS / LB / ACM adapters + registry; Overview page on sample data |
| **H4–H6** Close loop | Classify, aggregate, score, pipeline, CLI | Sessions, STARTTLS/pgsql, GREASE, `service` labels | Go rules, import/call dedupe, SAFE decoys, test-path | CBOM builder + validation; `/api/scan` |
| **H6 ✅ Checkpoint 1** | **End-to-end: `qtrace scan .` → report.json + cbom → React dashboard.** Everyone fixes integration bugs before continuing. |||
| **H6–H12** Depth | Full KB, `report_json` + roadmap, eval script, golden merged | Own fixtures (ECDHE cert, offer-vs-negotiated), plaintext detection, certs | Hard-coded keys, AST aliases, manifests, Code & Config page | Network / Cloud pages, Dockerfile |
| **H12 ✅ Checkpoint 2** | **Feature freeze for P0+P1.** `make eval` reported; list of known false positives/negatives. Decide which P2s to attempt (probe only if endpoints exist). |||
| **H12–H18** Polish | Accuracy fixes from eval | P2 only if green; help M4 with fixtures | `markdown.py`; P2 config/keyfiles with own fixtures | CBOM & Roadmap pages, README, `demo.sh` |
| **H18–H21** Harden | Bug bash on starter kit + own fixtures; Docker on a clean machine; screenshots |||
| **H21 ✅ Code freeze** | Only demo-breaking fixes after this. Tag `v1.0`. |||
| **H21–H24** Pitch | Rehearse ×3, record backup video, finalise deck (M4 owns) |||

Sleep: with 24h, staggered short naps only — two members nap H9–H11, two H12–H14 — so someone can always merge.

**Stand-up format (every ~3h, 3 min):** done / next / blocked / contract changes needed.

---

## 10. Testing & Accuracy Evaluation

### 10.1 Unit tests (each owner)

- Engine: parametrised normalise/decompose/classify tests (≥ 100 cases total). Include **judge traps**: X25519 = CRITICAL; Ed25519 = CRITICAL; AES-128 = MEDIUM; AES-256 = SAFE; SHA-256 = SAFE; SHA-1 = MEDIUM+broken; X25519MLKEM768 = SAFE; `Cipher.getInstance("AES")` → ECB warning; GREASE ignored; TLS 1.3 legacy_version not reported as TLS 1.2.
- Scanners: each rule has a fixture file and an assertion on raw_name, line, key_size.
- Output: CBOM strict-validates; JSON round-trips through `ScanResult.model_validate`.

### 10.2 Golden ground truth (`tests/golden/expected.yaml`)

The starter kit's "intentional patterns" are what judges will check. **Appendix D already contains the hand-verified expectations** (24 code files, 97 TLS sessions, 24 SSH sessions, 10 KMS keys, 7 listeners, 5 certificates). M1 converts Appendix D into `expected.yaml`; each member then adds expectations for their own fixtures:

Owner contributions follow [GOLDEN.md](GOLDEN.md) and
[golden.schema.json](golden.schema.json): a top-level list with explicit asset,
finding, session and count entries. M4 supplies confirmed cloud rows; raw warnings
and counts do not inflate algorithm accuracy. M1 implements the evaluator in 1.12.

`make eval` matches produced assets/occurrences to the golden list (tolerance ±2 lines) and prints **precision, recall and tier accuracy** per source type plus a list of misses and false positives. Target: ≥ 0.95 recall, ≥ 0.95 precision on the starter kit (it is small — every miss is visible). Show the table in the pitch.

### 10.3 CI-lite

`make check` runs Ruff lint/format checks and pytest during foundation development.
Task 1.12 adds evaluation to this gate once it exists. Run before every push to
`main`. (Optional GitHub Action running the same.)

---

## 11. Git Workflow & Conventions

- **M1 implementation branch**: reuse the persistent `m1` branch for every M1
  implementation task. Fetch origin, synchronize with origin/m1 and merge current
  origin/main as needed, preserving published history and recording pending commits.
  Do not create a new M1 branch per task.
- **Communications**: all members publish communications directly to `main`, with
  associated shared plan updates. Reconcile current origin/main and run applicable
  checks before pushing; preserve other members' work and repository protections.
  Pending implementation stays on member branches.
- **Milestone integration**: integrate implementation into main at significant
  milestones. Default M1 milestones are core engine (1.3–1.8), runnable CLI/native
  reports (1.9/1.11/1.10), and evaluation/starter integration (1.12/integration).
  Prefer PRs with cumulative green checks, preserve ownership and protections,
  and never force-push main. Optional work waits for a designated release milestone.
  Communications can advance main between implementation milestones.
- **Commit messages**: `area: imperative summary` (e.g. `engine: classify X25519 as Shor-vulnerable`).
- **M1 identity**: use configured author and committer `David Correia <davidfgcorreia@gmail.com>`. Do not add Codex co-author trailers to commits or PR merge/squash messages. Verify identity before committing; do not change global Git settings.
- **Task completion**: plan, implement, validate, save the local handoff, commit
  and push the implementation branch (`m1` for M1), and verify its remote commit. Record main integration
  separately as pending until a designated milestone is merged and its remote
  ancestry verified. A local commit alone is not remote publication.
- **Code style**: type hints everywhere, ruff default + `I` (isort), max line 110, docstrings on public functions, `logging` (no `print` outside CLI/UI).
- **No secrets, no real customer data** in the repo. The starter kit stays at the repo root (`sample-repos/`, `cloud-posture/`, `network-capture/`) and is **read-only**; generated output goes to `out/` (gitignored).
- **Determinism**: sort outputs (assets by risk desc then name; occurrences by file/line); stable IDs.
- **Performance budget**: full starter-kit scan < 60 s; skip files > 5 MB in code scanner; ignore `.git`, `node_modules`, `venv`, `vendor` (configurable).
- **Decisions log**: any deviation from this plan → an agreement item/reply in `communication/`, reflected in this plan when shared behavior changes.

---

## 12. Working with coding agents

Members retain their ownership boundaries. M1 uses a fresh session for each task:

1. **Repository instructions**: all members read this shared plan. M1 additionally reads the local-only root `AGENTS.md`, `agents/IMPLEMENTATION.md`, `agents/STATUS.md`, active task plan, and previous handoff. Shared instructions must not require these files to exist in another member's checkout.
2. **Reusable local skills**: M1's local root instructions route explicitly to `agents/skills/qtrace-task-cycle/SKILL.md`, `qtrace-core-engine/SKILL.md`, and `qtrace-integration/SKILL.md`. Use writable `agents/`, because `.agents/` is protected; automatic discovery is not assumed. Root `AGENTS.md` and all of `agents/` are Git-ignored: never stage or force-add them.
3. **Plan first**: refresh the individual task plan with current repo facts, dependencies, owned changes, and acceptance checks before implementation. The user-approved roadmap authorizes ordinary implementation choices without a recurring approval gate.
4. **Contract-first**: import types from `quantumtrace.models`; do not redefine them. Establish the approved initial additions in 1.2, then freeze contracts and coordinate later changes with the team.
5. **Test meaningful behavior**: use local fixtures and run the checks available at the current stage. Record unavailable checks honestly; no application `make check` exists during workflow-only M1-00.
6. **Handoff at task end**: record outcome, interface changes, exact checks/results, blockers, branch/commit/PR integration evidence, and the next-session prompt in the local task file. Update task completion after remote branch verification and main integration separately after a milestone; local updates need no additional Git commit.
7. **Fresh context**: end the session after its task handoff. The user opens a new session that reads these files; agents do not claim to clear conversation context or launch concurrent work.
8. **Ownership and accuracy**: do not silently fix another member's modules; record requests in communication/ and local handoffs. Never invent codepoints, OIDs, KMS mappings, or standards status; verify primary sources during the owning task and keep uncertain values explicit.

---

## 13. Demo & Pitch

**3-minute flow (rehearsed, scripted in `scripts/demo.sh`), built on the real starter kit:**

1. **Hook (20s):** "Adversaries are recording your traffic today to decrypt it with tomorrow's quantum computers. Most companies can't even say where RSA and ECDH live in their estate."
2. **One command (20s):** `qtrace scan .` — progress across PCAP, SSH, code and cloud, ending with the score panel (**Quantum Risk Score + grade, N HNDL-exposed sessions**).
3. **Dashboard (90s):**
   - Overview: gauge, tier donut, per-source bars.
   - Network: **54 of 97 TLS sessions** negotiate static-RSA `TLS_RSA_WITH_AES_128_CBC_SHA` across HTTPS, LDAPS and SMTP-STARTTLS → "no forward secrecy, every recorded session falls with one key". **36 sessions are TLS 1.3 + x25519 — modern but not quantum-safe.** Only **7 `vault*.lab` sessions** negotiate `X25519MLKEM768` (green) — and even those have unknown/classical authentication.
   - SSH: legacy `diffie-hellman-group1-sha1` + `ssh-rsa` + 3DES next to modern `curve25519-sha256` — still not PQ.
   - Offered-vs-negotiated (own fixture): client offers ML-KEM, server refuses → "the server is the blocker".
   - Code: the same RSA-1024 + SHA-1 signing flaw found in **Python, Java and Go**; AES-128-ECB with a hard-coded key — while AES-256-GCM, SHA-384 and PBKDF2 correctly stay green (no false positives).
   - Cloud: RSA-4096 code-signing key still CRITICAL; PendingDeletion key de-weighted; expired SHA-1 cert still serving an NLB listener; two plaintext HTTP listeners.
4. **Standards (30s):** CBOM page — CycloneDX 1.6 strict-validated ✅, every asset mapped to FIPS 203/204/205 replacement, NIST quantum security levels; download.
5. **Credibility (20s):** `make eval` table — precision/recall on the starter kit.
6. **Close (20s):** Roadmap page: Phase 1 hybrid KEX now, Phase 2 PKI to ML-DSA, Phase 3 AES-256 — aligned with NIST's 2030/2035 deprecation timeline. "QuantumTrace turns quantum risk into a prioritised migration backlog."

**Deck (5–6 slides):** Problem (HNDL) · Solution & architecture diagram · Classification model (tiers + HNDL + scoring formula) · Demo screenshots · Accuracy & standards (eval table, CBOM) · Future (CI gate `--fail-on critical`, continuous monitoring, SSH/IPsec, agent-based discovery).

**Backup:** record the demo video at H20; have `out/` pre-generated in case the live scan fails.

---

## 14. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Starter-kit formats differ from assumptions | Adapters break | Appendix D pre-analyses the kit; M2/M3 verify with tshark/by reading in H0–H1; adapters written against real samples; `generic_json.py` fallback; UNKNOWN instead of crash |
| tshark not installed / old Wireshark unaware of ML-KEM | No network data / wrong names | Docker image with tshark; always use numeric codepoints + own registry; Scapy fallback (P1) |
| TLS on non-standard ports | Handshakes missed | `-d tcp.port==N,tls` for all ports seen with TLS record headers; heuristic port scan of the capture |
| TLS 1.3 certificates encrypted | Missing auth info | Report as UNKNOWN honestly; keylog support (P2); explain in demo as a known limitation |
| False positives in code (comments, strings, docs) | Accuracy score drops | Comment skipping, test-path down-weighting, import vs call dedupe, golden eval loop after H12 |
| Double counting the same algorithm | Inflated score | `aggregate.py` dedupe by (canonical, usage); occurrence factor is log-bounded |
| Contract changes mid-build | Integration hell | Freeze at H1; all changes require all-member AGREED replies in communication/ |
| Agents hallucinate codepoints/OIDs | Wrong classifications | Generate from IANA CSV; *(verify)* markers; unit tests on key values |
| Live sandbox endpoints unreachable at demo time | Demo hole | Pre-captured pcap of the probe; probe is P2, never on the critical path |
| Key sizes behind constants (6 of the 24 code files) | Missed/wrong key size → wrong tier | File-scope constant resolution is P0 (task 3.2); look-ahead only a fallback |
| False positives on SAFE decoys (AES-256-GCM, SHA-384, PBKDF2) | Accuracy score drops | Decoy tests (task 3.7), golden eval |
| STARTTLS / Postgres-SSLRequest / non-443 TLS missed | ~35% of TLS sessions lost | Explicit decode-as + pure-Python fallback; test count = 97 |
| tshark unavailable on a teammate's machine | No network results | `purepy.py` fallback; Docker image has tshark |
| ELB policy table typed wrong | Wrong LB verdicts | Mark every row *(verify)*; unknown policy → UNKNOWN 0.5 |
| M4 overloaded (cloud + CBOM + API + React + deck) | Demo gaps | Load shifted to M1/M3 (§8); H6 re-balance rule |
| Running out of time | Unfinished demo | Strict P0/P1/P2; H12 feature freeze; H21 code freeze |

---

## Appendix B — Starter prompts

Paste at the beginning of each coding-agent session (adjust the task number).

**M1**
> I am M1 (Core & Risk Engine) on QuantumTrace. Read AGENTS.md, agents/STATUS.md, agents/IMPLEMENTATION.md, the previous task handoff, and agents/tasks/1.1.md. Read the task-cycle skill and relevant docs/PLAN.md sections. Start only task 1.1: refresh its written plan, reuse the persistent m1 branch synchronized with current origin/main, implement the project foundation, and validate it. Use my configured Git profile without Codex co-author trailers; publish the tested branch and integrate only at a designated milestone, save the 1.2 handoff, and end the session. Establish contracts in a separate fresh 1.2 session.

**M2**
> I am M2 (Network Layer) on QuantumTrace. Read docs/PLAN.md sections 6, 7.1, 7.3, 7.4, Appendix D.2/D.3 and my work package §8-M2. I own scanners/network/**, kb/tls_registry.yaml, kb/iana/, scripts/gen_pcaps.sh. First run `tshark -G fields | grep "tls.handshake"` and `tshark -r network-capture/network.pcap -Y tls.handshake -T json | head -200`, and confirm the counts in Appendix D.2 (97 TLS sessions: 54 TLS1.2 static-RSA, 36 TLS1.3 x25519, 7 X25519MLKEM768; 24 SSH sessions). Then implement 2.2 (pure-Python parser), 2.4 (tshark runner) and 2.5 (session assembly) producing Findings per §6. Use numeric codepoints and filter GREASE.

**M3**
> I am M3 (Code inspection) on QuantumTrace. Read docs/PLAN.md sections 6, 7.1–7.3, Appendix D.4 and my work package §8-M3. I own scanners/code/**, scanners/config/**, output/markdown.py, output/sarif.py. First read the 24 files in sample-repos/ and check Appendix D.4 line by line — report any correction. Then implement 3.2 (YAML regex rule engine **with file-scope constant resolution**) and the Python + Java rule files with fixtures and tests. Every SAFE decoy in D.4 must have a test asserting it is NOT flagged as MEDIUM/CRITICAL.

**M4**
> I am M4 (Cloud, CBOM, API, React dashboard, packaging, demo) on QuantumTrace. Read docs/PLAN.md sections 6, 7.5, 7.6, 13, Appendix D.5 and my work package §8-M4. I own scanners/cloud/**, kb/cloud_registry.yaml, output/cyclonedx.py, api/**, frontend/**, Dockerfile, README.md, scripts/demo.sh, tests/fixtures/scan_result_sample.json. First create scan_result_sample.json (~30 assets across pcap/ssh/code/kms/loadbalancer/acm and all tiers, 5 TLS sessions) that validates against ScanResult. Then scaffold FastAPI (api/main.py serving it at /api/result) and a Vite + React + TypeScript Overview page reading it; generate TS types from /openapi.json. Then the KMS/LB/ACM adapters against the real files in cloud-posture/.

---

## Appendix C — Reference links

Check items marked *(verify)* against these primary sources.

- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/203/final · /204/final · /205/final
- NIST IR 8547 — Transition to Post-Quantum Cryptography Standards: https://csrc.nist.gov/pubs/ir/8547/ipd
- NIST SP 800-208 (LMS/XMSS): https://csrc.nist.gov/pubs/sp/800/208/final
- IANA TLS parameters (cipher suites, supported groups, signature schemes) + CSV downloads: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
- IETF hybrid ECDHE-MLKEM key agreement for TLS 1.3: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
- IETF ML-DSA in TLS 1.3: https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/
- CycloneDX 1.6 specification & CBOM guide: https://cyclonedx.org/docs/1.6/json/ · https://cyclonedx.org/capabilities/cbom/
- cyclonedx-python-lib (validation): https://github.com/CycloneDX/cyclonedx-python-lib
- IBM CBOMkit / sonar-cryptography (prior art for code CBOM rules): https://github.com/IBM/cbomkit
- Wireshark TLS display filter reference: https://www.wireshark.org/docs/dfref/t/tls.html
- OpenSSL 3.5 PQC (ML-KEM/ML-DSA/SLH-DSA, hybrid groups): https://openssl-library.org/news/openssl-3.5-notes/
- Go `crypto/mlkem` and `tls.X25519MLKEM768`: https://pkg.go.dev/crypto/mlkem · https://pkg.go.dev/crypto/tls
- AWS KMS key specs: https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html
- NSA CNSA 2.0 algorithms & timeline: https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF
- AWS ELB security policies: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html
- AWS KMS DescribeKey / ACM DescribeCertificate response shapes: https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html · https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html
- OpenSSH post-quantum key exchange: https://www.openssh.com/pq.html
- FastAPI: https://fastapi.tiangolo.com/ · openapi-typescript: https://openapi-ts.dev/

---

## Appendix D — Starter-kit analysis & golden ground truth

> Hand-verified by reading every provided file; the pcap was parsed with a throw-away pure-Python reader (**tshark was not available**, so M2 confirms the numbers with tshark in H0–H1 and records differences in communication/ agreements). This appendix is the seed for `tests/golden/expected.yaml`. The task PDF says the kit covers "legacy TLS 1.2, modern TLS 1.3 and hybrid PQC" — it does, but only as three uniform profiles (below); anything richer (ECDHE, TLS 1.0, certificates, offered-but-refused ML-KEM) must come from our own fixtures.

### D.0 What is in the kit

| Path | Content | Notes |
|---|---|---|
| `network-capture/network.pcap` | classic libpcap, Ethernet, 2000 packets (1723 TCP, 277 UDP/DNS) | ~135 sessions: 97 TLS + 24 SSH + 14 HTTP |
| `sample-repos/{python,java,go}` | 8 + 8 + 8 files, standalone | the same 8 scenarios in 3 languages; `requirements.txt` has only `cryptography==46.0.5` |
| `cloud-posture/kms_key_inventory.json` | 10 keys, account `123456789012`, `eu-west-1` | AWS `ListKeys`/`DescribeKey` shape |
| `cloud-posture/load_balancer_listeners.json` | 5 LBs, 7 listeners | 5 TLS/HTTPS, 2 HTTP:80 |
| `cloud-posture/acm_certificates.json` | 5 certificates | joins listeners via ARN; **not in the original plan** |
| *(not provided)* | nginx/Apache config, binaries, PEM files, live sandbox endpoints | webserver/keyfile scanning and probing stay P2 |

### D.1 How the pcap was read (prototype logic for `purepy.py`)

libpcap header (little-endian, linktype 1) → per packet: Ethernet (handle 0x8100 VLAN) → IPv4 → TCP payload. A TLS record is `0x16 0x03 xx len(2)`; handshake type at byte 5 (`1` ClientHello, `2` ServerHello). ClientHello: skip version(2)+random(32)+session_id, read cipher suites(2-byte list), compression, extensions (`0` SNI, `10` groups, `13` sig algs, `43` supported_versions, `51` key_share). ServerHello: cipher suite, `43` selected version, `51` selected group. **Drop GREASE.** SSH: banner line `SSH-2.0-…`, then packet `[len4][padlen1][msg=20][cookie16]` followed by 10 name-lists.

### D.2 Network — TLS (97 sessions, all TCP, no GREASE present, all ClientHello `legacy_version` = 0x0303)

| # | Profile | Version | Negotiated suite | Negotiated group | Offered by client | Ports | Expected verdict |
|---|---|---|---|---|---|---|---|
| 54 | **Legacy static RSA** | TLS 1.2 (no `supported_versions`) | `0x002F TLS_RSA_WITH_AES_128_CBC_SHA` | — (RSA key transport) | suites `0x0035`, `0x002F` only; sig scheme `0x0401 rsa_pkcs1_sha256` | 443 ×33, 587 ×11 (SMTP **STARTTLS**), 636 ×10 (LDAPS) | CRITICAL; `forward_secrecy=false`, **HNDL exposed**; AES-128-CBC MEDIUM; MAC is HMAC-SHA1 (MEDIUM, *not* classically broken in HMAC use) |
| 36 | **Modern classical** | TLS 1.3 (`supported_versions` 0x0304) | `0x1301 TLS_AES_128_GCM_SHA256` | `0x001D x25519` | suites 1301/1302/1303; groups x25519, secp256r1; sig `0x0403`, `0x0804` | 443 ×18, 993 ×10 (IMAPS), 5432 ×8 (Postgres **SSLRequest**) | KEX CRITICAL (Shor, HNDL exposed — "modern ≠ quantum-safe"); cipher MEDIUM; cert unknown (encrypted) |
| 7 | **Hybrid PQC** | TLS 1.3 | `0x1302 TLS_AES_256_GCM_SHA384` | `0x11EC X25519MLKEM768` | groups `0x11EC`, x25519; key_share `0x11EC`, x25519 | 443 (`vaultNN.lab`) | KEX SAFE hybrid; cipher SAFE; **session UNKNOWN** (authentication unobservable because cert is encrypted in TLS 1.3; do not guess) |

SNI patterns: `webNN.lab`, `appNN.lab`, `mailNN.lab`, `dbNN.lab`, `dcNN.lab`, `vaultNN.lab`. Only handshake types 1 and 2 were seen as first records — verify with tshark whether Certificate messages exist (task 2.9). No TLS ≤ 1.1, no ECDHE TLS 1.2, no Kyber-draft codepoints, no case where ML-KEM is offered and refused.

### D.3 Network — SSH (24 sessions, port 22) and plaintext

| # | Peers (banners) | KEX offered | Host key | Cipher | Expected |
|---|---|---|---|---|---|
| 14 | server `OpenSSH_6.6.1p1 Ubuntu`, client `PuTTY_Release_0.76` | `diffie-hellman-group14-sha1`, `diffie-hellman-group1-sha1` | `ssh-rsa` (SHA-1) | `aes128-cbc`, `3des-cbc` | CRITICAL + classically broken (group1 = 1024-bit DH, SHA-1, 3DES); HNDL exposed |
| 10 | server `OpenSSH_9.6p1 Ubuntu`, client `OpenSSH_9.6` | `curve25519-sha256`, `diffie-hellman-group16-sha512` | `rsa-sha2-512`, `ssh-ed25519` | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com` | KEX CRITICAL (Shor), ciphers SAFE; **no PQ kex (`mlkem768x25519-sha256`) offered** |

Plaintext: 14 HTTP sessions on port 80 (`GET /status`, `Apache/2.4.58`, hosts `intranetNN.lab`) → `plaintext` findings, not scored as quantum risk. DNS (277 UDP packets) ignored.

### D.4 Code (24 files, 8 scenarios × 3 languages) — expected findings

Lines are 1-based. **Bold = SAFE decoy (must not be flagged as MEDIUM/CRITICAL).** Key sizes that require **constant resolution** are marked †.

| Scenario | Python | Java | Go | Expected asset(s) |
|---|---|---|---|---|
| MD5 password hash | `legacy_accounts.py:5` | `CustomerDirectory.java:8` | `member-directory/main.go:10` | MD5 (hash) MEDIUM, classically broken |
| SHA-1 checksum | `update_feed.py:5` | `PatchFeed.java:8` | `release-feed/main.go:10` | SHA-1 (hash) MEDIUM, classically broken |
| RSA-1024 + SHA-1 signing | `license_token.py:6` (key_size=1024), `:11`, `:16` (SHA1) | `ReceiptSigner.java:12-13` (`initialize(1024)`), `:18`, `:25` (`SHA1withRSA`) | `invoice-service/main.go:13` (1024), `:17`,`:18`,`:22`,`:23` (SHA1) | RSA-1024 (signature) CRITICAL, classically broken (<2048) **+** SHA-1 MEDIUM broken |
| Ed25519 signing | `webhook_signature.py:5` | `DeviceAttestation.java:12,17,24` | `agent-enrollment/main.go:4,11,20,21,25` | Ed25519 CRITICAL (Shor) — "modern ≠ quantum-safe" |
| **SHA-384 + HMAC-SHA256** | **`artifact_manifest.py:6` (sha384), `:14` (hmac sha256)** | **`ConfigSync.java:10` (SHA-384), `:20` (HmacSHA256)** | **`config-sync/main.go:13` (Sum384), `:22` (hmac+sha256)** | SHA-384 SAFE, HMAC-SHA256 SAFE |
| **PBKDF2-HMAC-SHA256 (600k it.)** | **`member_credentials.py:13,18`** | **`IdentityVault.java:22`** | **`auth-gateway/main.go:19-44`** (anchor L25) (hand-rolled, no pbkdf2 import; HMAC-SHA256 loop) | PBKDF2/KDF SAFE |
| AES-128-ECB + insecure RNG | `report_export.py:11` — key = `EXPORT_KEY` (16-byte literal, L5) †; `:17` `random.getrandbits` | `BatchExporter.java:14` — `TRANSFORMATION="AES/ECB/PKCS5Padding"` (L10) † ; key 16-byte literal L9; `:21` `new Random()` | `batch-pipeline/main.go:22` — `exportKey` 16 bytes (L10) †; manual `block.Encrypt` loop ⇒ ECB; `:7,:36` `math/rand` | AES-128-ECB MEDIUM (+ ECB warning, hard-coded key); insecure-RNG warning (UNKNOWN tier, excluded from quantum score) |
| **AES-256-GCM** | **`secure_transfer.py:16,21`** — `KEY_LEN=32` (L6) † | **`SessionCipher.java:18-19`** — `KEY_BITS=256` (L13) †; `:30,:39` `TRANSFORMATION="AES/GCM/NoPadding"` † | **`telemetry-relay/main.go:23,27,40,44`** — `keyLen=32` (L12) † ; `cipher.NewGCM` | AES-256-GCM SAFE |

Expected distinct assets after dedupe: **CRITICAL** RSA-1024, Ed25519; **MEDIUM** MD5, SHA-1, AES-128-ECB; **SAFE** SHA-384, HMAC-SHA256, PBKDF2, AES-256-GCM; **warnings** insecure RNG ×3 (Python/Java/Go), hard-coded AES key ×3. Anything else (e.g. `SecureRandom`, `os.urandom`, `crypto/rand`, `hmac.compare_digest`, `subtle.ConstantTimeCompare`) must produce **no** crypto-weakness finding. Library finding: `cryptography==46.0.5` only.

### D.5 Cloud — expected results

**KMS (10 keys)** — tier by `KeySpec`; `SYMMETRIC_DEFAULT` = AES-256-GCM *(verify)*.

| Alias | KeySpec / usage | State / origin | Expected |
|---|---|---|---|
| `licensing-jwt-signing` | RSA_2048 SIGN_VERIFY, `RSASSA_PKCS1_V1_5_SHA_256` | Enabled, prod | CRITICAL |
| `device-attestation` | ECC_NIST_P256 SIGN_VERIFY, `ECDSA_SHA_256` | Enabled | CRITICAL |
| `partner-feed-decrypt` | RSA_2048 ENCRYPT_DECRYPT, `RSAES_OAEP_SHA_256` | Enabled, **Origin EXTERNAL**, `ValidTo` 2027-11-05 | CRITICAL (imported key material, expiry noted) |
| `s3-object-encryption` | SYMMETRIC_DEFAULT | Enabled, rotation ON (365d) | SAFE |
| `ebs-volume-encryption` | SYMMETRIC_DEFAULT | Enabled, **rotation DISABLED** | SAFE (+ hygiene note) |
| `internal-ca-root` | ECC_NIST_P384 SIGN_VERIFY, `ECDSA_SHA_384` | Enabled, **MultiRegion** | CRITICAL — root of trust, high impact |
| `legacy-reports-export` | SYMMETRIC_DEFAULT | **PendingDeletion** (2026-10-12) | SAFE, exposure 0.3 |
| `hsm-backed-settlement` | RSA_3072, `RSASSA_PKCS1_V1_5_SHA_384` | Enabled, **Origin AWS_CLOUDHSM** | CRITICAL (HSM-backed ≠ PQ-safe) |
| `release-codesigning` | RSA_4096, `RSASSA_PSS_SHA_256` | Enabled | CRITICAL (larger RSA is not a fix) |
| `session-token-encryption` | SYMMETRIC_DEFAULT | Enabled, rotation ON | SAFE |

Totals: 6 CRITICAL, 4 SAFE; no PQC key specs; no MEDIUM.

**Load balancers (7 listeners)** — policy → protocol/cipher content must be hand-built from the AWS ELB security-policy table *(verify every row)*.

| LB (scheme) | Listener | SslPolicy | Expected |
|---|---|---|---|
| `public-web-alb` (internet-facing) | HTTPS:443 | `ELBSecurityPolicy-2016-08` | legacy: TLS 1.0+, static-RSA/CBC suites → CRITICAL, classically broken protocols, public exposure 1.5 |
| `public-web-alb` | HTTP:80 | — | **plaintext**, no encryption |
| `internal-admin-alb` (internal) | HTTPS:443 | `ELBSecurityPolicy-TLS-1-1-2017-01` | TLS 1.1 allowed → classically broken protocol |
| `api-gateway-alb` (internet-facing) | HTTPS:443 | `ELBSecurityPolicy-FS-1-2-Res-2020-10` | TLS 1.2, forward-secret ECDHE only → KEX CRITICAL (Shor), not static-RSA |
| `partner-api-alb` (internet-facing) | HTTPS:443 | `ELBSecurityPolicy-TLS13-1-2-2021-06` | TLS 1.3 capable but **no PQ hybrid group** → CRITICAL KEX; recommend an AWS PQ policy *(verify name)* |
| `legacy-tcp-nlb` (internal, network) | TLS:8443 | `ELBSecurityPolicy-TLS-1-2-2017-01` | TLS 1.2; contains non-FS RSA suites *(verify)* |
| `batch-internal-alb` (internal) | HTTP:80 | — | **plaintext** |

**ACM (5 certificates)**

| Domain | KeyAlgorithm / SignatureAlgorithm | Type, NotAfter | Expected |
|---|---|---|---|
| `www.example.com` | RSA_2048 / SHA256WITHRSA | AMAZON_ISSUED, 2026-11-01 | CRITICAL; expires in < 90 days of dump |
| `admin.internal.example.com` | EC_prime256v1 / ECDSA_WITH_SHA256 | AMAZON_ISSUED, 2026-12-20 | CRITICAL |
| `api.example.com` | RSA_2048 / SHA256WITHRSA | AMAZON_ISSUED, 2027-03-16 | CRITICAL |
| `partner-api.example.com` | EC_secp384r1 / ECDSA_WITH_SHA384 | AMAZON_ISSUED, 2027-05-05 | CRITICAL |
| `legacy-tcp.internal.example.com` | RSA_2048 / **SHA1WITHRSA** | **IMPORTED**, **NotAfter 2026-08-01 (already expired at dump time 2026-09-14) but Status ISSUED**, serves the NLB:8443 listener | CRITICAL + SHA-1 broken + **expired-in-use anomaly** |

### D.6 Traps the data sets for us (all must have a unit test)

1. X25519 and Ed25519 are CRITICAL even though they look modern (36 TLS sessions, 3 code files, SSH `ssh-ed25519`).
2. RSA-3072/4096 stay CRITICAL; only RSA < 2048 gets `classically_broken`.
3. Hybrid KEX session is **not** automatically SAFE overall — TLS 1.3 certificate is unobservable; report authentication and the overall session as UNKNOWN unless an observed component is CRITICAL or MEDIUM. Never guess.
4. HMAC-SHA1 inside `TLS_RSA_WITH_AES_128_CBC_SHA` is not "SHA-1 broken"; SHA-1 in a *signature* or plain checksum is.
5. Key sizes are behind file-level constants in the AES files (Python `secure_transfer`, Java `SessionCipher`/`BatchExporter`, Go `batch-pipeline`/`telemetry-relay`); Go ECB is a hand-written block loop; Go PBKDF2 is hand-rolled.
6. Three of eight code scenarios are SAFE decoys — false positives there cost accuracy points directly.
7. STARTTLS (587) and Postgres SSLRequest (5432) sessions only appear if non-443 ports/upgrades are handled.
8. A listener with no `SslPolicy` (HTTP:80) is plaintext, not "UNKNOWN crypto".

## M1 communication conclusions (2026-10-10)

See communication/M1M4agreement.md for the 14 M1 replies and M1toAll.md for
pending owner confirmations. Existing frozen models remain unchanged. All extra
keys are retained; engine-derived hygiene advice goes in asset rationale and
recommendations, while raw Findings remain unchanged. Listener policy evidence
links by listener resource_id and ACM joins use certificate_arns. KMS resources
use observed KeyArn, retaining AliasName in extra.alias. One KEY Finding feeds
scored algorithm assets; M4 constructs per-key CBOM material inventory from those
Findings without duplicate scoring. Configured policy choices are not negotiated
traffic. Cloud signature composites are decomposed centrally. Both HTTP listeners
remain plaintext hygiene observations, distinguished as HTTPS redirect versus
plaintext forwarding; the initial redirect request is still HTTP.

The validated scoring KB in task 1.3 uses tier_weights, exposure, broken_multiplier,
occurrence (cap/log_divisor), grade_bands and hndl_floor (score/condition), with
section 7.5 values. M4 may serve validated data at /api/scoring; no extra ScanResult
block or invented fallback values. Roadmap dates are product planning targets.
The CycloneDX json-validation extra is declared explicitly for strict validation
dependencies. Classified mode strings are lowercase schema values, while raw
Finding mode strings may remain uppercase.

M3 communication follow-up: communication/M1M3agreement.md has M1 replies to
all eight items. Key-size inheritance must remain unambiguous and retain bounded
confidence/provenance; unknown evidence is never merged into a known size based
solely on sharing a file. Hard-coded-key starter warnings require observed AES
sinks, with literals redacted. Known hand-rolled PBKDF2 kit evidence uses
PBKDF2-HMAC-SHA256 and hand_rolled metadata; SAFE is quantum policy, not a general
implementation audit. Raw ECB/GCM modes are retained, with bare Java AES defaults
conditioned on verified provider context. SunJCE/SunPKCS11 defaults are provider
specific ([Oracle provider documentation](https://docs.oracle.com/en/java/javase/25/security/oracle-providers.html)).
Go independent-block encryption must be distinguished from chained encryption.
Unknown AES size remains None and classifies MEDIUM. Golden seeding incorporates
the verified M3 occurrence corrections, with PBKDF2 lines 19–44 anchored at 25
and Ed25519 verification sites at 21/25. M3's local completion claim needs a
published tested implementation reference before it is treated as available.
