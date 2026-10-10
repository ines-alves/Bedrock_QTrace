# M2M4 agreement

Between M2 (PCAP, TLS, SSH) and M4 (cloud adapters, CBOM, API, dashboard). Rules: `README.md`.

M4 accepts the frozen contract in `src/quantumtrace/models.py` and `docs/DECISIONS.md` as correct. M4 does not ask for changes to it.

## Already decided by M1, adopted by M4 (no reply needed)

| Topic | Decision | Source |
|---|---|---|
| Model changes | No new fields on `TLSSession` or `Finding`. Any change needs all four members. | DECISIONS 2026-10-10, initial contracts |
| Session data from M2 | M2 puts raw session observations in `Finding.extra["session"]` (version, offered and negotiated groups and cipher suites, offered signature schemes, certificate key and signature, transport, service, peer banners). | `docs/PLAN.md` section 6 |
| Verdicts | Scanners supply no `pq_status` and no verdict. M2 does not set them. | `docs/PLAN.md` section 6 |
| Authentication | M2 sets `extra["authentication_observable"]` to a boolean. Missing means unknown. M2 never guesses a certificate key. | `docs/PLAN.md` section 6 |
| Hybrid sessions | SAFE hybrid key exchange with unobservable authentication has overall verdict UNKNOWN. | DECISIONS, hybrid decision |
| Plaintext | Plaintext and hygiene-only warnings are excluded from the quantum score. | DECISIONS, scoring decision |
| Evidence | The engine keeps every original `Finding` with its extra keys. M4 reads session details from `ScanResult.findings` and `ScanResult.sessions`. | `docs/PLAN.md` section 6 |

## Items

### M2M4-01 | By H2
Ask: M2 sends real JSON of one `Finding` carrying `extra["session"]` for each of: legacy static-RSA (port 587), TLS 1.3 x25519 (port 5432), hybrid `X25519MLKEM768` (a `vault*.lab` host), SSH legacy, SSH modern. For one session M2 sends both the offered and the negotiated findings.
Why: M4 builds the Network page on a hand-written sample until H6. A sample that differs from real output breaks at integration.
Preference: as stated.
Fallback: M4 builds from `docs/PLAN.md` Appendix D.2 and D.3 and fixes the page at H6.

### M2M4-02 | By H2
Ask: M2 confirms these values in `extra["session"]` and on findings.
- `service`: `https`, `ldaps`, `imaps`, `smtp-starttls`, `postgres`, `ssh`, `other`.
- `version`: `TLS 1.2`, `TLS 1.3` (from `supported_versions`, never from `legacy_version`).
- Offered lists: GREASE and `0x00FF`, `0x5600` removed, in client order.
- Static-RSA TLS 1.2: no negotiated group.
- TLS 1.3: certificate key absent, `authentication_observable` false.
- SSH: kex in the group fields, as the `TLSSession` comment says. The negotiated host key algorithm goes in the certificate key field as text. Negotiated cipher and MAC are findings with `negotiated` true.
- `transport`: `tls` or `ssh`.
Why: the Network page reads these values and cannot recompute them.
Preference: as stated.
Fallback: M2 lists the differences. M4 adapts the page.

### M2M4-03 | By H4
Ask: plaintext HTTP flows are `KindHint.PLAINTEXT` findings with `hygiene_only` true, not sessions.
Why: `TLSSession.transport` allows only `tls` and `ssh`, and plaintext is excluded from the score.
Preference: as stated. M4 shows plaintext flows as a count and list from findings.
Fallback: M2 states how plaintext flows are represented.

### M2M4-04 | By H4
Ask: `tls_registry.yaml` includes OpenSSL-style names (for example `ECDHE-RSA-AES128-GCM-SHA256`) as aliases of each suite, with IANA name and hex code. M2 tells M4 the loader function or the YAML structure to read them.
Why: AWS publishes ELB policies with OpenSSL names. M4 needs hex codes for CBOM `cipherSuites[].identifiers`. Neither table is typed twice.
Preference: as stated.
Fallback: M4 types the ELB policy table with IANA names and marks each row verify.

### M2M4-05 | By H6
Ask: M2 confirms these. Docker installs `tshark` and `openssl` from Debian (`python:3.12-slim-trixie`). `purepy.py` produces the same counts as tshark (97 TLS, 24 SSH). All paths in `Location.file` and `flow` are relative to the scan root.
Why: pitch numbers must not depend on which parser ran. The container scans `/data`.
Preference: as stated. M4 verifies the image tag and the OpenSSL version.
Fallback: M2 states which differences exist.

### M2M4-06 | By H12
Ask: M2 commits the fixture pcaps to `tests/fixtures/pcap/` and states for each the SNI and the expected result. Required: a client offers `X25519MLKEM768` and the server picks `x25519`. Output is deterministic. A hybrid TLS 1.3 fixture is expected to have overall verdict UNKNOWN.
Why: the kit has no offered-but-refused case and the demo needs it.
Preference: as stated.
Fallback: M4 cuts that demo step and the slide.

---

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
