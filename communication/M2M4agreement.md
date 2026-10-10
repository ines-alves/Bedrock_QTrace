# M2M4 agreement

Between M2 (PCAP, TLS, SSH) and M4 (cloud adapters, CBOM, API, dashboard). Rules: `README.md`.

### M2M4-01 | By H2
Ask: M2 sends real JSON of one `TLSSession` for each of: legacy static-RSA (port 587), TLS 1.3 x25519 (port 5432), hybrid `X25519MLKEM768` (a `vault*.lab` host), SSH legacy, SSH modern. M2 also sends the `Finding`s of one session (offered and negotiated).
Why: M4 builds the Network page on a hand-written sample until H6. A sample that differs from real output breaks at integration.
Preference: as stated.
Fallback: M4 builds from PLAN.md Appendix D.2 and D.3 and fixes the page at H6.

### M2M4-02 | By H2
Ask: M2 fixes these values.
- `service`: `https`, `ldaps`, `imaps`, `smtp-starttls`, `postgres`, `ssh`, `other`.
- `pq_status`: `pq_hybrid` if the negotiated group is a hybrid. `pq_pure` if pure ML-KEM. `classical` for everything else with a negotiated key exchange, including static RSA. `unknown` if nothing was negotiated.
- `verdict_tier`: worst tier of the negotiated components.
- `cert_key`: `None` for TLS 1.3. For SSH, the negotiated host key algorithm as text.
- Offered lists: GREASE and `0x00FF`, `0x5600` removed, in client order.
- `negotiated_group`: `None` for static-RSA TLS 1.2.
- New optional fields on `TLSSession`: `kex_tier: Tier | None`, `auth_tier: Tier | None`, `host_key: str | None`, `cipher: str | None`, `mac: str | None`.
Why: the 7 hybrid sessions have a SAFE key exchange and an unknown authentication. `verdict_tier` alone cannot show both.
Preference: as stated.
Fallback: M4 shows `pq_status` and `verdict_tier` as two columns only, with no key exchange and authentication split.

### M2M4-03 | By H4
Ask: plaintext HTTP flows are `KindHint.PLAINTEXT` findings, not `TLSSession`s.
Why: `TLSSession.transport` allows only `tls` and `ssh`.
Preference: as stated. M4 shows plaintext flows as a count and list from findings.
Fallback: M2 adds `plaintext` to `transport` before H1.

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
Ask: M2 commits the fixture pcaps to `tests/fixtures/pcap/` and states for each the SNI and the expected result. Required: a client offers `X25519MLKEM768` and the server picks `x25519`. Output is deterministic.
Why: the kit has no such case and the demo needs it.
Preference: as stated.
Fallback: M4 cuts that demo step and the slide.

---

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
