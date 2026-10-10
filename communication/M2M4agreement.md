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
| M2M4-01 | M2 | n/a | CHANGED | Real parser output, not hand-written. Files: `tests/fixtures/pcap/samples/legacy_rsa_587.json`, `tls13_x25519_5432.json`, `hybrid_vault.json`, `ssh_legacy.json`, `ssh_modern.json`. Each is a JSON list of `Finding` dicts for one session, offered and negotiated. Deadline moves to H4 because `tls_session.py` and `ssh.py` are not written yet. The exact shape is fixed now in `M2toAll.md` section 6, so M4 can build the page against it. |
| M2M4-02 | M2 | n/a | CHANGED | Service and transport values accepted as written. Changes: (1) `version` also takes `TLS 1.0`, `TLS 1.1`, `SSL 3.0` (fixture 2.8c is TLS 1.0), never from `legacy_version`; SSH uses `SSH-2.0` from the banner. (2) `authentication_observable` is true only when a Certificate message was parsed. TLS 1.3 and a TLS 1.2 capture without a Certificate (the whole kit) give false. (3) TLS 1.2 ECDHE: `negotiated_group` comes from ServerKeyExchange when present, otherwise absent. (4) SSH: kex in the group fields, host key algorithm as text in `cert_key`, offered host key list in `offered_sig_schemes`, offered ciphers in `offered_cipher_suites`, negotiated cipher and MAC as separate findings with `negotiated` true. (5) TLS 1.3 signature schemes are offered only; the selected one is encrypted. |
| M2M4-03 | M2 | n/a | AGREED | Plaintext is a `PLAINTEXT` finding with `extra["hygiene_only"]` true, `source_type` PCAP, `protocol` `http`, `Location.flow` set, and `extra["http"]` with method, path, host and server. Never a `TLSSession`. A STARTTLS flow that never upgrades uses the same kind with `protocol` `smtp`. The kit has none of the second kind: all 11 STARTTLS flows upgrade. |
| M2M4-04 | M2 | n/a | CHANGED | OpenSSL names are not typed. The generator runs `openssl ciphers -V 'ALL:COMPLEMENTOFALL'` (and `openssl list -tls-groups` for groups) and stores the result as aliases. Structure of `kb/tls_registry.yaml`: top keys `meta`, `cipher_suites`, `groups`, `signature_schemes`, `versions`. Each key is a hex string like `"0xC02F"`. A suite entry has `iana` (string) and `openssl` (list of strings, may be empty). M4 reads the YAML with `yaml.safe_load` and needs no import. A helper `quantumtrace.scanners.network.registry.load_registry()` exists for convenience. The registry holds names and PQC facts only, no tier. Items that could not be verified carry `verify`. Deadline H4. |
| M2M4-05 | M2 | n/a | CHANGED | Counts: `purepy.py` already gives 97 TLS, 24 SSH and 14 HTTP, and `tests/test_network_purepy.py` cross-checks it with tshark per stream. Paths: `Location.file` is relative to the scan root; a single pcap passed directly uses its parent as root, so `network.pcap`. The image needs `tshark` only (set `DEBIAN_FRONTEND=noninteractive`, the Debian package asks a debconf question). `openssl` is needed only for `--probe`, not for scanning. M2 does not verify the image tag; M4 does. |
| M2M4-06 | M2 | n/a | CHANGED | By H12 as asked. Fixtures in `tests/fixtures/pcap/`: `tls12_ecdhe_ecdsa_p256.pcap` (SNI `ecdsa.lab`, certificate present, auth observable), `tls13_offer_hybrid_server_x25519.pcap` (SNI `refuse.lab`, offers 0x11EC, server picks 0x001D), `tls10_3des.pcap` (SNI `old.lab`), `tls13_hybrid_keylog.pcap` plus `.keylog` (SNI `hybrid.lab`). Expected values per file in `tests/fixtures/pcap/expected.yaml`. Pcaps are committed, not regenerated in tests, so output is deterministic. Change: the hybrid fixture is UNKNOWN only when scanned without the keylog. With the keylog the certificate becomes observable, and an ECDSA certificate makes it CRITICAL. The keylog path is P2 and may not ship. |
| M2M4-02 | M2 | n/a | CHANGED | Addition after M1 review (`M1M2` replies): the session finding also carries `extra["certificate_state"]` with `observed`, `encrypted` (TLS 1.3) or `absent` (TLS 1.2 or older with no Certificate in the capture). `authentication_observable` is unchanged. The Network page can show "certificate not in capture" separately from "encrypted". |
| M2M4-04 | M2 | n/a | CHANGED | Correction to the earlier row: group aliases come from `openssl list -all-tls-groups` (adds `P-256`, `P-384`, `P-521`), and `prime256v1` is added from `openssl ecparam`, marked `verify`. Plain `openssl list -tls-groups` has one name per group and is not enough. |
