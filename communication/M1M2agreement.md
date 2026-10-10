# M1M2 agreement

Between M1 (contract, engine, pipeline, CLI, native report) and M2 (PCAP, TLS, SSH, live probe). Rules: `README.md`.

M2 accepts the frozen contract in `src/quantumtrace/models.py` and `docs/DECISIONS.md` as correct. M2 does not ask for changes to it.

## Already decided by M1, adopted by M2 (no reply needed)

| Topic | Decision | Source |
|---|---|---|
| Model changes | No new fields on `Finding` or `TLSSession`. Any change needs all four members. | DECISIONS 2026-10-10, initial contracts |
| Scanner output | A scanner yields only `Finding` or `ScanError`. Scanners supply no tier, threat, `pq_status` or verdict. | `scanners/base.py`, `docs/PLAN.md` section 6 |
| Session evidence | Raw session observations go in `Finding.extra["session"]`. `extra["authentication_observable"]` is a boolean, and absence means unknown. | `docs/PLAN.md` section 6 |
| Hybrid sessions | SAFE hybrid key exchange with unobservable authentication has overall verdict UNKNOWN, unless an observed component is CRITICAL or MEDIUM. | DECISIONS, hybrid decision |
| Scoring scope | Plaintext and hygiene-only warnings are excluded from the quantum score and readiness. | DECISIONS, scoring decision |
| Identity | `finding_id` hashes `detector\|raw_name\|file\|line\|flow\|frame\|resource_id`. | `scanners/base.py` |
| Scan options | `ScanOptions` has only `exclude_dirs` and `scanner_names`. | `models.py` |

## Items

### M1M2-01 | By H4
Ask: the engine builds every `TLSSession` from the findings that share a `session_id`, using `extra["session"]`, and sets `pq_status` and `verdict_tier` itself. M2 never instantiates `TLSSession`.
Why: `PLAN.md` task 2.5 says `tls_session.py` produces `TLSSession`, but the model requires `pq_status` and `verdict_tier`, scanners may not set them, and `Scanner.scan` cannot yield a session.
Preference: as stated. M2 documents the exact `extra["session"]` keys in `M2toAll.md` section 6, with the names of `TLSSession` fields.
Fallback: M2 provides `build_session_views(findings) -> list[dict]` in `tls_session.py`, returning `TLSSession` fields without `pq_status` and `verdict_tier`. M1 wraps them.

### M1M2-02 | By H4
Ask: network findings use the hex codepoint as `raw_name` (for example `"0x11EC"`, `"0x002F"`). `kind_hint` disambiguates the namespace, because `0x0201` is both group MLKEM768 and signature scheme `rsa_pkcs1_sha1`. M1 resolves the codepoint to an algorithm through `kb/tls_registry.yaml` (field `iana`) and then `algorithms.yaml`. The registry holds names and PQC facts, never a tier.
Why: Wireshark display names change between versions, and the engine must not depend on them.
Preference: as stated. M2 also puts `extra["codepoint"]` and `extra["iana_name"]` (null when unknown) on each finding.
Fallback: M2 puts the IANA name in `raw_name` and the codepoint in `extra["codepoint"]`.

### M1M2-03 | By H4
Ask: M1 routes `.pcap`, `.pcapng` and `.cap` files to the scanner named `pcap`. Evidence fields: `Location.file` is relative to the scan root; `Location.flow` is `client_ip:port->server_ip:port` with the client first, and IPv6 addresses in brackets (`[2001:db8::1]:50000->[2001:db8::2]:443`); `Location.frame` is the ClientHello frame for offered findings and the ServerHello frame for negotiated ones; `Location.sni` is set when present. SSH findings use `source_type` SSH, all others PCAP.
Why: the scanner protocol has one `source_type` per scanner, but the evidence source differs for SSH, and `finding_id` hashes `flow` and `frame`.
Preference: as stated.
Fallback: M1 states the routing and M2 follows it. M2 registers a second scanner `ssh` for SSH findings only if M1 requires one source type per scanner.

### M1M2-04 | By H6
Ask: M1 confirms `normalize.py` accepts these SSH names exactly as sent on the wire, because the kit uses them: kex `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, `curve25519-sha256`, `diffie-hellman-group16-sha512`; host key `ssh-rsa`, `rsa-sha2-512`, `ssh-ed25519`; cipher `aes128-cbc`, `3des-cbc`, `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`; MAC `hmac-sha1`, `hmac-sha2-256-etm@openssh.com`. Also `mlkem768x25519-sha256` and `sntrup761x25519-sha512` as PQC kex.
Why: `ssh-rsa` means RSA with SHA-1 and `diffie-hellman-group1-sha1` is 1024-bit DH, so a generic RSA or DH alias would lose the classical break.
Preference: as stated. `Finding.usage` is `KEY_EXCHANGE`, `SIGNATURE`, `ENCRYPTION` and `MAC` for the four lists, and `kind_hint` is `ALGORITHM`.
Fallback: M2 maps the wire names to names M1 already knows in a table inside `ssh.py`.

### M1M2-05 | By H12
Ask: the live probe is not a file scanner. M1 adds a CLI flag `--probe host:port` (repeatable) that calls `probe_endpoints(endpoints: list[str], timeout: float = 10.0) -> Iterator[Finding | ScanError]` from `quantumtrace.scanners.network.probe` after the file scanners and feeds the findings to the engine.
Why: `Scanner.can_handle` takes a `Path`, and a `host:port` is not one. `ScanOptions` has no probe field.
Preference: as stated. Without `--probe` nothing touches the network.
Fallback: M2 exposes `python -m quantumtrace.scanners.network.probe host:port` printing findings as JSON, and M1 skips the flag.

### M1M2-06 | By n/a
Ask: M2 confirms the incomplete-handshake, path-dependent identity, version namespace, detector and frame clarifications relayed by the user on 2026-10-10, with a tested implementation commit reference.
Why: M1 tasks 1.9 and 1.12 must consume partial captures without false conflicts or invocation-dependent golden matches.
Preference: ClientHello-only groups retain offered Findings plus ScanError without a PROTOCOL_VERSION/session finding or extra.session; ServerHello-only groups can carry extra.session with offered_* null. HelloRetryRequest alone establishes no negotiated selection and its session finding has negotiated=false. Location.file is scan-root-relative (direct file scans use the parent), so session_id can differ across invocations. Golden evaluation uses a fixed repository root and avoids literal session_id selectors. PROTOCOL_VERSION keeps the observed label (for example TLS 1.3), may carry extra.codepoint=0x0304 with extra.iana_name=None, and resolves only through the registry versions map. Detector values pcap.tls.version, pcap.tls.cipher_suite, pcap.tls.group and pcap.tls.signature_scheme distinguish namespaces; M1 dispatches by kind_hint, not one detector string. TLS 1.2 ECDHE group evidence anchors at ServerKeyExchange. M1 retains partial evidence/errors, treats missing or null observations as incompleteness rather than conflicting values, and never promotes offers or retries to negotiated evidence. No frozen model changes.
Fallback: Preserve incomplete groups and errors with explicit unknowns; owner behavior remains unverified until the tested commit and fixtures are reviewed.

---

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
| M1M2-01 | M1 | n/a | CHANGED | M2 assembles raw per-flow observations and yields Finding/ScanError only; M1 builds classified TLSSession views from session_id plus extra.session in task 1.9, using central engine classifications from tasks 1.5–1.8. M2 need not instantiate TLSSession or implement the fallback view builder. Preserve analyze(findings) -> (assets, summary) and run() signatures. Raw extra.session accepts the section 6 keys, no pq_status/verdict_tier. M1 derives source from the capture path or live target, converts nullable raw lists to typed output lists, and resolves TLS codes to verified registry iana names for presentation, preserving all raw evidence. Unknown names remain their hex spelling; missing selected components remain None. Conflicting session evidence becomes an explicit error/unknown rather than an arbitrary winner. Offered algorithms alone never establish negotiated authentication or a session verdict. |
| M1M2-02 | M1 | n/a | AGREED | Use hex raw_name with KindHint.CIPHER_SUITE/GROUP/SIGNATURE_SCHEME selecting separate TLS namespaces. Retain extra.codepoint and extra.iana_name (None when unknown); the KB resolves through M2-owned verified registry iana names, never Wireshark labels or a guessed default. Normalize hex spelling deterministically without changing original Findings. Unknown or verify-only entries remain explicitly uncertain; PQC metadata is evidence for central classification, not a scanner tier. Session output uses registry names where verified, while raw extra.session retains hex values in client order. Protocol-version, certificate, plaintext and SSH wire-name Findings do not need invented numeric codes; absent codepoint metadata may be None. |
| M1M2-03 | M1 | n/a | CHANGED | Task 1.9 dispatches .pcap/.pcapng/.cap to registered pcap when its can_handle accepts the file; no extra ssh registration is required. Adapter source_type may be PCAP while each SSH Finding Location uses SSH; aggregation uses actual Location.source_type. Accept relative POSIX file, client-first flow with bracketed IPv6, observed SNI, and hello frames for offered/selected TLS evidence. Certificate and other later observations use their actual evidence frame, not an unrelated ServerHello frame; raw protocol summary may anchor at ClientHello. SSH findings anchor at the observed relevant KEXINIT/exchange frame. Mark negotiated=True only when selection is observed or reliably established from both directional proposals under protocol rules; client offers alone remain offered. Unsupported capture formats must yield ScanError, not empty success. |
| M1M2-04 | M1 | n/a | AGREED | Keep every listed SSH wire name verbatim with the stated usages and ALGORITHM kind; central KB/normalization/decomposition in 1.3–1.5 handles these aliases without scanner-side canonicalization. Preserve ssh-rsa as the negotiated RSA/SHA-1 signature algorithm, distinct from the ssh-rsa public-key blob format reused by rsa-sha2-512; never infer SHA-1 from blob format alone. Group1 retains its fixed 1024-bit DH parameter, and MAC SHA-1 remains distinct from a collision-broken SHA-1 signature. Verified sources: https://www.rfc-editor.org/rfc/rfc4253 and https://www.rfc-editor.org/rfc/rfc8332 . Both hybrid names are documented by https://www.openssh.org/pq.html ; SAFE KEX does not make classical or unobservable authentication SAFE. Remaining per-name parameters/standards claims are verified during the owning KB task. |
| M1M2-05 | M1 | n/a | AGREED | Accept optional M2 probe_endpoints(endpoints: list[str], timeout: float = 10.0) -> Iterator[Finding | ScanError]. Task 1.10 provides repeatable --probe host:port (bracketed IPv6 form supported), passes endpoints via the existing run(probes=...) parameter, and task 1.9 calls the optional probe after file scanners, before analysis. Live Findings use SourceType.LIVE and Location.target with raw session evidence. No implicit probes or network calls when probes is None/empty. Missing adapter/dependency, invalid target, timeout or endpoint failure returns an explicit error; retain successful endpoints. Probe implementation stays optional P2 with M2, tests use local fixtures/mocks and do not access the network; no new ScanOptions field is needed. |
| M1M2-01 | M2 | n/a | AGREED | M2 does not instantiate `TLSSession` and writes no view builder. M2 emits one session finding per `session_id`. A second hello pair in the same stream (renegotiation) is not a second session: M2 keeps the first pair and emits a `ScanError` naming the stream, so M1 never sees two competing winners. |
| M1M2-03 | M2 | n/a | AGREED | Evidence frames: hello frames for offered and selected TLS values; the certificate finding uses the frame where the Certificate message ends; SSH findings use the frame where that side's KEXINIT ends. `negotiated` is true only for a selection seen in the ServerHello, or for SSH when the first client algorithm that is also in the server list is found under the RFC 4253 rule. Client offers alone are false. A capture the active parser cannot read (pcapng without tshark, non-Ethernet link type) yields a `ScanError`, never an empty success. `purepy.py` records no certificate frame yet; M2 adds it with `certs.py`. |
