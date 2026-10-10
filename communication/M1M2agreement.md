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

---

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
