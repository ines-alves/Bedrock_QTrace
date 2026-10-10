# M2M3 agreement

Between M2 (PCAP, TLS, SSH, live probe) and M3 (code scanner, config and key files, markdown summary, Code & Config page). Rules: `README.md`.

M3 and M2 accept the frozen contract in `src/quantumtrace/models.py` and `docs/DECISIONS.md` as correct. Neither asks for changes to it.

## Already decided, adopted by both (no reply needed)

| Topic | Decision | Source |
|---|---|---|
| Model changes | No new fields on `Finding`. Any change needs all four members. | DECISIONS 2026-10-10, initial contracts |
| Scanners supply facts | Both report what they see. The engine assigns tier and verdict. | `docs/PLAN.md` section 6 |
| Key material | Neither prints or stores private key material. | `docs/PLAN.md` task 3.13 |

## Items

### M2M3-01 | By H4
Ask: file ownership by extension. M2 owns `.pcap`, `.pcapng` and `.cap`. M3 owns `.pem`, `.crt`, `.cer`, `.der`, `.key` and SSH key files. M2 `can_handle` returns false for anything else, and M3 returns false for capture files.
Why: the pipeline offers every file to every scanner, and a certificate seen by both would be counted twice.
Preference: as stated.
Fallback: M1 routes by extension and each side follows it.

### M2M3-02 | By H12
Ask: M3 `config/keyfiles.py` reuses M2 `describe_certificate(der: bytes) -> dict` from `quantumtrace/scanners/network/certs.py`. M3 decodes PEM to DER. The dict has `key_type`, `key_size`, `curve`, `signature_algorithm`, `not_before`, `not_after` (ISO 8601 with timezone) and `self_signed`. It never contains private key material.
Why: one X.509 parser, one set of names, and M2 tests it on a real fixture.
Preference: as stated. M2 delivers by H14 (task 2.9, P1).
Fallback: M3 calls `cryptography.x509` directly and maps the names itself.

### M2M3-03 | By H12
Ask: M3 `config/webserver.py` resolves literal OpenSSL names (`ECDHE-RSA-AES128-GCM-SHA256`, `X25519MLKEM768`, `prime256v1`) through `kb/tls_registry.yaml` and puts `extra["codepoint"]` on the finding. The YAML has `cipher_suites` and `groups` keyed by hex string, each with an `openssl` list. Cipher strings such as `HIGH:!aNULL` are not names and M3 emits them as raw text.
Why: the same suite then has the same codepoint in code, config and network, so the engine merges it into one asset.
Preference: as stated. M3 reads the YAML with `yaml.safe_load`, or `quantumtrace.scanners.network.registry.load_registry()`.
Fallback: M3 emits the raw OpenSSL name and the engine aliases it.

---

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
