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
| M2M3-01 | M3 | n/a | CHANGED | M3 owns `.pem`, `.crt`, `.cer`, `.der`, `.key` and the SSH key files `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` and `*.pub`. M3 `can_handle` is false for `.pcap`, `.pcapng` and `.cap` (the code scanner takes only `.py`, `.java`, `.go` today). Until `config/keyfiles.py` exists (P2, `M3D-12`) these files produce no findings. |
| M2M3-02 | M3 | n/a | AGREED | M3 `keyfiles.py` reuses `describe_certificate(der)` after M2D-07. M3 splits PEM chains into DER and never passes private key material to it. Request: M2 lists the allowed `key_type` values in `M2toAll.md` or the `certs.py` docstring. Fallback accepted: direct `cryptography.x509` if the module is late. |
| M2M3-03 | M3 | n/a | CHANGED | M3 keeps `raw_name` as seen and adds `extra["codepoint"]` and `extra["iana_name"]`, `None` when the registry does not resolve the name (same keys and null rule as `M1M2-02`). Cipher strings such as `HIGH:!aNULL` are emitted raw. Registry read through `load_registry()` or `yaml.safe_load`. Merging with network findings depends on `M1M3-09`. Request: M2 confirms the `openssl` lists cover group names such as `prime256v1`. |
| M2M3-01 | M2 | n/a | AGREED | M3 list accepted. M2 `can_handle` accepts only `.pcap`, `.pcapng` and `.cap`, and never opens key files. SSH in M2 means SSH traffic in captures, not key files. |
| M2M3-02 | M2 | n/a | AGREED | Allowed `key_type` values: `RSA`, `EC`, `Ed25519`, `Ed448`, `DSA`, `unknown` (a key type the library cannot decode, for example a post-quantum key). `key_size` is bits for `RSA` and `DSA`, otherwise `None`. `curve` is the library curve name for `EC` (`secp256r1`, `secp384r1`, `secp521r1`), otherwise `None`. `signature_algorithm` is the library name when known, otherwise the dotted OID, and `signature_algorithm_oid` is always the dotted OID. `describe_certificate` returns `None` on undecodable bytes and never raises. Values are also listed in `M2toAll.md` section 7. |
| M2M3-03 | M2 | n/a | CHANGED | No: the OpenSSL group lists do not cover `prime256v1`. Verified on OpenSSL 3.6.4: `openssl list -tls-groups` gives one name per group (`secp256r1`, `x25519`, `X25519MLKEM768`), and `-all-tls-groups` adds only `P-256`, `P-384`, `P-521`. M2 adds `prime256v1` to the `openssl` list of group `0x0017` in the generator, using the pairing from `openssl ecparam`, marked `verify`. Names that no list resolves stay `None`, as M3 states. M3 should not rely on the registry for other X9.62 names. |
