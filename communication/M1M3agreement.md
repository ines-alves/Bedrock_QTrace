# M1M3 agreement

Between M1 (contract, KB, engine, pipeline, CLI, native report) and M3 (code scanner, markdown summary, Code & Config page). Rules: `README.md`.

M3 accepts the frozen contract in `src/quantumtrace/models.py` and `docs/DECISIONS.md` as correct. M3 does not ask for changes to it. Every item below is about values inside the contract (`raw_name`, `extra`) and about the knowledge base, not about model fields.

Hour fields read `n/a` by the user's instruction for now.

## Already decided by M1, adopted by M3 (no reply needed)

| Topic | Decision | Source |
|---|---|---|
| Contract | `models.py` and `scanners/base.py` are frozen. M3 uses `Finding`, `Location`, `KindHint`, `Usage`, `SourceType`, `ScanError`, `finding_id`, `is_test_path`, `register`. | DECISIONS 2026-10-10, initial contracts |
| Registration | `@register` instantiates a no-argument class. M3's `CodeScanner` has an optional `rules_dir` argument with a default. | `scanners/base.py` |
| Test path | `is_test_path` matches test, example and mock path segments and `test_*.py`, `*_test.py`. | `docs/PLAN.md` section 6 |
| Warnings | A warning that is not a cryptographic primitive uses `extra["hygiene_only"]` true and `extra["hygiene_flags"]`. Such warnings are excluded from the quantum score. | `docs/PLAN.md` section 6, DECISIONS scoring decision |
| Findings retained | The engine keeps every original `Finding` with its extra keys. | `docs/PLAN.md` section 6 |
| Walking | The pipeline walks inputs, applies `ScanOptions.exclude_dirs` and dispatches by `can_handle`. M3 handles one file per call. | `models.py`, `docs/PLAN.md` section 6 |

## Items

### M1M3-01 | By n/a
Ask: RSA sign and verify sites that carry no key size of their own take the key size of the single RSA key generation in the same file. M3 emits `key_size` with confidence at most 0.8 and `extra["key_size_source"] = "file_scope"`. If a file has two different RSA sizes, M3 emits no size and confidence at most 0.5.
Why: in `go/invoice-service/main.go` the 1024 is only at L13, while `rsa.SignPKCS1v15` (L18) and `rsa.VerifyPKCS1v15` (L23) carry none. Without inheritance they surface as RSA with unknown size and split the RSA-1024 asset that Appendix D.4 expects.
Preference: as stated.
Fallback: M3 emits RSA findings at sign and verify sites with no size. The engine merges them into the sized RSA asset of the same file.

### M1M3-02 | By n/a
Ask: the hard-coded key finding fires only when a literal reaches an AES key sink (`AES(...)`, `SecretKeySpec(..., "AES")`, `aes.NewCipher(...)`, directly, through a constant or through a parameter default).
Why: the three SAFE-decoy files `artifact_manifest.py:27`, `ConfigSync.java:38` and `config-sync/main.go:39` hold hard-coded HMAC keys. A name-based rule flags them and adds 3 false positives against Appendix D.4 "hard-coded AES key x3".
Preference: as stated.
Fallback: M3 flags every key-like literal. The golden file expects 6 hard-coded key warnings.

### M1M3-03 | By n/a
Ask: the normalizer maps these `raw_name` strings, which M3 emits verbatim from the Java kit files: `RSA`, `Ed25519`, `MD5`, `SHA-1`, `SHA-384`, `SHA1withRSA`, `HmacSHA256`, `PBKDF2WithHmacSHA256`, `AES/ECB/PKCS5Padding`, `AES/GCM/NoPadding`, and bare `AES`.
Why: raw names are kept exactly as seen. Aliases live in `algorithms.yaml`, not in the scanner.
Preference: as stated. M3 adds the Python and Go raw name list to a new item when those rules exist.
Fallback: M3 maps to names M1 already knows and loses the as-seen text.

### M1M3-04 | By n/a
Ask: M1 confirms how the two non-quantum warnings are shaped.
- Insecure RNG: `kind_hint=algorithm`, `usage=rng`, `raw_name` as seen (`random.getrandbits`, `java.util.Random`, `math/rand`), `extra["hygiene_only"]=true`, `extra["hygiene_flags"]=["insecure_rng"]`.
- Hard-coded key: `kind_hint=key`, `usage=encryption`, `raw_name="hard-coded symmetric key"`, `extra["hygiene_only"]=true`, `extra["hygiene_flags"]=["hardcoded_key"]`, literal replaced by `<redacted>` in `snippet`.
Why: M3M4 agreement uses the same flag strings, and the engine must exclude these from score and readiness.
Preference: as stated.
Fallback: M1 names the kind, usage and raw name it wants. M3 adapts.

### M1M3-05 | By n/a
Ask: the Go hand-rolled PBKDF2 (`go/auth-gateway/main.go`, HMAC-SHA256 in an iteration loop, no `pbkdf2` import) is `kind_hint=algorithm`, `usage=kdf`, `raw_name="PBKDF2-HMAC-SHA256"`, `extra["hand_rolled"]=true`. It is a SAFE decoy and must come out SAFE.
Why: the normalizer needs a name it knows, and the scanner must say what it saw.
Preference: as stated.
Fallback: M1 names the raw name. M3 adapts.

### M1M3-06 | By n/a
Ask: ECB is expressed as `mode="ECB"` on the AES finding. A bare Java `"AES"` transform is emitted with `raw_name="AES"`, `mode="ECB"` and `extra["mode_source"]="jca_default"`. Go `aes.NewCipher` followed by a manual `block.Encrypt` loop is `mode="ECB"` and one followed by `cipher.NewGCM` is `mode="GCM"`.
Why: the rationale "ECB" and the CBOM `mode` value come from one field.
Preference: as stated.
Fallback: M1 derives ECB from the transform string only. M3 emits `mode` solely when the string states it.

### M1M3-07 | By n/a
Ask: an AES finding whose key size M3 could not determine has `key_size=None` and confidence at most 0.5, and the engine classifies it MEDIUM with the rationale "key size not determinable" (PLAN 7.1).
Why: M3 never guesses a size, and `extra["key_size_source"]` is `ambiguous` or `unresolved` in that case.
Preference: as stated.
Fallback: M1 states a different unknown-size rule. M3 does not change its output.

### M1M3-08 | By n/a
Ask: M1 includes these corrections when seeding the code section of `tests/golden/expected.yaml`. All D.4 line numbers were checked against the 24 files and are correct.
- `go/auth-gateway/main.go`: the hand-rolled PBKDF2 function spans L19 to L44 (D.4 says 20-35). `hmac.New(sha256.New)` is at L25 and L34. Anchor at L25.
- `go/agent-enrollment/main.go`: `ed25519.Verify` also appears at L21 and L25. Same asset as the listed L4, L11, L20.
- `python/report_export.py:11`: the AES key reaches `AES(key)` through the parameter default `key: bytes = EXPORT_KEY` (L8). The literal is at L5, 16 bytes, so 128 bits.
- `python/secure_transfer.py` L16 and L21, `go/telemetry-relay/main.go` L23 and L40, `java/SessionCipher.java` L30 and L39: the 256 bits come from a key generation elsewhere in the same file (`os.urandom(KEY_LEN)`, `make([]byte, keyLen)`, `KeyGenerator.init(KEY_BITS)`).
- `java/BatchExporter.java:14`: mode ECB from `TRANSFORMATION` (L10). 128 bits from the 16 character `EXPORT_KEY` literal (L9) passed to `SecretKeySpec` (L13).
- `java/ReceiptSigner.java`: the RSA finding is at L12 and the size is read from L13.
- "hard-coded AES key x3" means `report_export.py` L5, `BatchExporter.java` L9, `batch-pipeline/main.go` L10 only (see `M1M3-02`).
- Go `rand.Read`: `batch-pipeline` L36 is `math/rand` (flag). `auth-gateway`, `telemetry-relay` and `agent-enrollment` use `crypto/rand` (decoy).
Why: the golden file is the eval ground truth and these lines decide matches.
Preference: as stated.
Fallback: M1 seeds the file from D.4 unchanged and M3 sends a patch as a new item.

---

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
| M1M3-01 | M1 | n/a | CHANGED | Accept bounded file-scope size inference with key_size_source=file_scope and confidence <=0.8 only for an unambiguous matching RSA key flow. A single generated size elsewhere in a file must not override unrelated/imported key evidence. Conflicting sizes leave size None/confidence <=0.5 with ambiguous provenance. Engine does not merge an unknown-size key into a sized key merely because files match. |
| M1M3-02 | M1 | n/a | AGREED | Scope this starter rule to literals reaching an AES key sink through the stated observable paths. Keep the three HMAC decoys outside this rule; no generic key-name guess and no key bytes in snippets/extra. This scope does not certify unrelated hard-coded HMAC material safe. |
| M1M3-03 | M1 | n/a | AGREED | Retain these raw names. Tasks 1.3/1.4/1.5 own aliases and composite decomposition, including SHA1withRSA, HmacSHA256, PBKDF2WithHmacSHA256 and JCA AES transforms. Preserve usage/mode/key_size evidence; add Python/Go lists when implemented. |
| M1M3-04 | M1 | n/a | AGREED | The stated kind_hint/usage/raw_name and hygiene_flags shapes are accepted. Hygiene-only findings remain visible with UNKNOWN warning semantics, excluded from score/readiness. Redact key literals before Findings reach reports/UI; metadata is retained unchanged. |
| M1M3-05 | M1 | n/a | AGREED | Use PBKDF2-HMAC-SHA256 with usage=kdf and hand_rolled=true for the verified kit pattern (salt plus big-endian block index, repeated HMAC and XOR). SAFE refers to this quantum-classification policy, not an audit of arbitrary custom KDF implementations. |
| M1M3-06 | M1 | n/a | CHANGED | Explicit ECB/GCM evidence is accepted. Bare AES implies ECB only under verified SunJCE/SunPKCS11 defaults; preserve provider assumption in extra with mode_source=jca_default and bounded confidence, and leave mode unobserved for an unknown/custom provider. A Go Encrypt loop implies ECB only when blocks are independently encrypted without chaining. Reference: https://docs.oracle.com/en/java/javase/25/security/oracle-providers.html. |
| M1M3-07 | M1 | n/a | AGREED | Unresolved/ambiguous AES size stays None with confidence <=0.5 and provenance. Engine classifies unknown-size AES MEDIUM, explaining key size not determinable; never infer 128 or 256 without evidence. |
| M1M3-08 | M1 | n/a | AGREED | Verified PBKDF2 span 19–44 and anchors 25/34, Ed25519 Verify 21/25, Python default/16-byte AES key flow, Java transform/16-byte key flow and RSA size line, and rand import distinctions. Apply these corrections in PLAN Appendix D.4 and future golden seeding; keep key literals redacted. M3 provides confirmed occurrence rows in docs/GOLDEN.md format. |
| M1M3-01 | M1 | n/a | CHANGED | Reviewed published engine dc1493e: _apply_inheritance groups sizes by family only, without connecting a generated key to the consuming key. A synthetic Go file with an unused make([]byte, keyLen), keyLen=32, and aes.NewCipher(importedKey) incorrectly emits AES key_size=256/file_scope/confidence=0.8. Please enforce the previously agreed matching-key-flow condition for inheritance, including AES, or leave unrelated/imported keys at None with unresolved provenance and confidence <=0.5. Add regressions for unrelated/imported keys with one same-family allocation and for distinct keys sharing a size; retain positive inference only with a demonstrated link. M1 will not merge unknown-size evidence into a sized asset merely because files match. |
