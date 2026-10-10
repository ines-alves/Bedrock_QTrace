# M1M4 agreement

Between M1 (contract, engine, pipeline, CLI, native report) and M4 (cloud adapters, CBOM, API, dashboard). Rules: `README.md`.

M4 accepts the frozen contract in `src/quantumtrace/models.py` and `docs/DECISIONS.md` as correct. M4 does not ask for changes to it.

## Already decided by M1, adopted by M4 (no reply needed)

| Topic | Decision | Source |
|---|---|---|
| Model changes | No new fields on `CryptoAsset` or `TLSSession`. | DECISIONS 2026-10-10, initial contracts |
| Cloud facts | M4 emits facts in `Finding.extra` using the frozen keys: `origin`, `state`, `public_exposure`, `source_timestamp`, `hygiene_only`, `hygiene_flags`. M4 does not interpret them. | `docs/PLAN.md` section 6 |
| Findings retained | The engine keeps every original `Finding`, including extra keys. M4 reads cloud details from `ScanResult.findings` through each asset's `finding_ids`. | `docs/PLAN.md` section 6 |
| Expiry | Engine computes expiry from `source_timestamp` (the dump's `GeneratedAt`), otherwise scan start. M4 emits `source_timestamp` and does not compute expiry. | DECISIONS, expiry decision |
| Scan options | `ScanOptions` has only `exclude_dirs` and `scanner_names`. Default excludes include `out` and `agents`. | `models.py` |
| Roadmap | `ScanResult.roadmap` is a list of `RoadmapItem(phase 0 to 3, action, asset_ids, occurrence_count)`. | `models.py` |
| Hybrid key exchange | SAFE hybrid key exchange with unobservable authentication has overall verdict UNKNOWN. | DECISIONS, hybrid decision |
| Score scope | Plaintext, hygiene-only warnings, libraries and derived containers are excluded from the quantum score and readiness. | DECISIONS, scoring decision |
| Dependencies | `pyproject.toml` already has `fastapi`, `uvicorn[standard]`, `python-multipart`, `cyclonedx-python-lib`, `jsonschema`, Python 3.12. | `pyproject.toml` |
| Reports | Native reports stay valid `ScanResult` documents. No extra top-level blocks. | DECISIONS, contract decision |

## Items

### M1M4-01 | By H4
Ask: confirm the engine keeps these extra keys that M4 emits beyond the frozen list, and does not reject or rename them.
- KMS: `alias`, `key_usage`, `rotation_status`, `valid_to`, `deletion_date`, `multi_region`
- Listener: `lb_name`, `lb_type`, `listener_protocol`, `port`, `ssl_policy`, `listener_arn`, `certificate_arns`, `redirects_to_https`
- Certificate: `domain`, `cert_status`, `not_before`, `not_after`, `in_use_by`, `signature_algorithm`, `key_algorithm`
- `hygiene_flags` values M4 emits (direct observations only): `rotation_disabled`, `multi_region_key`, `redirect_only_listener`
Why: the Cloud page and the CBOM read these keys.
Preference: as stated.
Fallback: M1 names the keys. M4 renames.

### M1M4-02 | By H4
Ask: confirm the engine, not the adapters, derives these hygiene warnings from the raw `origin`, `state`, `not_after` and `source_timestamp`: expired certificate still in use, certificate expiring within 90 days, imported certificate, external key material, pending deletion, HSM-backed key.
Why: Decision 18 and section 6 say scanners supply facts and the engine interprets them. M4 passes `origin` and `state` as the source spells them (`AWS_CLOUDHSM`, `EXTERNAL`, `IMPORTED`, `PendingDeletion`, `ISSUED`).
Preference: as stated. The warnings appear as findings or assets with `hygiene_only` true and a `hygiene_flags` list that M4 reads.
Fallback: M4 emits the warnings as `hygiene_flags` computed from `source_timestamp`.

### M1M4-03 | By H4
Ask: each TLS listener becomes a `protocol` asset. Its `components` are the policy cipher suites, the policy groups and the certificate asset. `aggregate.py` links them by equal `Location.resource_id` (ARN).
Why: the expired SHA-1 certificate must raise the tier of the listener that serves it, and the CBOM needs `dependencies[]`.
Preference: as stated.
Fallback: M4 provides `link_cloud(findings)` in `scanners/cloud/`. `pipeline.py` calls it after all scanners and before `analyze()`.

### M1M4-04 | By H4
Ask: M1 adds aliases or patterns in `algorithms.yaml` for these raw names: `RSA_2048`, `RSA_3072`, `RSA_4096`, `ECC_NIST_P256`, `ECC_NIST_P384`, `EC_prime256v1`, `EC_secp384r1`, `SHA1WITHRSA`, `SHA256WITHRSA`, `ECDSA_WITH_SHA256`, `ECDSA_WITH_SHA384`.
Why: algorithm naming must live in one place.
Preference: as stated. M4 sets `key_size` and `curve` on the finding when the source gives them. M4 `cloud_registry.yaml` only holds `SYMMETRIC_DEFAULT` (AES-256-GCM, to verify) and the ELB policy table.
Fallback: M4 maps these names in `cloud_registry.yaml` to names M1 already knows.

### M1M4-05 | By H4
Ask: one `KindHint.KEY` finding per KMS key. `raw_name` is `KeySpec`. `usage` is `SIGNATURE` for `SIGN_VERIFY` and `ENCRYPTION` for `ENCRYPT_DECRYPT`. The engine derives the algorithm asset and the `related-crypto-material` asset from it.
Why: two findings per key double count the same key.
Preference: as stated.
Fallback: M4 emits one `KEY` and one `ALGORITHM` finding per key, as in `docs/PLAN.md` task 4.3.

### M1M4-06 | By H4
Ask: both HTTP:80 listeners emit a `PLAINTEXT` finding with `hygiene_only` true. The redirect listener (`public-web-alb`) also has `redirects_to_https` true and `hygiene_flags` `["redirect_only_listener"]`. The golden file marks it as redirect-only, not as a plaintext exposure.
Why: Appendix D.5 counts two plaintext listeners, but only `batch-internal-alb` forwards plain traffic. Both stay out of the score, so only the golden file and the UI wording are affected.
Preference: as stated.
Fallback: only `batch-internal-alb` emits `PLAINTEXT`. The golden file has one plaintext listener.

### M1M4-07 | By H4
Ask: the pipeline offers every `.json` file to every scanner. The first scanner whose `can_handle` returns true wins. `generic_json` is tried last. `Location.file` is relative to the scan root. KMS `Location.resource_id` is the `AliasName`.
Why: all three cloud files are `.json` and M4 detects them by content (`Keys`, `LoadBalancers`, `Certificates`). KMS keys have no ARN in the data.
Preference: as stated.
Fallback: M1 routes by file name (`kms_key_inventory.json`, `load_balancer_listeners.json`, `acm_certificates.json`).

### M1M4-08 | By H6
Ask: every `CryptoAsset` has `primitive` and `mode` values from the CycloneDX lists (or `None` for `mode`), and a unique, deterministic `asset_id` with no spaces. `primitive`: `signature, hash, pke, kem, key-agree, block-cipher, stream-cipher, mac, kdf, ae, drbg, xof, combiner, other, unknown`. `mode`: `cbc, ecb, ccm, gcm, cfb, ofb, ctr, other, unknown`.
Why: `primitive` and `mode` are plain strings in `models.py`, and CycloneDX strict validation rejects other values.
Preference: as stated.
Fallback: M4 maps unknown values to `other` in `cyclonedx.py` and logs them.

### M1M4-09 | By H6
Ask: M1 commits `kb/scoring.yaml` with stable keys (tier weights, exposure values, broken multiplier, occurrence formula, grade bands, HNDL floor). M4 serves it read-only at `/api/scoring` for the score explanation.
Why: the explanation must show what the engine really uses, and `ScanResult` has no field for it.
Preference: as stated.
Fallback: M4 hard-codes the text from `docs/PLAN.md` section 7.5.

### M1M4-10 | By H6
Ask: M1 confirms the roadmap phases mean: 0 this week (classically broken), 1 now (HNDL key exchange), 2 by 2027 (signatures and PKI), 3 by 2030 (symmetric and hash). M4 shows the phase title and deadline from this fixed table next to M1's `action`.
Why: `RoadmapItem` has a phase number and an action, but no title or deadline.
Preference: as stated.
Fallback: M1 gives the titles.

### M1M4-11 | By H6
Ask: M1 confirms these. `build_cbom(result) -> dict` and `validate_cbom(cbom) -> list[str]` belong to M4. The CLI writes to `out/` by default. `qtrace scan --format cbom` calls M4's functions. `qtrace ui` runs `uvicorn api.main:app`. `/api/result` reads `out/report.json`.
Why: CLI and API must meet without guessing.
Preference: as stated.
Fallback: M1 states the differences.

### M1M4-12 | By H6
Ask: M4 reports whether `cyclonedx-python-lib` strict validation needs an extra beyond the current `pyproject.toml`. If yes, M1 adds it.
Why: M4 has not verified it.
Preference: as stated.
Fallback: M4 sends M1 the exact line.

### M1M4-13 | By H2
Ask: M1 sends the schema of `tests/golden/expected.yaml`. M4 writes the cloud section (10 keys, 7 listeners, 5 certificates).
Why: the cloud entries must match the eval format.
Preference: as stated.
Fallback: M4 writes the entries in the format shown in `docs/PLAN.md` section 10.2.

### M1M4-14 | By H2
Ask: M4 pushes to branches named `m4/<topic>`. M1 merges to `main` after tests and lint pass. M4 does not push to `main`.
Why: M1's workflow decisions use per-task branches and a verified green `main`.
Preference: as stated.
Fallback: M1 states the process M4 must follow.

---

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
| M1M4-01 | M1 | unknown | AGREED | All listed extra keys and observed hygiene_flags are retained unchanged in original Findings. This is a future engine preservation requirement, already compatible with models.py. |
| M1M4-02 | M1 | unknown | CHANGED | The engine derives expiry and other hygiene interpretation from raw facts, using source_timestamp then scan start. Original Findings remain unchanged. Derived warnings appear in CryptoAsset.rationale/recommendations; CryptoAsset has no extra/hygiene_only field. M4 reads raw hygiene_flags from findings and derived advice from assets. HSM backing and multi-region are context, not automatically weaknesses. |
| M1M4-03 | M1 | unknown | CHANGED | Use listener Location.resource_id for policy/component association, then join extra.certificate_arns to ACM certificate Location.resource_id. Listener ARN and certificate ARN are different. Engine tasks 1.5/1.7/1.9 own the join and tier propagation; no cloud scanner classification or link_cloud callback. Configured policy choices are not observed negotiated traffic. |
| M1M4-04 | M1 | unknown | AGREED | Task 1.3 adds key-spec aliases/patterns; signature composites are decomposed in 1.5 before normalization. Preserve raw names, usage, key_size and curve; factual mappings require primary-source verification. Cloud registry stays with M4. |
| M1M4-05 | M1 | unknown | CHANGED | Emit one KEY Finding per KMS key with the stated usage. Engine derives scored algorithm assets linked to original finding_ids. M4 builds per-key related-material CBOM components from these retained Findings, referencing the classified algorithm; do not score material and algorithm twice. No duplicate ALGORITHM Finding is needed. |
| M1M4-06 | M1 | unknown | CHANGED | Keep two PLAINTEXT hygiene Findings; verified public-web-alb redirects to HTTPS and batch-internal-alb forwards HTTP. Retain redirects_to_https and redirect_only_listener. Golden/UI distinguish redirect-only from plaintext forwarding; the initial HTTP request is still cleartext. Both are excluded from quantum scoring. |
| M1M4-07 | M1 | unknown | CHANGED | Content-based can_handle wins in deterministic scanner-name order among specific handlers; generic_json runs last. Pipeline honors selected adapters and does not route by filename. Location.file is scan-root-relative. KMS data does contain KeyArn: use it as resource_id, retain AliasName in extra.alias, with KeyId then AliasName only as fallback if ARN absent. |
| M1M4-08 | M1 | unknown | AGREED | Engine output uses the listed CycloneDX 1.6 primitive/mode enums, lowercase mode or None, stable unique whitespace-free asset IDs. Raw Finding.mode may remain uppercase. Verified against https://cyclonedx.org/schema/bom-1.6.schema.json; no frozen model change needed. |
| M1M4-09 | M1 | unknown | CHANGED | Task 1.3 will publish scoring.yaml with tier_weights, exposure, broken_multiplier, occurrence(cap/log_divisor), grade_bands, and hndl_floor(score/condition). Exact values remain PLAN 7.5. M4 may expose validated loaded data read-only at /api/scoring, outside ScanResult; unavailable KB returns a clear unavailable response rather than invented values. |
| M1M4-10 | M1 | unknown | CHANGED | Confirmed as migration planning phases, not universal regulatory deadlines: 0 this week includes classical/hygiene fixes, 1 now HNDL KEX, 2 by 2027 signatures/PKI, 3 by 2030 symmetric/hash. M4 can use the fixed display table; published legal/standards deadlines require separate verification. |
| M1M4-11 | M1 | unknown | AGREED | build_cbom/validate_cbom belong to M4. CLI task 1.10 defaults to out/, --format cbom uses both functions, qtrace ui invokes uvicorn api.main:app, and /api/result consumes out/report.json. Missing optional owner implementations fail explicitly. |
| M1M4-12 | M1 | unknown | CHANGED | M1 verified installed cyclonedx-python-lib 11.12.0 metadata: json-validation extra declares jsonschema[format-nongpl] and referencing. Added cyclonedx-python-lib[json-validation]>=8 and refreshed uv.lock. Baseline strict valid/invalid BOM smoke checks pass; M4 still owns full CBOM fixture validation. |
| M1M4-13 | M1 | unknown | CHANGED | Use docs/GOLDEN.md and docs/golden.schema.json: top-level expectation list, kind asset/finding/session/count. M4 owns cloud rows (10 key resources, 7 listener resources, 5 certificate resources), preserving two HTTP listeners with distinct redirect flags. Evaluator implementation remains 1.12; no guessed policy classifications should become verified ground truth. |
| M1M4-14 | M1 | unknown | CHANGED | Push tested m4/<topic> branches. M1 integrates cumulative green work at significant milestones, not each task. Default M1 milestones: 1.8 core, 1.9/1.11/1.10 CLI/native reports, 1.12/integration evaluated starter gate. Cross-owner dependencies can use explicitly recorded tested branch commits; no direct or forced main pushes by M4. |
