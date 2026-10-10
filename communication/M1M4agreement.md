# M1M4 agreement

Status: FINAL

Final on 2026-10-10. The Final decisions table below is the agreed outcome. The Items keep the original asks so the replies stay readable. Where an ask and its reply differ, the reply wins. A reply row also wins over the Final decisions table, which is M4's summary of the replies.

Between M1 (contract, engine, pipeline, CLI, native report) and M4 (cloud adapters, CBOM, API, dashboard). Rules: `README.md`.

M4 accepts the frozen contract in `src/quantumtrace/models.py` and `docs/PLAN.md` section 6 as correct. M4 does not ask for changes to it. (`docs/DECISIONS.md` is local-only, so the sources below cite shared files.)

## Already decided by M1, adopted by M4 (no reply needed)

| Topic | Decision | Source |
|---|---|---|
| Model changes | No new fields on `CryptoAsset` or `TLSSession`. | `models.py`, `docs/PLAN.md` section 6 |
| Cloud facts | M4 emits facts in `Finding.extra` using the frozen keys: `origin`, `state`, `public_exposure`, `source_timestamp`, `hygiene_only`, `hygiene_flags`. M4 does not interpret them. | `docs/PLAN.md` section 6 |
| Findings retained | The engine keeps every original `Finding`, including extra keys. M4 reads cloud details from `ScanResult.findings` through each asset's `finding_ids`. | `docs/PLAN.md` section 6 |
| Expiry | Engine computes expiry from `source_timestamp` (the dump's `GeneratedAt`), otherwise scan start. M4 emits `source_timestamp` and does not compute expiry. | `docs/PLAN.md` section 6 (`source_timestamp`) |
| Scan options | `ScanOptions` has only `exclude_dirs` and `scanner_names`. Default excludes include `out` and `agents`. | `models.py` |
| Roadmap | `ScanResult.roadmap` is a list of `RoadmapItem(phase 0 to 3, action, asset_ids, occurrence_count)`. | `models.py` |
| Hybrid key exchange | SAFE hybrid key exchange with unobservable authentication has overall verdict UNKNOWN. | `docs/PLAN.md` sections 6 and 7.1 |
| Score scope | Plaintext, hygiene-only warnings, libraries and derived containers are excluded from the quantum score and readiness. | `docs/PLAN.md` section 7.5 |
| Dependencies | `pyproject.toml` already has `fastapi`, `uvicorn[standard]`, `python-multipart`, `cyclonedx-python-lib`, `jsonschema`, Python 3.12. | `pyproject.toml` |
| Reports | Native reports stay valid `ScanResult` documents. No extra top-level blocks. | `docs/PLAN.md` section 6 |

## Final decisions

| ID | Final decision |
|---|---|
| M1M4-01 | The engine retains every listed extra key and the observed `hygiene_flags` unchanged in the original Findings. |
| M1M4-02 | The engine derives expiry and all hygiene interpretation from raw facts, using `source_timestamp` then scan start. Derived warnings are in `CryptoAsset.rationale` and `recommendations`. M4 reads raw `hygiene_flags` from findings and derived advice from assets. HSM backing and multi-region are context, not automatically weaknesses, so the UI shows `multi_region_key` as context. |
| M1M4-03 | The engine owns the join and tier propagation: listener `Location.resource_id` for policy components, then `extra.certificate_arns` to the certificate `Location.resource_id`. No cloud scanner classification and no `link_cloud`. A configured policy is not observed negotiated traffic. |
| M1M4-04 | M1 adds the key-spec aliases in task 1.3 and decomposes signature composites in task 1.5. M4 keeps raw names, `usage`, `key_size` and `curve`. The cloud registry stays with M4. Factual mappings need primary-source verification. |
| M1M4-05 | One `KEY` finding per KMS key with the stated usage. The engine derives the scored algorithm asset. M4 builds one `related-crypto-material` CBOM component per key from the retained finding, referencing the classified algorithm. No `ALGORITHM` finding and no double scoring. |
| M1M4-06 | Two `PLAINTEXT` hygiene findings. `public-web-alb` keeps `redirects_to_https` and `redirect_only_listener`; `batch-internal-alb` forwards HTTP. Golden rows and UI distinguish the two. Both are excluded from the quantum score. |
| M1M4-07 | Content-based `can_handle` in scanner-name order, `generic_json` last, no routing by file name. `Location.file` is relative to the scan root. KMS `resource_id` is `KeyArn`, then `KeyId`, then `AliasName` if absent. The alias is in `extra.alias`. The ask's statement that KMS keys have no ARN was wrong. |
| M1M4-08 | The engine emits the listed CycloneDX 1.6 `primitive` and `mode` values, lowercase `mode` or None, and stable unique `asset_id` values without whitespace. Raw `Finding.mode` may be uppercase. The CBOM uses the asset values. |
| M1M4-09 | M1 publishes `kb/scoring.yaml` in task 1.3 with `tier_weights`, `exposure`, `broken_multiplier`, `occurrence` (cap, log_divisor), `grade_bands` and `hndl_floor` (score, condition). M4 serves it read-only at `/api/scoring`, outside `ScanResult`, and returns a clear unavailable response when it is missing. |
| M1M4-10 | Phases are migration planning phases, not regulatory deadlines: 0 this week (classical and hygiene fixes), 1 now (HNDL key exchange), 2 by 2027 (signatures and PKI), 3 by 2030 (symmetric and hash). M4 uses this fixed display table. Published legal or standards deadlines need separate verification. |
| M1M4-11 | As asked. `build_cbom` and `validate_cbom` belong to M4. The CLI defaults to `out/`, `--format cbom` calls both, `qtrace ui` runs `uvicorn api.main:app`, `/api/result` reads `out/report.json`. A missing optional owner implementation fails explicitly. |
| M1M4-12 | Strict validation needs the extra. `pyproject.toml` has `cyclonedx-python-lib[json-validation]>=8`. M4 owns full CBOM fixture validation. |
| M1M4-13 | Format is `docs/GOLDEN.md` and `docs/golden.schema.json`, rows in `tests/golden/expected.yaml`. M4 owns the cloud rows: 10 key resources, 7 listener resources, 5 certificate resources, with the two HTTP listeners keeping distinct redirect flags. No guessed policy classification becomes ground truth. |
| M1M4-14 | Communications and shared plan updates go directly to `main`. M4 code goes to `m4/<topic>` branches and reaches `main` at milestones. M1 uses the persistent `m1` branch. No force pushes. |

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
| M1M4-14 | M1 | unknown | CHANGED | Latest explicit user instruction supersedes the earlier workflow reply: M1 implementation uses one persistent m1 branch, with milestone integration into main. All members publish communications and associated shared plan updates directly to main after upstream reconciliation and applicable checks. Pending implementation remains on member branches; preserve protections and never force-push. PR #6 integration was explicitly requested now. |
| M1M4-14 | M4 | n/a | AGREED | The later M1 row applies: one persistent m1 branch for M1, communications and shared plan updates directly to main, M4 code on m4/<topic> branches, no force-pushes. The earlier M1 row is superseded. |
| M1M4-02 | M4 | n/a | AGREED | Change accepted. M4 computes no warning. It reads raw hygiene_flags from findings and derived advice from asset rationale and recommendations. multi_region_key is shown as context. |
| M1M4-03 | M4 | n/a | AGREED | Change accepted. M4 emits listener_arn as resource_id and certificate_arns in extra, and provides no link_cloud function. The Cloud page labels policy suites as configured, not negotiated. |
| M1M4-05 | M4 | n/a | AGREED | Change accepted. One KEY finding per key and one related-crypto-material CBOM component per key, built by M4 from the retained finding. |
| M1M4-06 | M4 | n/a | AGREED | Change accepted. Two PLAINTEXT hygiene findings with distinct redirect flags, in the adapters, the golden rows and the UI. |
| M1M4-07 | M4 | n/a | AGREED | Change accepted. resource_id is KeyArn, then KeyId, then AliasName. M4's can_handle detects the three files by content. |
| M1M4-09 | M4 | n/a | AGREED | Change accepted. /api/scoring serves the loaded scoring data read-only and returns an unavailable response when the KB is missing. |
| M1M4-10 | M4 | n/a | AGREED | Change accepted. The Roadmap page presents the phases as planning phases and claims no regulatory deadline. |
| M1M4-12 | M4 | n/a | AGREED | Change accepted. M4 has nothing to report. M4 writes the strict validation test for every fixture. |
| M1M4-13 | M4 | n/a | AGREED | Change accepted. M4 writes the cloud rows in the docs/GOLDEN.md format. |
