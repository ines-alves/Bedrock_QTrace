# M1M4 agreement

Between M1 (contract, engine, pipeline, CLI, report) and M4 (cloud adapters, CBOM, API, dashboard). Rules: `README.md`.

### M1M4-01 | By H1
Ask: add two optional fields to `CryptoAsset` in `models.py`: `attributes: dict[str, Any] = {}` and `flags: list[str] = []`. The engine copies `Finding.extra` into `attributes` and `Finding.extra["flags"]` into `flags`.
Why: `Finding.extra` does not survive aggregation, so the UI and CBOM cannot see cloud details.
Preference: as stated. `extra` keys:
- KMS: `alias`, `key_state`, `key_usage`, `origin`, `multi_region`, `rotation_status`, `valid_to`, `deletion_date`
- Listener: `lb_name`, `lb_type`, `scheme`, `listener_protocol`, `port`, `ssl_policy`, `listener_arn`, `certificate_arns`, `redirects_to_https`
- Certificate: `domain`, `cert_type`, `cert_status`, `not_before`, `not_after`, `days_to_expiry`, `in_use_by`, `signature_algorithm`, `key_algorithm`
- `flags` values: `expired_in_use`, `expires_within_90d`, `imported_cert`, `sha1_signature`, `rotation_disabled`, `external_key_material`, `pending_deletion`, `multi_region_key`, `hsm_backed`, `plaintext_listener`, `redirect_only_listener`, `public_listener`
Fallback: no model change. M4 UI reads cloud details from `ScanResult.findings` via `finding_ids`. CBOM omits them.

### M1M4-02 | By H1
Ask: each TLS listener becomes a `protocol` asset. Its `components` are the policy cipher suites, the policy groups and the certificate asset. `aggregate.py` links them by equal `Location.resource_id` (ARN).
Why: the expired SHA-1 certificate must raise the tier of the listener that serves it, and the CBOM needs `dependencies[]`.
Preference: as stated.
Fallback: M4 provides `link_cloud(findings)` in `scanners/cloud/`. `pipeline.py` calls it after all scanners and before `analyze()`.

### M1M4-03 | By H1
Ask: M1 adds aliases or patterns in `algorithms.yaml` for these raw names: `RSA_2048`, `RSA_3072`, `RSA_4096`, `ECC_NIST_P256`, `ECC_NIST_P384`, `EC_prime256v1`, `EC_secp384r1`, `SHA1WITHRSA`, `SHA256WITHRSA`, `ECDSA_WITH_SHA256`, `ECDSA_WITH_SHA384`.
Why: algorithm naming must live in one place.
Preference: as stated. M4 sets `key_size` and `curve` on the finding when the source gives them. M4 `cloud_registry.yaml` only holds `SYMMETRIC_DEFAULT` (AES-256-GCM, to verify) and the ELB policy table.
Fallback: M4 maps these names in `cloud_registry.yaml` to names M1 already knows.

### M1M4-04 | By H1
Ask: one `KindHint.KEY` finding per KMS key. `raw_name` is `KeySpec`. `usage` is `SIGNATURE` for `SIGN_VERIFY` and `ENCRYPTION` for `ENCRYPT_DECRYPT`. The engine derives the algorithm asset and the `related-crypto-material` asset from it.
Why: two findings per key double count the same key.
Preference: as stated.
Fallback: M4 emits one `KEY` finding and one `ALGORITHM` finding per key, as in PLAN.md task 4.3.

### M1M4-05 | By H4
Ask: the engine reads `extra["scheme"] == "internet-facing"` and `extra["key_state"]` for the exposure weights in `scoring.yaml`.
Why: only the adapters know these facts.
Preference: as stated.
Fallback: M1 names the keys. M4 renames.

### M1M4-06 | By H4
Ask: only the forwarding HTTP:80 listener (`batch-internal-alb`) is a `PLAINTEXT` finding. The redirect listener (`public-web-alb`) gets flag `redirect_only_listener` and is not scored. `tests/golden/expected.yaml` has one plaintext listener, not two.
Why: PLAINTEXT on a redirect listener is a false positive in `make eval`. PLAN.md Appendix D.5 says two.
Preference: as stated.
Fallback: both are `PLAINTEXT`, and M4 keeps the flag on the redirect one.

### M1M4-07 | By H4
Ask: the as-of date for "expired" and "expires within 90 days" is the `GeneratedAt` value in the same cloud file (2026-09-14). No `ScanOptions` change.
Why: using today's date changes results every day.
Preference: as stated.
Fallback: M1 adds optional `ScanOptions.as_of: date | None`. M4 uses it if set.

### M1M4-08 | By H4
Ask: the pipeline offers every `.json` file to every scanner. The first scanner whose `can_handle` returns true wins. `generic_json` is tried last. `Location.file` is relative to the scan root. KMS `Location.resource_id` is the `AliasName`.
Why: all three cloud files are `.json` and M4 detects them by content (`Keys`, `LoadBalancers`, `Certificates`). KMS keys have no ARN in the data.
Preference: as stated.
Fallback: M1 routes by file name instead (`kms_key_inventory.json`, `load_balancer_listeners.json`, `acm_certificates.json`).

### M1M4-09 | By H6
Ask: every `CryptoAsset` has `primitive` and `mode` values from the CycloneDX lists (or `None` for `mode`), and a unique, deterministic `asset_id` with no spaces. `primitive` list: `signature, hash, pke, kem, key-agree, block-cipher, stream-cipher, mac, kdf, ae, drbg, xof, combiner, other, unknown`. `mode` list: `cbc, ecb, ccm, gcm, cfb, ofb, ctr, other, unknown`.
Why: CycloneDX strict validation rejects other values.
Preference: as stated.
Fallback: M4 maps unknown values to `other` in `cyclonedx.py` and logs them.

### M1M4-10 | By H6
Ask: `report.json` has two extra blocks. `roadmap`: list of `{phase, title, deadline, actions, asset_ids}`. `scoring`: `{tier_weights, exposure, broken_multiplier, occurrence_formula, grade_bands, hndl_floor}` copied from `scoring.yaml`.
Why: the Roadmap page and the score explanation must show what the engine does.
Preference: as stated.
Fallback: M4 hard-codes the text from PLAN.md sections 7.5 and 7.7.

### M1M4-11 | By H1
Ask: `pyproject.toml` contains `fastapi`, `uvicorn[standard]`, `python-multipart`, `cyclonedx-python-lib`, `jsonschema`, Python 3.12.
Why: Docker and the API install from it.
Preference: as stated. M4 reports by H6 whether `cyclonedx-python-lib` needs the `json-validation` extra, and M1 adds it.
Fallback: M4 sends M1 the exact lines.

### M1M4-12 | By H6
Ask: M1 confirms these. `build_cbom(result) -> dict` and `validate_cbom(cbom) -> list[str]` are M4's and signatures are final. The CLI writes to `out/` by default. `qtrace scan --format cbom` calls M4's functions. `qtrace ui` runs `uvicorn api.main:app`. `/api/result` reads `out/report.json`.
Why: CLI and API must meet without guessing.
Preference: as stated.
Fallback: M1 states the differences.

### M1M4-13 | By H2
Ask: M1 sends the schema of `tests/golden/expected.yaml`. M4 writes the cloud section (10 keys, 7 listeners, 5 certificates).
Why: the cloud entries must match the eval format.
Preference: as stated.
Fallback: M4 writes the entries in the format shown in PLAN.md section 10.2.

---

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
