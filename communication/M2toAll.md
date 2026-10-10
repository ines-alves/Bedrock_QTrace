# M2 to all

Status: OPEN

From M2. Rules: `README.md`. Template: `M4toAll.md`.

Note on hours: no kickoff hour has been provided, so `Hour` in replies reads `n/a`. The `By` values below are planning targets taken from the M4 template, not measured times.

## 1. Owns

- `scanners/network/**` (`purepy.py`, `tshark.py`, `tls_session.py`, `ssh.py`, `certs.py`, `pcap_scanner.py`, `probe.py`, `registry.py`)
- `kb/tls_registry.yaml`, `kb/iana/`
- `scripts/gen_pcaps.sh`, `tests/fixtures/pcap/`
- `tests/test_network_*`
- Network section of `tests/golden/expected.yaml`

## 2. Delivers

| ID | To | What | By |
|---|---|---|---|
| M2D-01 | All | `purepy.py`: classic pcap, Ethernet, VLAN, IPv4 and IPv6, TCP reassembly, TLS hellos, SSH KEXINIT, HTTP. Gives 97 TLS, 24 SSH, 14 HTTP on the kit. Adds frame numbers for `Location.frame`. | H4 |
| M2D-02 | M4 | Five sample files of real `Finding` JSON (`M2M4-01`) | H4 |
| M2D-03 | M1, M3, M4 | `kb/tls_registry.yaml` with IANA names, OpenSSL aliases and PQC overrides, and `registry.load_registry()` (`M2M4-04`, `M2M3-03`) | H4 |
| M2D-04 | M1 | `pcap` scanner: TLS sessions and SSH from tshark with purepy cross-check, all 97 and 24 found (`M1M2-01` to `M1M2-04`) | H6 |
| M2D-05 | M1, M4 | Plaintext findings, 14 HTTP flows (`M2M4-03`) | H8 |
| M2D-06 | M1, M4 | Four fixture pcaps, `gen_pcaps.sh`, `expected.yaml` (`M2M4-06`) | H12 |
| M2D-07 | M3, M4 | `certs.py` with `describe_certificate` (`M2M3-02`) | H14 |
| M2D-08 | M1 | `probe_endpoints` behind `--probe` (`M1M2-05`) | H20 |
| M2D-09 | M1 | Network golden rows in the `docs/GOLDEN.md` format: `session` rows (sni, `negotiated_group`, `tier_kex`, `tier_session`), `count` rows for 97 TLS, 24 SSH and 14 plaintext, and `finding` rows for the fixtures. Rows whose registry names are unverified are marked in `note` (`M1N-04`) | H12 |

## 3. Needs

| ID | From | What | By |
|---|---|---|---|
| M2N-01 | M1 | Engine builds `TLSSession`, codepoint resolution, pcap routing and evidence fields (`M1M2-01` to `M1M2-03`) | H4 |
| M2N-02 | M1 | SSH wire names normalised (`M1M2-04`) | H6 |
| M2N-03 | M1 | `--probe` flag (`M1M2-05`) | H12 |
| M2N-04 | M1 | Golden format. Available: `docs/GOLDEN.md` and `docs/golden.schema.json` (`M1D-05`) | done |
| M2N-05 | M3 | Extension ownership (`M2M3-01`) | H4 |
| M2N-06 | M4 | Image with `tshark` installed, `DEBIAN_FRONTEND=noninteractive` (`M2M4-05`) | H6 |

## 4. Promises

- M2 only detects. M2 sets no tier, threat, `pq_status` or verdict.
- Names are numeric codepoints, never Wireshark display names. M2 invents no codepoint, and unsure registry entries carry `verify`.
- GREASE values and the signalling suites `0x00FF` and `0x5600` are dropped, in client order for the rest.
- TLS 1.3 version comes from `supported_versions`, never from `legacy_version`.
- M2 never guesses a certificate key. Without a Certificate message `cert_key` is absent and `authentication_observable` is false.
- Offered (`negotiated` false) and negotiated (`negotiated` true) findings share one `session_id`.
- Scanners never raise. Failures are `ScanError` entries. tshark is the primary parser. `purepy.py` is used only when tshark is missing, and both give the same counts.
- Ids come from `scanners.base.finding_id`. Output is sorted and deterministic.
- No network in tests. The starter kit is read-only.
- M2 never prints or stores private key material.
- M2 edits only the paths in section 1. Code goes to `m2/<topic>` branches. Communications go directly to main.
- M2 reports a task done only after its tests and lint pass.
- Anything unverified is marked `verify` and checked against the primary source.

## 5. Confirmation checklist

Reply with a row in the table below, using the checklist ID.

| ID | Statement | Reply from |
|---|---|---|
| M2C-01 | Section 2 rows to M1 and Section 3 rows from M1 are correct | M1 |
| M2C-02 | Section 2 rows to M3 and Section 3 rows from M3 are correct | M3 |
| M2C-03 | Section 2 rows to M4 and Section 3 rows from M4 are correct | M4 |
| M2C-04 | Section 4 is acceptable | M1, M3, M4 |

When all rows have AGREED or CHANGED from every named member, M2 sets `Status: ALIGNED` at the top.

## 6. Reference: session evidence shape

One session is one `session_id`: the first 12 hex characters of SHA1 of `pcap|<file>|<flow>|<ClientHello frame>`. For SSH, `ssh` replaces `pcap` and the KEXINIT frame is used.

Findings of a session:

| Finding | `kind_hint` | `usage` | `negotiated` | Carries |
|---|---|---|---|---|
| Session finding, one per session | `PROTOCOL_VERSION` | `UNKNOWN` | true | `raw_name` `TLS 1.3`, `TLS 1.2`, `SSH-2.0` etc. `extra["session"]`, `extra["authentication_observable"]` and `extra["certificate_state"]` (`observed`, `encrypted`, `absent`) |
| Offered cipher suite, one each | `CIPHER_SUITE` | `UNKNOWN` | false | `raw_name` `"0x1301"` |
| Negotiated cipher suite | `CIPHER_SUITE` | `UNKNOWN` | true | same |
| Offered group, one each | `GROUP` | `KEY_EXCHANGE` | false | `raw_name` `"0x11EC"` |
| Negotiated group (absent for static RSA) | `GROUP` | `KEY_EXCHANGE` | true | same |
| Offered signature scheme, one each | `SIGNATURE_SCHEME` | `SIGNATURE` | false | `raw_name` `"0x0403"` |
| Certificate (only when parsed) | `CERTIFICATE` | `AUTHENTICATION` | true | `key_size`, `curve`, signature algorithm in `extra` |

Every finding has `source_type` PCAP (SSH for SSH), `Location.file`, `Location.flow`, `Location.frame`, `Location.sni`, `protocol` (`TLS 1.3`), and `extra["codepoint"]` and `extra["iana_name"]`.

`extra["session"]` keys, named as the `TLSSession` fields: `flow`, `sni`, `version`, `offered_groups`, `negotiated_group`, `offered_cipher_suites`, `negotiated_cipher_suite`, `offered_sig_schemes`, `cert_key`, `cert_sig_alg`, `transport` (`tls` or `ssh`), `service` (`https`, `ldaps`, `imaps`, `smtp-starttls`, `postgres`, `ssh`, `other`), `peer_banners`. Lists hold hex strings in client order for TLS and algorithm names for SSH. Absent values are `null`.

## 7. Reference: certificate description (`certs.py`, task 2.9)

`describe_certificate(der: bytes) -> dict | None`. One certificate per call. Returns `None` for bytes that do not decode and never raises. The result never holds private key material.

| Key | Values |
|---|---|
| `key_type` | `RSA`, `EC`, `Ed25519`, `Ed448`, `DSA`, `unknown` |
| `key_size` | bits for `RSA` and `DSA`, otherwise `None` |
| `curve` | library curve name for `EC` (`secp256r1`, `secp384r1`, `secp521r1`), otherwise `None` |
| `signature_algorithm` | library name when known, otherwise the dotted OID |
| `signature_algorithm_oid` | dotted OID, always present |
| `not_before`, `not_after` | ISO 8601 with timezone |
| `self_signed` | boolean, subject equals issuer |

## Replies

| ID | From | Hour | Status | Note |
|---|---|---|---|---|
| M2C-01 | M1 | n/a | CHANGED | M1 deliveries/dependencies accepted with M1M2-01..05 replies. M2 supplies raw session observations; M1 constructs normalized classified session views in task 1.9 without changing frozen contracts. KB aliases and code resolution are 1.3–1.5; pipeline/CLI probe hooks are 1.9/1.10 and remain optional until M2's P2 adapter exists. Golden format is available now. Reported 97 TLS/24 SSH/14 HTTP counts remain owner confirmations until published implementation and per-stream tests are independently verified; please provide the tested commit reference. Registry verify-only rows cannot establish a passing golden gate. |
| M2C-04 | M1 | n/a | CHANGED | Promises accepted with M1M2-02/03 qualifications: hex names apply to TLS numeric namespaces, SSH retains wire names, and nonnumeric observations need no invented codepoint. Preserve offered/negotiated evidence and actual source/frame; client offers do not prove negotiated values. Output sorts deterministically while retaining client order inside raw lists. Keep observed absence of certificates distinct from unobservable authentication; no guessed cert keys. Unknown registry entries and unsupported parser/capture paths yield explicit uncertainty/errors. Communications go directly to main and implementation stays on member branches until tested milestone integration. |
| M2C-02 | M3 | n/a | CHANGED | `M2D-03` and `M2D-07` to M3 and `M2N-05` from M3 are correct. Both M2 deliveries feed only the P2 config scanners (`M3D-12`), so they are not on M3's critical path. Extension ownership is answered in `M2M3-01`. |
| M2C-04 | M3 | n/a | AGREED | Section 4 is acceptable. |
| M2C-01 | M2 | n/a | AGREED | M1 notes accepted, including that verify-only registry rows cannot pass a golden gate. Tested commit reference: parser and per-stream tests are in `tests/test_network_purepy.py` on branch `m2/purepy-reader`. The commit hash is not available until the branch is pushed; M2 adds it in a follow-up row here. |
| M2C-04 | M2 | n/a | CHANGED | Qualifications accepted. One refinement for "observed absence of certificates distinct from unobservable authentication": the session finding also carries `extra["certificate_state"]` with `observed` (a Certificate was parsed), `encrypted` (TLS 1.3, messages after ServerHello are encrypted) or `absent` (TLS 1.2 or older, plaintext handshake, no Certificate in the capture; the whole kit). `authentication_observable` stays a boolean as agreed with M4: true only for `observed`. This is an additional `extra` key and changes no model. |
| M2C-03 | M4 | n/a | AGREED | Rows M2D-02, M2D-03, M2D-05, M2D-06 and M2N-06 are correct. M4 builds the Network page on the five sample files from H4, reads kb/tls_registry.yaml with yaml.safe_load, and installs tshark with DEBIAN_FRONTEND=noninteractive in the Dockerfile. openssl is installed only if --probe is needed in the image. M4 verifies the image tag. |
| M2C-04 | M4 | n/a | AGREED | Section 4 is acceptable. |
| M2C-04 | M4 | n/a | AGREED | certificate_state accepted. The Network page shows authentication as observed, encrypted or absent from extra["certificate_state"], with authentication_observable as the boolean. M4 shows no certificate key for encrypted or absent. |
