# Scan orchestration

`quantumtrace.pipeline.run(inputs, probes=None, options=None) -> ScanResult` uses
the frozen ScanOptions/ScanResult contracts. It imports the currently published
self-registering owner adapters: `cloud.acm`, `cloud.kms`, `cloud.loadbalancer`,
`code.regex` and `code.manifest`.
Scanners match content/extensions through their own can_handle, in scanner-name
order; names containing `generic_json` are tried last. The first accepting handler
runs once. Explicit scanner selection restricts handlers; unavailable selections
produce an error and no fallback to an unselected scanner. Import, can_handle,
iteration and invalid emission failures become ScanError; prior yielded Findings
remain usable. Excluded directories are skipped. Unsupported files and missing
inputs have explicit errors, so coverage gaps never look like empty success.

Traversal sorts input paths and children, uses each directory input as its evidence
root and each direct file's parent as its root, and deduplicates resolved physical
files across overlapping inputs and file symlinks. Directory symlinks are skipped
to avoid cycles and escapes through linked directories. Outer roots are visited
first, so overlapping input order does not select different evidence paths. A
repo-root scan and a direct-file scan deliberately have different relative paths;
IDs are repeatable within each invocation root. Findings retain every distinct
metadata emission even when finding IDs collide; identical emissions and errors
are idempotent. Raw Location/extra values are never rewritten by orchestration.

One UTC scan-start time is supplied explicitly to classification as its hygiene
reference; a source timestamp retains priority. Result start/finish times are
metadata. The stable scan ID hashes canonical absolute inputs, probe targets,
normalized options and original finding evidence, excluding source_timestamp and
scan times. Output assets, findings, sessions and errors sort deterministically.
Scores/session IDs do not depend on wall-clock time; expiry advice can legitimately
change when the explicit reference changes. Findings containing a source timestamp
keep it in the serialized ScanResult. Native JSON round-trips through ScanResult.

Currently no registered PCAP adapter or config/keyfile/binary scanner or optional
probe adapter is published on main. Their files are reported
as unsupported by run; requested probes return explicit unavailable-adapter errors
and never trigger implicit network traffic. M2 owns the registered capture/probe
adapter. M4 ACM is now wired into the loader and verified with its five resources.
Published raw parser helpers work and are exercised in session tests, but they do
not satisfy the end-to-end registered-scanner H6 gate.
M3 manifests are routed through the registered adapter; their library Findings
remain inventory and are excluded from quantum counts, readiness and scoring.
M3 Markdown output is available through `output.markdown.write_markdown_summary`;
CLI output integration follows in task 1.10.
Later owner modules must be included in the loader when integrated; this list
never guesses or substitutes a detection implementation owned by another member.

# Session views

`engine.sessions.build_sessions(findings, classified_roots)` returns typed TLS/SSH
views and recoverable metadata errors. It groups all network findings with a
session_id, without requiring a protocol-version finding, extra.session dictionary
or fixed detector name. Plaintext is not a session. Source comes only from the
capture file or live target; certificate_state/authentication_observable and all
arbitrary owner extras remain in original Findings. Frozen TLSSession has no
certificate_state field, so consumers use retained raw findings for that detail.

Names resolve in the field's TLS namespace through verified rows; unknown or
unverified codepoints keep canonical hex. Alias-only uncertainty does not block
a confirmed numeric row, while the marked alias remains unresolved. Observed textual
versions and metadata labels are retained; numeric version rows cite their supplied
RFC sources; rows without a source still remain hex.
Null/absent fields do not compete with actual observed values. Raw client order is
retained for metadata offer lists, and null lists become [] only in typed views.
Without metadata, individual offered rows reconstruct a deterministic list ordered
by evidence frame/id; client wire order cannot be claimed when that list is absent.
No offered-only record or unselected metadata creates a negotiated choice. TLS
ServerKeyExchange frames remain on the raw Findings and asset occurrences.

Contradictory scalar choices, ordered lists, flows/sources, certificate states,
observability or malformed typed metadata produce explicit errors and an UNKNOWN
pq_status; uncertainty makes SAFE verdicts UNKNOWN while actually observed
CRITICAL/MEDIUM mechanisms retain their conservative verdict. Disputed scalar
fields are left unset. No arbitrary
winner is selected. SSH asymmetric ciphers display the observed client-to-server
choice while both directions' negotiated components contribute to the verdict;
raw direction flags and owner warnings are retained. Peer banners retain their
client/server ordering, including empty placeholders.

Session verdicts use only actually negotiated eligible classified atoms, excluding
container rows and hybrid trace halves. Authentication uses observed certificate
or host-algorithm evidence plus explicit observability; unobservable/absent auth
adds UNKNOWN, while known CRITICAL/MEDIUM mechanisms still dominate. Missing KEX
or cipher adds UNKNOWN to an otherwise SAFE summary. Certificate fields are hidden
when auth is unobservable; no RSA/ECDSA key is guessed. `pq_status` describes KEX
independently: SAFE atomic hybrids are pq_hybrid, SAFE pure KEMs pq_pure, known
classical KEX classical, and missing/unresolved KEX unknown. Thus a SAFE hybrid
with encrypted authentication is pq_hybrid with an UNKNOWN overall verdict.

Task 1.9 acceptance separates fake-scanner orchestration, available code/cloud
starter scans, direct published network-sample consumption and real pure-Python
capture consumption. Full H6 waits for registered owner adapters, actual tshark
checks, and complete starter coverage; golden accuracy remains task 1.12.
