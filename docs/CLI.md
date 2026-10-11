# QuantumTrace command line

Install the Python 3.12 development environment with `make install`, then use
`.venv/bin/qtrace --help`. An installed wheel also provides the `qtrace` command.

```sh
qtrace scan sample-repos cloud-posture network-capture --out out/ --format json,cbom,md
qtrace scan network-capture/network.pcap --out out/
qtrace ui
```

`scan` accepts files and directories, using the delivered registered scanners.
It defaults to native JSON in `out/report.json`. `--format` accepts a comma-separated
selection of `json`, `cbom` and `md`, producing `report.json`, `cbom.json` and
`summary.md`. CBOM output passes M4's strict offline validator before writing.
Native JSON and CBOM files use atomic replacement. Markdown uses M3's writer.
Native reports retain findings, asset links, session views, errors and the typed
migration roadmap. The roadmap phases are planning priorities, not deadlines.

The console displays grade, risk score, readiness, scored asset counts and the
top ten risks. Protocol and certificate containers do not inflate scored counts.
Complete scans exit 0. Partial scans retain usable reports, display coverage errors
and exit 2. Invalid arguments, unavailable requested writers and output failures
also exit 2. A file found while walking a folder that no scanner supports is
reported as a coverage error only when it may hold key material or TLS/SSH
configuration: `.pem`, `.crt`, `.cer`, `.der`, `.key`, `.csr`, `.p12`, `.pfx`,
`.p7b`, `.p8`, `.jks`, `.keystore` and `.pub` files, `id_rsa`/`id_dsa`/`id_ecdsa`/
`id_ed25519`, `authorized_keys`, and `nginx.conf`, `httpd.conf`, `ssl.conf`,
`haproxy.cfg`, `openssl.cnf`, `java.security`, `sshd_config`, `ssh_config`. Other
walked files (source in unsupported languages, web assets, documentation) are not
cryptographic input: they are skipped and the console prints how many. A file
named explicitly on the command line is always reported. The starter directory
command above is therefore complete and exits 0 (its three README files are
skipped); the capture itself produces 97 TLS and 24 SSH
sessions plus 14 plaintext flows. The starter capture contains no TLS Certificate messages, so
unobservable authentication is retained rather than guessed.

Repeat `--probe host:port` to request explicit probes; bracket IPv6 addresses,
for example `--probe '[::1]:443'`. The optional M2 probe adapter is not delivered:
requests appear as coverage errors and exit 2. Ordinary scans initiate no probes.
SARIF output is not provided by this CLI.

## CI use

`--out -` writes exactly one native JSON document (the `report.json` content) to
stdout; the summary tables, threshold messages and errors go to stderr. It accepts
only `--format json`; requesting `cbom` or `md` with `--out -` exits 2 before scanning.

`--fail-on critical` exits 1 when any classified, scored asset is CRITICAL;
`--fail-on medium` also counts MEDIUM. Containers, hygiene-only warnings and raw
unclassified names are never counted. UNKNOWN assets are reported separately on
stderr and do not trigger the threshold. Reports are written before the exit code
is decided.

Exit precedence: 2 for invalid arguments, unavailable writers, scan or output
failures and partial coverage (scan errors); otherwise 1 when the threshold is
reached; otherwise 0. A partial scan therefore exits 2 even if the threshold is
also reached, and still emits its JSON report.

```sh
# Gate a pipeline on quantum-vulnerable cryptography and keep the report.
qtrace scan src/ config/ --out - --fail-on critical > quantumtrace.json
# Directory reports plus a stricter gate.
qtrace scan src/ --out out/ --format json,cbom --fail-on medium
```

`ui` launches M4's `api.main:app` through Uvicorn, defaulting to `127.0.0.1:8000`.
Run it from the repository root; `--host` and `--port` override the bind address.
The API serves a built frontend when `frontend/dist` exists. Uploads are M4 task
4.8; the current scan API accepts server-side paths. API failures are reported
explicitly. The CLI does not build the frontend.

`qtrace eval` and `make eval` run the packaged offline golden evaluator from the
repository root. `scripts/eval.py --root /path/to/checkout` also supports an explicit
checkout. Exit 0 requires precision and recall at least 0.95 for every assessed
source and overall, correct tiers/flags/SAFE expectations, and complete confirmed
coverage. Failed accuracy or incomplete coverage exits 1; invalid setup exits 2.
`make check` includes this gate. Confirmed-only metrics are labelled explicitly;
network/cloud accuracy remains unmeasured until their owners contribute rows.
See [GOLDEN.md](GOLDEN.md) for matching, scope and provisional counts.
