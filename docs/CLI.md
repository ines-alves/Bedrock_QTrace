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
also exit 2.

Key, certificate and keystore files are scanned (`.pem`, `.crt`, `.cer`, `.der`,
`.key`, `.csr`, `.p7b`, `.p8`, `.pub`, `.p12`, `.pfx`, `.jks`, `.keystore`,
`id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519` and their `_sk` forms, `ssh_host_*_key`,
`authorized_keys`, `known_hosts`): each key or certificate is reported with its
type, size or curve, signature algorithm and validity. A private key is reported
as present (type, size, whether it is encrypted) and never shown. Server
configuration files are scanned for TLS and SSH settings: nginx, Apache httpd,
HAProxy, `openssl.cnf`, `java.security`, `sshd_config`/`ssh_config`, Spring Boot
`application*.properties`/`.yml` and Tomcat `server.xml`, plus `.conf`, `.cfg` and
`.cnf` files and files in `sites-enabled`, `conf.d` and similar directories when
they contain TLS or SSH directives. A key file whose content is not a key,
certificate or keystore is a coverage error.

A file found while walking a folder that no scanner supports is skipped: source
in unsupported languages, web assets and documentation are not cryptographic
input, and the console prints how many files were skipped. A file named
explicitly on the command line is always reported. The starter directory
command above is therefore complete and exits 0 (its three README files are
skipped); the capture itself produces 97 TLS and 24 SSH
sessions plus 14 plaintext flows. The starter capture contains no TLS Certificate messages, so
unobservable authentication is retained rather than guessed.

Repeat `--probe host:port` to probe live TLS endpoints; bracket IPv6 addresses,
for example `--probe '[::1]:443'`. Paths are optional with `--probe`
(`qtrace scan --probe example.org:443`); a scan with neither paths nor probes
exits 2. Targets are a DNS name, IPv4 address or bracketed IPv6 address with a
port; URLs and address ranges are rejected. Ordinary scans open no connection.

Each endpoint gets up to two handshakes through the local `openssl s_client`
(10 seconds each): the OpenSSL default offer, then a TLS 1.3 offer of only
X25519MLKEM768 unless the default handshake already selected a hybrid group. The
report keeps what the server selected (version, cipher suite, group, handshake
signature scheme) and the leaf certificate key and signature; the probe's own
client offer is not reported. Each handshake is its own session. A server that
refuses the hybrid-only offer is recorded on the default session
(`extra.hybrid_attempt`), not as an error; the forced offer says nothing about
the server's default preference. Certificate trust is recorded separately
(`extra.verify_result`); the sent chain is not treated as verified. Unreachable
endpoints, timeouts and a missing `openssl` executable or hybrid group are
coverage errors (exit 2); other endpoints are still reported. Hybrid probing
needs OpenSSL 3.5 or later. SARIF output is not provided by this CLI.

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
reached; otherwise 0. Scan errors with `severity: "info"` (report schema 1.1) are notes,
not coverage gaps: the console lists them under "Notes", and they never change the
exit code or fail the golden gate. A partial scan therefore exits 2 even if the threshold is
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
