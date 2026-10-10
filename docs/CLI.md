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
also exit 2. The starter directory command above reports three unsupported README
files and exits 2; the capture itself produces 97 TLS and 24 SSH sessions plus
14 plaintext flows. TLS certificate extraction is still an M2 follow-up, so
unobservable authentication is retained rather than guessed.

Repeat `--probe host:port` to request explicit probes; bracket IPv6 addresses,
for example `--probe '[::1]:443'`. The optional M2 probe adapter is not delivered:
requests appear as coverage errors and exit 2. Ordinary scans initiate no probes.
SARIF, JSON stdout and score threshold exits are not part of this CLI milestone.

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
