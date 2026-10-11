#!/usr/bin/env bash
# Deterministic demo run on the starter kit: scans sample-repos, cloud-posture and network-capture and
# writes report.json, cbom.json and summary.md to out/. The inputs and their order are fixed, so
# the findings, assets, ids and score are identical on every run (only the two timestamps differ).
#
#   scripts/demo.sh           scan, validate the CBOM, print the summary
#   scripts/demo.sh --serve   then start the API and dashboard on http://127.0.0.1:8000
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -x .venv/bin/python ]; then
  PY=.venv/bin/python
else
  PY=${PYTHON:-python3}
fi

# Use the installed console script when there is one, else run the CLI module from the source tree.
if [ -x .venv/bin/qtrace ]; then
  QTRACE=(.venv/bin/qtrace)
elif command -v qtrace >/dev/null 2>&1; then
  QTRACE=(qtrace)
else
  export PYTHONPATH="src${PYTHONPATH:+:$PYTHONPATH}"
  QTRACE=("$PY" -m quantumtrace.cli)
fi

for input in sample-repos cloud-posture network-capture; do
  [ -d "$input" ] || { echo "Missing starter kit folder: $input" >&2; exit 1; }
done

# Only the files this script writes are replaced; anything else in out/ is left alone.
mkdir -p out
rm -f out/report.json out/cbom.json out/summary.md

# Exit code 2 means a scan error was reported (a pcap tool is missing, for instance), and the reports
# are still written, so the demo continues and says so.
status=0
"${QTRACE[@]}" scan sample-repos cloud-posture network-capture --out out --format json,cbom,md || status=$?
if [ "$status" -ne 0 ] && [ "$status" -ne 2 ]; then
  echo "Scan failed with exit code $status" >&2
  exit "$status"
fi
[ "$status" -eq 2 ] && echo "Note: the scan reported errors; see the summary above."

for report in report.json cbom.json summary.md; do
  [ -s "out/$report" ] || { echo "Expected out/$report was not written" >&2; exit 1; }
done
echo "Demo reports written to out/ (report.json, cbom.json, summary.md)."

if [ "${1:-}" = "--serve" ]; then
  [ -d frontend/dist ] || echo "frontend/dist is missing: run 'cd frontend && npm ci && npm run build' for the dashboard (the API still works)." >&2
  exec "${QTRACE[@]}" ui
fi
