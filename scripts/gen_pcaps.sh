#!/usr/bin/env bash
# Generate the M2 fixture captures (PLAN 2.8 / M2M4-06) from real OpenSSL handshakes on loopback.
#
#   scripts/gen_pcaps.sh [output-dir]      default: tests/fixtures/pcap
#
# Needs OpenSSL >= 3.5 (X25519MLKEM768) and tcpdump with permission to capture on loopback
# (macOS: member of access_bpf; Linux: root or CAP_NET_RAW). Port 443 must be bindable
# (override with PORT=...).
#
# Output is NOT byte-reproducible (fresh keys and randoms each run). The pcaps are committed and
# tests read the committed files; rerun only to replace them, then update expected.yaml.
# Exit status 3: tls10_3des.pcap was skipped because this openssl has no DES-CBC3-SHA.
set -euo pipefail

OUT="${1:-$(cd "$(dirname "$0")/.." && pwd)/tests/fixtures/pcap}"
PORT="${PORT:-443}"
HOST=127.0.0.1
OPENSSL="${OPENSSL:-openssl}"
case "$(uname -s)" in Darwin) IFACE=lo0 ;; *) IFACE=lo ;; esac

mkdir -p "$OUT"
WORK="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT

"$OPENSSL" version | grep -Eq 'OpenSSL (3\.([5-9]|[1-9][0-9])|[4-9])\.' || {
  echo "OpenSSL >= 3.5 required (found: $("$OPENSSL" version))" >&2; exit 1; }

ecdsa_cert() {  # name cn
  "$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
    -subj "/CN=$2" -keyout "$WORK/$1.key" -out "$WORK/$1.crt" 2>/dev/null
}
rsa_cert() {  # name cn
  "$OPENSSL" req -x509 -newkey rsa:2048 -nodes -days 365 -sha256 \
    -subj "/CN=$2" -keyout "$WORK/$1.key" -out "$WORK/$1.crt" 2>/dev/null
}

# Capture one handshake. Args: name sni; server args after `--server`, client args after `--client`.
capture() {
  local name="$1" sni="$2"; shift 2
  local sargs=() cargs=() mode=""
  for a in "$@"; do
    case "$a" in --server) mode=s ;; --client) mode=c ;;
      *) if [ "$mode" = s ]; then sargs+=("$a"); else cargs+=("$a"); fi ;;
    esac
  done
  local raw="$WORK/$name.raw.pcap"
  tcpdump -i "$IFACE" -n -U -w "$raw" "tcp port $PORT" 2>"$WORK/tcpdump.log" &
  local tp=$!; PIDS+=("$tp"); sleep 1
  "$OPENSSL" s_server -accept "$PORT" -naccept 1 -quiet "${sargs[@]}" >/dev/null 2>"$WORK/server.log" &
  local sp=$!; PIDS+=("$sp"); sleep 1
  printf 'GET / HTTP/1.0\r\n\r\n' | "$OPENSSL" s_client -connect "$HOST:$PORT" -servername "$sni" \
    -quiet "${cargs[@]}" >/dev/null 2>"$WORK/client.log" || {
      echo "$name: handshake failed:" >&2
      cat "$WORK/client.log" "$WORK/server.log" >&2
      kill -INT "$tp" 2>/dev/null || true
      return 1
    }
  sleep 1
  kill -INT "$tp" 2>/dev/null || true
  wait "$tp" 2>/dev/null || true
  wait "$sp" 2>/dev/null || true
  python3 - "$raw" "$OUT/$name.pcap" <<'PY'
import struct, sys
src, dst = sys.argv[1:]
data = open(src, "rb").read()
magics = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}
endian = magics[data[:4]]
linktype = struct.unpack_from(endian + "I", data, 20)[0]
if linktype not in (0, 1):
    sys.exit(f"unexpected link type {linktype}")
out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
off, n = 24, 0
while off + 16 <= len(data):
    sec, usec, caplen, wirelen = struct.unpack_from(endian + "IIII", data, off)
    frame = data[off + 16 : off + 16 + caplen]
    off += 16 + caplen
    if linktype == 0:  # BSD loopback: 4-byte family, then the IP packet; give it an Ethernet header
        ip = frame[4:]
        ether = b"\x00" * 12 + (b"\x86\xdd" if ip[:1] and ip[0] >> 4 == 6 else b"\x08\x00")
        frame, wirelen = ether + ip, wirelen - 4 + 14
    out += struct.pack("<IIII", sec, usec, len(frame), wirelen) + frame
    n += 1
open(dst, "wb").write(out)
print(f"{dst}: {n} packets")
PY
}

# (a) TLS 1.2 ECDHE-ECDSA P-256, certificate present.
ecdsa_cert ecdsa ecdsa.lab
capture tls12_ecdhe_ecdsa_p256 ecdsa.lab \
  --server -cert "$WORK/ecdsa.crt" -key "$WORK/ecdsa.key" -tls1_2 \
    -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -groups prime256v1 \
  --client -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256

# (b) client offers X25519MLKEM768 (and sends its key share), server only supports x25519.
ecdsa_cert refuse refuse.lab
capture tls13_offer_hybrid_server_x25519 refuse.lab \
  --server -cert "$WORK/refuse.crt" -key "$WORK/refuse.key" -tls1_3 -groups X25519 \
  --client -tls1_3 -groups '*X25519MLKEM768:*X25519'

# (c) TLS 1.0 with 3DES. Needs an OpenSSL built with weak ciphers (Homebrew's is not).
STATUS=0
if "$OPENSSL" ciphers 'DES-CBC3-SHA:@SECLEVEL=0' >/dev/null 2>&1; then
  rsa_cert old old.lab
  capture tls10_3des old.lab \
    --server -cert "$WORK/old.crt" -key "$WORK/old.key" -tls1 -cipher 'DES-CBC3-SHA:@SECLEVEL=0' \
    --client -tls1 -cipher 'DES-CBC3-SHA:@SECLEVEL=0'
else
  echo "SKIPPED tls10_3des: this openssl has no DES-CBC3-SHA (build with enable-weak-ssl-ciphers)" >&2
  STATUS=3
fi

# (d) TLS 1.3 hybrid with an ECDSA certificate, plus the client keylog.
ecdsa_cert hybrid hybrid.lab
capture tls13_hybrid_keylog hybrid.lab \
  --server -cert "$WORK/hybrid.crt" -key "$WORK/hybrid.key" -tls1_3 -groups X25519MLKEM768 \
  --client -tls1_3 -groups X25519MLKEM768 -keylogfile "$OUT/tls13_hybrid_keylog.keylog"

echo "done: $(ls "$OUT"/*.pcap | wc -l | tr -d ' ') of 4 captures in $OUT"
exit "$STATUS"
