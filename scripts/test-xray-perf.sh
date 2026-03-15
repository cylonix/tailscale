#!/bin/bash
# test-xray-perf.sh — Two-VM throughput diagnostic for XRAY DERP relay.
#
# USAGE
#   On VM1 (server): run install-xray-derper.sh first, then:
#       ./test-xray-perf.sh server
#
#   On VM2 (client):
#       ./test-xray-perf.sh client <VM1_IP> <UUID> <PUBLIC_KEY> <SHORT_ID> \
#           [REALITY_SERVER_NAME] [TUNNEL_PATH]
#
# The script runs four iperf3 measurements to isolate which layer is slow:
#   Test 1 — Raw TCP between VMs (baseline, no DERP, no xray)
#   Test 2 — Direct to DERP port on VM1 (bypasses xray, tests DERP overhead)
#   Test 3 — Through xray tunnel (full stack, via xray SOCKS5 proxy + socat)
#   Test 4 — Reverse (download) through xray tunnel
#
# Expected results after stream-up fix:
#   Test 1 ≈ 500-600 Mbps
#   Test 2 ≈ Test 1  (DERP loopback adds <5% overhead)
#   Test 3 ≈ Test 2  (xray stream-up ≈ raw TCP)
#   Test 4 ≈ Test 3

set -euo pipefail

IPERF_DURATION="${IPERF_DURATION:-15}"
XRAY_SOCKS_PORT=10808
XRAY_BIN=/usr/local/bin/xray
XRAY_CLIENT_CFG=/tmp/xray-perf-client.json
SOCAT_BRIDGE_PORT=15201

die() { echo "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" &>/dev/null || die "missing: $1 (apt install $1)"; }

# ────────────────────────── SERVER MODE ──────────────────────────
if [[ "${1:-}" == "server" ]]; then
    need iperf3
    need socat

    DERP_PORT=8080
    DERP_BYPASS_PORT=9998   # direct DERP port (no xray) for Test 2

    echo "=== XRAY DERP performance test server ==="
    echo "DERP port      : $DERP_PORT"
    echo "DERP bypass    : $DERP_BYPASS_PORT  (socat → $DERP_PORT, bypasses xray)"
    echo ""

    # socat bypass: exposes DERP directly for Test 2
    echo "[server] Starting socat bypass on :$DERP_BYPASS_PORT → 127.0.0.1:$DERP_PORT"
    pkill -f "socat.*$DERP_BYPASS_PORT" 2>/dev/null || true
    socat TCP-LISTEN:$DERP_BYPASS_PORT,reuseaddr,fork TCP:127.0.0.1:$DERP_PORT &
    SOCAT_PID=$!
    trap "kill $SOCAT_PID 2>/dev/null; true" EXIT

    # iperf3 server for Test 1 (raw TCP baseline)
    echo "[server] Starting iperf3 on :5201"
    pkill -f "iperf3.*5201" 2>/dev/null || true
    iperf3 -s -p 5201 -D --logfile /tmp/iperf3-server.log

    echo ""
    echo "Server ready. On VM2 (client) run:"
    echo "  $0 client <THIS_VM_IP> <UUID> <PUBLIC_KEY> <SHORT_ID>"
    echo ""
    echo "Press Ctrl-C to stop."
    wait $SOCAT_PID
    exit 0
fi

# ────────────────────────── CLIENT MODE ──────────────────────────
[[ "${1:-}" == "client" ]] || { echo "Usage: $0 server | client <VM1_IP> <UUID> <PUB_KEY> <SHORT_ID> [SNI] [PATH]"; exit 1; }

SERVER_IP="${2:?VM1 IP required}"
XRAY_UUID="${3:?UUID required}"
XRAY_PUBKEY="${4:?Public key required}"
XRAY_SHORTID="${5:?Short ID required}"
REALITY_SNI="${6:-www.microsoft.com}"
TUNNEL_PATH="${7:-/cylonix-derp-tunnel}"

need iperf3
need socat
[[ -x "$XRAY_BIN" ]] || die "xray not found at $XRAY_BIN (run: bash -c \"\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ install)"

DERP_IPERF_PORT=5201      # raw TCP iperf3 on VM1
DERP_BYPASS_PORT=9998     # DERP direct (no xray) on VM1
XRAY_DERP_PORT=443        # xray inbound on VM1

echo "=== XRAY DERP performance test client ==="
echo "Server         : $SERVER_IP"
echo "UUID           : $XRAY_UUID"
echo "Reality SNI    : $REALITY_SNI"
echo "Tunnel path    : $TUNNEL_PATH"
echo ""

# Write xray client config (VLESS+REALITY+XHTTP, stream-up).
cat > "$XRAY_CLIENT_CFG" <<XCFG
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": $XRAY_SOCKS_PORT,
    "protocol": "socks",
    "settings": {"auth": "noauth", "udp": false}
  }],
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "$SERVER_IP",
        "port": $XRAY_DERP_PORT,
        "users": [{"id": "$XRAY_UUID", "encryption": "none"}]
      }]
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "reality",
      "realitySettings": {
        "serverName": "$REALITY_SNI",
        "publicKey": "$XRAY_PUBKEY",
        "shortId": "$XRAY_SHORTID",
        "fingerprint": "chrome"
      },
      "xhttpSettings": {
        "host": "$REALITY_SNI",
        "path": "$TUNNEL_PATH",
        "scMaxEachPostBytes": 32768
      }
    }
  }]
}
XCFG

# Start xray client.
echo "[client] Starting xray SOCKS proxy on 127.0.0.1:$XRAY_SOCKS_PORT"
pkill -f "xray run.*$XRAY_CLIENT_CFG" 2>/dev/null || true
"$XRAY_BIN" run -c "$XRAY_CLIENT_CFG" &>/tmp/xray-client.log &
XRAY_PID=$!
trap "kill $XRAY_PID 2>/dev/null; pkill -f 'socat.*$SOCAT_BRIDGE_PORT' 2>/dev/null; true" EXIT
sleep 2  # give xray time to start

header() { echo ""; echo "──────────────────────────────────────"; echo "  $*"; echo "──────────────────────────────────────"; }

# ── Test 1: Raw TCP baseline ──────────────────────────────────────
header "Test 1: Raw TCP baseline (no xray, no DERP)"
iperf3 -c "$SERVER_IP" -p $DERP_IPERF_PORT -t $IPERF_DURATION --connect-timeout 5000 || \
    echo "WARN: Test 1 failed (iperf3 server not running?)"

# ── Test 2: Direct DERP (no xray) ────────────────────────────────
header "Test 2: Direct DERP port (no xray) — isolates DERP/loopback overhead"
iperf3 -c "$SERVER_IP" -p $DERP_BYPASS_PORT -t $IPERF_DURATION --connect-timeout 5000 || \
    echo "WARN: Test 2 failed (socat bypass not running on server?)"

# ── Test 3: Upload through xray ──────────────────────────────────
header "Test 3: Upload through xray tunnel (client→server)"
pkill -f "socat.*$SOCAT_BRIDGE_PORT" 2>/dev/null || true
# Bridge iperf3 traffic through the xray SOCKS5 proxy.
socat TCP-LISTEN:$SOCAT_BRIDGE_PORT,reuseaddr,fork \
    SOCKS4A:127.0.0.1:$SERVER_IP:$DERP_BYPASS_PORT,socksport=$XRAY_SOCKS_PORT &
SOCAT_PID=$!
sleep 1
iperf3 -c 127.0.0.1 -p $SOCAT_BRIDGE_PORT -t $IPERF_DURATION --connect-timeout 5000 || \
    echo "WARN: Test 3 failed"
kill $SOCAT_PID 2>/dev/null || true

# ── Test 4: Download through xray ────────────────────────────────
header "Test 4: Download through xray tunnel (server→client, -R)"
pkill -f "socat.*$SOCAT_BRIDGE_PORT" 2>/dev/null || true
socat TCP-LISTEN:$SOCAT_BRIDGE_PORT,reuseaddr,fork \
    SOCKS4A:127.0.0.1:$SERVER_IP:$DERP_BYPASS_PORT,socksport=$XRAY_SOCKS_PORT &
SOCAT_PID=$!
sleep 1
iperf3 -c 127.0.0.1 -p $SOCAT_BRIDGE_PORT -t $IPERF_DURATION -R --connect-timeout 5000 || \
    echo "WARN: Test 4 failed"
kill $SOCAT_PID 2>/dev/null || true

# ── RTT / latency snapshot ────────────────────────────────────────
header "RTT comparison"
echo "Raw ping to server:"
ping -c 5 -q "$SERVER_IP" 2>/dev/null || echo "(ping blocked)"

echo ""
echo "DERP latency-check via xray:"
socat TCP-LISTEN:$SOCAT_BRIDGE_PORT,reuseaddr,fork \
    SOCKS4A:127.0.0.1:$SERVER_IP:8080,socksport=$XRAY_SOCKS_PORT &
SOCAT_PID=$!
sleep 1
curl -s -o /dev/null -w "  connect: %{time_connect}s  TTFB: %{time_starttransfer}s  total: %{time_total}s\n" \
    --max-time 5 "http://127.0.0.1:$SOCAT_BRIDGE_PORT/derp/latency-check" || echo "  (no response)"
kill $SOCAT_PID 2>/dev/null || true

# ── Socket stats during xray connection ──────────────────────────
header "TCP socket stats for xray connection (ss -tni)"
socat TCP-LISTEN:$SOCAT_BRIDGE_PORT,reuseaddr,fork \
    SOCKS4A:127.0.0.1:$SERVER_IP:$DERP_BYPASS_PORT,socksport=$XRAY_SOCKS_PORT &
SOCAT_PID=$!
sleep 1
# Run short iperf in background while capturing ss output.
iperf3 -c 127.0.0.1 -p $SOCAT_BRIDGE_PORT -t 5 --connect-timeout 5000 &>/dev/null &
IPERF_PID=$!
sleep 1
echo "ss output (look at cwnd, rtt, rcv_space, snd_buf):"
ss -tni "dport = :$XRAY_DERP_PORT or sport = :$XRAY_DERP_PORT" 2>/dev/null || \
    ss -tni "dst $SERVER_IP" 2>/dev/null || echo "  (no matching sockets)"
wait $IPERF_PID 2>/dev/null || true
kill $SOCAT_PID 2>/dev/null || true

header "Done — check /tmp/xray-client.log for xray errors"
echo "Interpretation guide:"
echo "  Test1 ≈ Test2 → DERP overhead is negligible"
echo "  Test2 ≫ Test3 → xray XHTTP is the bottleneck (stream-up fix should close this gap)"
echo "  Test3 ≈ Test4 → upload and download are symmetric"
echo "  Small cwnd in ss → TCP window not full; increase kernel tcp buffer sizes"
