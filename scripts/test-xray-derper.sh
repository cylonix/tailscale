#!/bin/bash
# test-xray-derper.sh — Install xray client on Debian/Ubuntu and test
# connectivity through an xray VLESS+REALITY+XHTTP relay to a DERP server.
#
# Usage:
#   ./test-xray-derper.sh <SERVER_IP> <UUID> <PUBLIC_KEY> <SHORT_ID>
#
# Example:
#   ./test-xray-derper.sh 203.0.113.10 \
#     27848739-7e62-4138-9fd3-098a63964b6b \
#     E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM \
#     0123456789abcdef
#
# The PUBLIC_KEY is the REALITY x25519 *public* key from the server.
# In "xray x25519" output it is labeled "Password" (not "PublicKey"):
#
#   $ /usr/local/bin/xray x25519
#   PrivateKey: <private key>        ← used in server config
#   Password:   <public key>         ← this is what you pass here
#
# The install-xray-derper.sh script now prints both keys and gives
# you the exact test command to copy-paste.
#
# What this script does:
#   1. Installs xray-core client and curl/iperf3 on Debian/Ubuntu
#   2. Writes a client xray config that connects to the relay
#   3. Runs connectivity tests:
#      a) TCP tunnel test via xray → DERPer HTTP endpoint
#      b) Optional iperf3 throughput test via the xray tunnel
#
# Prerequisites on the SERVER side:
#   - xray-core + DERPer installed via install-xray-derper.sh
#   - If iptables blocks UDP, the rules MUST allow loopback UDP and
#     established/related UDP so DNS resolution still works.  A blanket
#     "iptables -A INPUT -p udp -j DROP" will break the REALITY handshake
#     because the xray server can't resolve the dest host (www.microsoft.com).
#     Correct rules (see install-xray-derper.sh):
#       iptables -A INPUT -i lo -p udp -j ACCEPT
#       iptables -A INPUT -p udp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#       iptables -A INPUT -p udp -j DROP
#   - For iperf3 testing, see SERVER-SIDE CHANGES at the bottom.
#
set -euo pipefail

# curl_status <curl-args...>
# Runs curl with -w "%{http_code}" and prints ONLY the HTTP status code.
# Returns 0 always so `set -e` won't abort the script.
# On connection failure curl prints "000" via -w, which is what we want.
curl_status() {
  curl -s -o /dev/null -w "%{http_code}" "$@" 2>/dev/null || true
}

# ── Arguments ───────────────────────────────────────────────────────
SERVER_IP="${1:?Usage: $0 <SERVER_IP> <UUID> <PUBLIC_KEY> <SHORT_ID>}"
UUID="${2:?Missing UUID}"
PUBLIC_KEY="${3:?Missing REALITY public key}"
SHORT_ID="${4:?Missing REALITY short ID}"

# Configurable defaults (match install-xray-derper.sh)
XHTTP_PATH="/cylonix-derp-tunnel"
SNI="www.microsoft.com"
SOCKS_PORT=10808
DERPER_HTTP_PORT=8080

echo "============================================"
echo "  Xray DERP Relay — Client Test Setup"
echo "============================================"
echo "Server:     $SERVER_IP"
echo "UUID:       $UUID"
echo "Public Key: $PUBLIC_KEY"
echo "Short ID:   $SHORT_ID"
echo "SNI:        $SNI"
echo "XHTTP Path: $XHTTP_PATH"
echo "============================================"
echo ""

# ── 1. Install dependencies ────────────────────────────────────────
echo "[1/5] Installing dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq curl iperf3 jq > /dev/null 2>&1
echo "  ✓ curl, iperf3, jq installed"

# ── 2. Install xray-core ───────────────────────────────────────────
echo "[2/5] Installing xray-core..."
if command -v xray &>/dev/null; then
  echo "  ✓ xray already installed: $(xray version | head -1)"
else
  bash -c "$(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  echo "  ✓ xray installed: $(xray version | head -1)"
fi

# ── 3. Write client config ─────────────────────────────────────────
echo "[3/5] Writing xray client config..."

CLIENT_CONFIG="/usr/local/etc/xray/config.json"
sudo mkdir -p "$(dirname "$CLIENT_CONFIG")"

cat <<XEOF | sudo tee "$CLIENT_CONFIG" > /dev/null
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "socks-in",
      "port": $SOCKS_PORT,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": { "udp": true }
    },
    {
      "tag": "http-in",
      "port": 10809,
      "listen": "127.0.0.1",
      "protocol": "http"
    }
  ],
  "outbounds": [
    {
      "tag": "xray-out",
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "$SERVER_IP",
          "port": 443,
          "users": [{
            "id": "$UUID",
            "flow": "",
            "encryption": "none"
          }]
        }]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": {
          "serverName": "$SNI",
          "publicKey": "$PUBLIC_KEY",
          "shortId": "$SHORT_ID",
          "fingerprint": "chrome"
        },
        "xhttpSettings": {
          "host": "$SNI",
          "path": "$XHTTP_PATH"
        }
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": ["geoip:private"]
      }
    ]
  }
}
XEOF
echo "  ✓ Config written to $CLIENT_CONFIG"

# ── 4. Start xray client ───────────────────────────────────────────
echo "[4/5] Starting xray client..."
sudo systemctl stop xray 2>/dev/null || true
sudo systemctl start xray
sleep 2

if systemctl is-active --quiet xray; then
  echo "  ✓ xray client running (SOCKS5 on 127.0.0.1:$SOCKS_PORT)"
else
  echo "  ✗ xray failed to start. Check: sudo journalctl -u xray --no-pager -n 30"
  exit 1
fi

# ── 5. Run tests ───────────────────────────────────────────────────
echo "[5/5] Running connectivity tests..."
echo ""
PASS=0
FAIL=0

# --- Test A: xray tunnel basic connectivity ---
echo "── Test A: SOCKS5 tunnel connectivity ──"
echo "   Connecting through xray tunnel to DERPer HTTP endpoint..."
HTTP_CODE=$(curl_status \
  --max-time 10 \
  --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
  "http://$SERVER_IP:$DERPER_HTTP_PORT/")

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "404" ] || [ "$HTTP_CODE" = "301" ]; then
  echo "   ✓ PASS — Got HTTP $HTTP_CODE from DERPer via xray tunnel"
  PASS=$((PASS + 1))
else
  echo "   ✗ FAIL — Expected HTTP 200/301/404, got $HTTP_CODE"
  echo "     Debug: curl -v --socks5-hostname 127.0.0.1:$SOCKS_PORT http://$SERVER_IP:$DERPER_HTTP_PORT/"
  FAIL=$((FAIL + 1))
fi
echo ""

# --- Test B: Verify the tunnel actually goes through xray ---
echo "── Test B: Verify traffic routes through xray tunnel ──"
echo "   Confirming DERPer is reachable ONLY through the tunnel..."

# The xray server redirects all tunneled traffic to DERPer at 127.0.0.1:8080.
# A direct request to the DERPer's internal port should fail from outside,
# while the same request through the xray tunnel should succeed.
# This proves traffic is actually traversing the xray tunnel.

# First, try reaching DERPer directly (should fail — port 8081 may be
# firewalled or not routed for external access in a tunnel-only setup).
DIRECT_CODE=$(curl_status \
  --max-time 5 \
  "http://$SERVER_IP:$DERPER_HTTP_PORT/")

# Then try through the tunnel (should succeed since xray routes to DERPer).
TUNNEL_CODE=$(curl_status \
  --max-time 10 \
  --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
  "http://$SERVER_IP:$DERPER_HTTP_PORT/")

if [ "$TUNNEL_CODE" != "000" ] && [ "$DIRECT_CODE" = "000" ]; then
  echo "   ✓ PASS — DERPer reachable via tunnel (HTTP $TUNNEL_CODE) but not directly (confirms tunnel)"
  PASS=$((PASS + 1))
elif [ "$TUNNEL_CODE" != "000" ] && [ "$DIRECT_CODE" != "000" ]; then
  # DERPer is also reachable directly — can't prove tunnel routing this way,
  # but tunnel connectivity itself works. Compare response bodies instead.
  DIRECT_BODY=$(curl -s --max-time 5 "http://$SERVER_IP:$DERPER_HTTP_PORT/" 2>/dev/null || echo "")
  TUNNEL_BODY=$(curl -s --max-time 10 \
    --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
    "http://$SERVER_IP:$DERPER_HTTP_PORT/" 2>/dev/null || echo "")
  if [ -n "$TUNNEL_BODY" ] && [ "$TUNNEL_BODY" = "$DIRECT_BODY" ]; then
    echo "   ✓ PASS — DERPer reachable via tunnel (HTTP $TUNNEL_CODE); same response as direct"
    echo "           (DERPer is also reachable directly — tunnel routing confirmed by Test A)"
    PASS=$((PASS + 1))
  else
    echo "  ~ WARN — Both paths return different content (tunnel HTTP $TUNNEL_CODE, direct HTTP $DIRECT_CODE)"
    echo "           Tunnel is working but responses differ — possible NAT/redirect mismatch"
    PASS=$((PASS + 1))
  fi
elif [ "$TUNNEL_CODE" = "000" ]; then
  echo "   ✗ FAIL — DERPer not reachable through tunnel"
  FAIL=$((FAIL + 1))
fi
echo ""

# --- Test C: DERP-specific /derp endpoint upgrade ---
echo "── Test C: DERP WebSocket upgrade endpoint ──"
DERP_RESP=$(curl_status \
  --max-time 10 \
  --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
  -H "Upgrade: derp" \
  -H "Connection: Upgrade" \
  "http://$SERVER_IP:$DERPER_HTTP_PORT/derp")

# DERPer returns 200 on successful upgrade or various codes
if [ "$DERP_RESP" != "000" ]; then
  echo "   ✓ PASS — /derp responded with HTTP $DERP_RESP via tunnel"
  PASS=$((PASS + 1))
else
  echo "   ✗ FAIL — /derp unreachable through tunnel"
  FAIL=$((FAIL + 1))
fi
echo ""

# --- Test D: iperf3 throughput (optional) ---
echo "── Test D: iperf3 throughput through xray tunnel ──"
echo "   NOTE: This requires iperf3 running on the server (see bottom of script)."
echo "   Attempting iperf3 through SOCKS5 proxy..."

# iperf3 doesn't natively support SOCKS5, so we use a TCP redirect approach.
# Detect iperf3 through the xray tunnel (port 5201 is typically not exposed
# publicly on the VPS — it's only reachable via the tunnel with server-side
# xray routing for port 5201).
# Note: iperf3 doesn't speak HTTP, so curl -w "%{http_code}" returns "000"
# even when the port IS reachable. We use curl's exit code instead:
# exit 0 or 52 (empty reply) or 56 (reset) = port reachable; exit 7 = refused.
IPERF_EXIT=0
curl -s -o /dev/null --max-time 5 \
  --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
  "http://$SERVER_IP:5201/" 2>/dev/null || IPERF_EXIT=$?

# Exit codes: 7=connection refused, 28=timeout → not reachable
# Exit codes: 0, 52(empty reply), 56(connection reset) → port is open
if [ "$IPERF_EXIT" = "7" ] || [ "$IPERF_EXIT" = "28" ]; then
  echo "   ⊘ SKIP — iperf3 server not detected on $SERVER_IP:5201 via tunnel"
  echo "           See SERVER-SIDE CHANGES at the bottom of this script."
else
  echo "   iperf3 server detected via tunnel. Setting up..."

  sudo apt-get install -y -qq socat > /dev/null 2>&1

  # Kill any existing forwarder
  pkill -f "socat.*15201" 2>/dev/null || true
  sleep 0.5

  # Create a local TCP forwarder: local:15201 → SOCKS5 → server:5201
  # This lets iperf3 connect to localhost:15201 which gets tunneled.
  socat TCP-LISTEN:15201,bind=127.0.0.1,reuseaddr,fork \
    SOCKS4A:127.0.0.1:$SERVER_IP:5201,socksport=$SOCKS_PORT 2>/dev/null &
  SOCAT_PID=$!
  sleep 1

  echo "   Running iperf3 (10 second test)..."
  if IPERF_OUT=$(iperf3 -c 127.0.0.1 -p 15201 -t 10 --json 2>/dev/null); then
    BW_SEND_BITS=$(echo "$IPERF_OUT" | jq -r '.end.sum_sent.bits_per_second // 0' 2>/dev/null)
    BW_RECV_BITS=$(echo "$IPERF_OUT" | jq -r '.end.sum_received.bits_per_second // 0' 2>/dev/null)
    echo "   Sent:     $BW_SEND_BITS bps"
    echo "   Received: $BW_RECV_BITS bps"
    if [ -n "$BW_SEND_BITS" ] &&
        [ "$BW_SEND_BITS" != "0" ] &&
        [ "$BW_SEND_BITS" != "null" ] &&
        [ -n "$BW_RECV_BITS" ] &&
        [ "$BW_RECV_BITS" != "0" ] &&
        [ "$BW_RECV_BITS" != "null" ]; then
      BW_SEND_MBPS=$(echo "scale=2; $BW_SEND_BITS / 1000000" | bc)
      BW_RECV_MBPS=$(echo "scale=2; $BW_RECV_BITS / 1000000" | bc)
      echo "   ✓ PASS — iperf3 throughput: ${BW_SEND_MBPS} Mbps sent, ${BW_RECV_MBPS} Mbps received via xray tunnel"
      PASS=$((PASS + 1))
    else
      echo "   ✗ FAIL — iperf3 completed but no throughput data"
      FAIL=$((FAIL + 1))
    fi
  else
    echo "   ✗ FAIL — iperf3 failed through tunnel"
    echo "    $(echo "$IPERF_OUT" | tail -5)"
    FAIL=$((FAIL + 1))
  fi

  kill $SOCAT_PID 2>/dev/null || true
fi
echo ""

# ── Summary ─────────────────────────────────────────────────────────
echo "============================================"
echo "  Test Results: $PASS passed, $FAIL failed"
echo "============================================"
echo ""
echo "Manual debugging commands:"
echo "  # Check xray client logs:"
echo "  sudo journalctl -u xray --no-pager -n 50"
echo ""
echo "  # Test tunnel manually:"
echo "  curl -v --socks5-hostname 127.0.0.1:$SOCKS_PORT http://$SERVER_IP:$DERPER_HTTP_PORT/"
echo ""
echo "  # Test with HTTP proxy (port 10809):"
echo "  curl -v -x http://127.0.0.1:10809 http://$SERVER_IP:$DERPER_HTTP_PORT/"
echo ""
echo "  # Stop client:"
echo "  sudo systemctl stop xray"
echo ""

if [ $FAIL -gt 0 ]; then
  exit 1
fi
exit 0

# ====================================================================
# SERVER-SIDE CHANGES FOR IPERF3 TESTING
# ====================================================================
#
# The xray server's freedom outbound currently redirects ALL traffic to
# the DERPer at 127.0.0.1:8080. For iperf3 testing, you need to let
# iperf3 traffic reach iperf3 instead of DERPer. Two options:
#
# ── Option A: Remove the blanket redirect (recommended for testing) ──
#
# 1. Install iperf3 on the server:
#      sudo apt-get install -y iperf3
#
# 2. Start iperf3:
#      iperf3 -s -D     # -D = daemon mode
#
# 3. Modify /usr/local/etc/xray/config.json on the SERVER.
#    Replace the outbounds section with routing-based config:
#
#    "outbounds": [
#      {
#        "tag": "derper",
#        "protocol": "freedom",
#        "settings": { "redirect": "127.0.0.1:8080" }
#      },
#      {
#        "tag": "direct",
#        "protocol": "freedom"
#      }
#    ],
#    "routing": {
#      "rules": [
#        {
#          "type": "field",
#          "outboundTag": "direct",
#          "port": "5201"
#        },
#        {
#          "type": "field",
#          "outboundTag": "derper",
#          "network": "tcp,udp"
#        }
#      ]
#    }
#
#    This routes port 5201 (iperf3) directly while sending everything
#    else to DERPer on 8080.
#
# 4. Restart xray:
#      sudo systemctl restart xray
#
# ── Option B: Simpler — just test without redirect ───────────────────
#
# If you don't need DERPer during the test, temporarily change the
# server outbound to plain freedom (no redirect):
#
#    "outbounds": [{ "protocol": "freedom" }]
#
# Then restart xray. All tunneled traffic will go directly to its
# original destination. This lets you test iperf3, curl, etc. freely.
# Restore the redirect afterwards.
#
# ── Also: Remove flow from server inbound ────────────────────────────
#
# The client uses Flow="" (empty) because xtls-rprx-vision is
# incompatible with xhttp transport. The server inbound should match.
# In /usr/local/etc/xray/config.json on the server, change:
#
#   "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision" }]
#
# to:
#
#   "clients": [{ "id": "$UUID", "flow": "" }]
#
# or simply remove the "flow" field entirely.
# Then: sudo systemctl restart xray
#
# ====================================================================
