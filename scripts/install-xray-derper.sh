#!/bin/bash
set -e

derperIP=$1
if [ -z "$derperIP" ]; then
  echo "Usage: $0 <DERP Server IP>"
  exit 1
fi

# 1. System Updates & Optimization
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl socat

# 2. Enable TCP BBR and IP forwarding
# BBR improves throughput for the xray tunnel.
# IP forwarding is required when this server is used as a Tailscale exit node;
# without it the kernel silently drops forwarded packets.
echo "net.core.default_qdisc=fq" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 3. Install DERPer binary from github release
curl -LO "https://github.com/cylonix/cylonix/releases/latest/download/derper"
sudo mv derper /usr/local/bin/derper
sudo chmod +x /usr/local/bin/derper

# 4. Install Xray-core
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# 5. Generate Security Credentials
UUID=$(/usr/local/bin/xray uuid)
KEYS=$(/usr/local/bin/xray x25519)
PRIVATE_KEY=$(echo "$KEYS" | grep "PrivateKey" | awk '{print $2}')
PUBLIC_KEY=$(echo "$KEYS" | grep "Password" | awk '{print $2}')
SHORT_ID=$(openssl rand -hex 4)

# 6. Configure Xray Sidecar
cat <<EOF | sudo tee /usr/local/etc/xray/config.json
{
  "inbounds": [{
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "$UUID" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "www.microsoft.com:443",
        "serverNames": ["www.microsoft.com"],
        "xver": 0,
        "privateKey": "$PRIVATE_KEY",
        "shortIds": ["$SHORT_ID"]
      },
      "xhttpSettings": {
        "mode": "stream-up",
        "host": "www.microsoft.com",
        "path": "/cylonix-derp-tunnel",
        "scStreamUpServerSecs": "3600-7200",
        "scMinPostsIntervalMs": 0
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {
      "redirect": "127.0.0.1:8080"
    }
  }]
}
EOF

# 7. Create DERP Systemd Service
cat <<EOF | sudo tee /etc/systemd/system/derp.service
[Unit]
Description=Cylonix DERP Server
After=network.target

[Service]
ExecStart=/usr/local/bin/derper -hostname $derperIP -a :8080 -http-port 8081
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

# 8. Firewall — block unsolicited incoming UDP but allow DNS.
# REALITY needs to reach the dest host (www.microsoft.com:443) for its
# fallback/authentication flow, which requires DNS resolution over UDP.
# A blanket "iptables -A INPUT -p udp -j DROP" blocks DNS responses and
# breaks the REALITY handshake (connection reset by peer).
#
# We need to allow:
#   - UDP on loopback (systemd-resolved uses 127.0.0.53 over UDP)
#   - Established/related UDP (responses to outgoing DNS queries)
# Then drop all other incoming UDP.
#
# Note: The ts-input chain (from tailscaled) is processed first via
# "-A INPUT -j ts-input".  Traffic that doesn't match ts-input rules
# RETURNs to the main INPUT chain where our rules take effect.
echo "Configuring iptables UDP rules..."

# Remove any existing blanket UDP DROP to avoid duplicates
while iptables -D INPUT -p udp -j DROP 2>/dev/null; do :; done
# Remove old conntrack rule if present
iptables -D INPUT -p udp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
# Remove old loopback rule if present
iptables -D INPUT -i lo -p udp -j ACCEPT 2>/dev/null || true

# Add rules in order after the ts-input jump:
# 1. Allow all UDP on loopback (for systemd-resolved on 127.0.0.53)
# 2. Allow established/related UDP (DNS responses from external resolvers)
# 3. Drop everything else
iptables -A INPUT -i lo -p udp -j ACCEPT
iptables -A INPUT -p udp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p udp -j DROP
echo "  ✓ iptables: incoming UDP blocked (loopback + DNS responses allowed)"

# 9. Start Services
sudo systemctl daemon-reload
sudo systemctl enable xray derp
sudo systemctl restart xray derp

echo "--------------------------------------------------"
echo "DEPLOYMENT COMPLETE"
echo "Relay IP: $(curl -s ifconfig.me)"
echo "Xray UUID: $UUID"
echo "Reality Private Key: $PRIVATE_KEY"
echo "Reality Public Key: $PUBLIC_KEY"
echo "Reality Short ID: $SHORT_ID"
echo "XHTTP Path: /cylonix-derp-tunnel"
echo "--------------------------------------------------"
echo ""
echo "To test from a client machine, run:"
echo "  ./test-xray-derper.sh $(curl -s ifconfig.me) $UUID $PUBLIC_KEY $SHORT_ID"
echo "--------------------------------------------------"
