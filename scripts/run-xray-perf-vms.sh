#!/bin/bash
# run-xray-perf-vms.sh — spin up two local QEMU VMs and run the XRAY DERP
# throughput test (test-xray-perf.sh) to validate the stream-up mode fix.
#
# VM1 runs xray-core (VLESS+REALITY+XHTTP, port 443) forwarding to iperf3 (:5201).
# VM2 runs the client side of test-xray-perf.sh.
# VMs communicate directly via a point-to-point QEMU socket LAN (10.100.0.0/30).
#
# Prerequisites (install once):
#   macOS:  brew install qemu cdrtools       # cdrtools gives mkisofs
#   Linux:  apt install qemu-system-x86-64 qemu-utils genisoimage iperf3 socat
#
# Usage:
#   ./scripts/run-xray-perf-vms.sh           # run the full test
#   ./scripts/run-xray-perf-vms.sh clean     # delete cached disk images

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Tunables ──────────────────────────────────────────────────────────────────
CACHE_DIR="${XRAY_PERF_CACHE:-/Volumes/2TB-1/.cache/cylonix/xray-perf-vms}"
VM1_SSH_PORT=12201
VM2_SSH_PORT=12202
LAN_SOCKET_PORT=12300      # QEMU point-to-point socket for VM-to-VM LAN
VM1_LAN_IP="10.100.0.1"
VM2_LAN_IP="10.100.0.2"
VM1_USER_MAC="52:54:00:aa:00:01"   # user-NAT interface (DHCP, SSH from host)
VM2_USER_MAC="52:54:00:aa:00:02"
VM1_MAC="52:54:00:ab:cd:01"        # LAN interface (static, VM-to-VM)
VM2_MAC="52:54:00:ab:cd:02"
VM_MEMORY="1536"
VM_CPUS="2"
DISK_SIZE="10G"
SSH_BOOT_TIMEOUT=600       # seconds to wait for SSH after QEMU start
IPERF_DURATION=15

# ── Architecture / image selection ────────────────────────────────────────────
HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"

case "$HOST_ARCH" in
    arm64|aarch64)
        QEMU_BIN="${QEMU_BIN:-qemu-system-aarch64}"
        QEMU_MACHINE_BASE="virt"
        QEMU_NET_DEV="virtio-net-device"
        UBUNTU_IMAGE_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-arm64.img"
        UBUNTU_IMAGE_FILE="jammy-arm64.img"
        ;;
    *)
        QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
        QEMU_MACHINE_BASE="q35"
        QEMU_NET_DEV="virtio-net-pci"
        UBUNTU_IMAGE_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
        UBUNTU_IMAGE_FILE="jammy-amd64.img"
        ;;
esac

case "$HOST_OS" in
    Linux)  QEMU_ACCEL="kvm" ;;
    Darwin) QEMU_ACCEL="hvf" ;;
    *)      QEMU_ACCEL="tcg" ;;
esac
QEMU_CPU="host"
[ "$QEMU_ACCEL" = "tcg" ] && QEMU_CPU="max"
QEMU_MACHINE="${QEMU_MACHINE_BASE},accel=${QEMU_ACCEL}"

# ── Helpers ───────────────────────────────────────────────────────────────────
die()  { echo "ERROR: $*" >&2; exit 1; }
log()  { echo "$(date '+%H:%M:%S') $*"; }
sep()  { echo ""; echo "──────────────────────────────────────────────────────"; echo "  $*"; echo "──────────────────────────────────────────────────────"; }

need() {
    command -v "$1" &>/dev/null || die "missing: $1
  macOS:  brew install $2
  Linux:  apt install $3"
}

iso_tool() {
    for t in genisoimage mkisofs; do
        command -v "$t" &>/dev/null && echo "$t" && return
    done
    die "no ISO tool found
  macOS:  brew install cdrtools    (provides mkisofs)
  Linux:  apt install genisoimage"
}

vm_ssh() {
    local port="$1"; shift
    ssh -q \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -i "$SSH_KEY" \
        -p "$port" \
        root@127.0.0.1 "$@"
}

vm_scp() {
    local port="$1" src="$2" dst="$3"
    scp -q \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -i "$SSH_KEY" \
        -P "$port" \
        "$src" "root@127.0.0.1:$dst"
}

wait_for_ssh() {
    local port="$1" name="$2"
    local deadline=$(( $(date +%s) + SSH_BOOT_TIMEOUT ))
    log "Waiting for $name SSH on port $port (up to ${SSH_BOOT_TIMEOUT}s)..."
    while true; do
        vm_ssh "$port" true 2>/dev/null && { log "$name is up"; return 0; }
        [ "$(date +%s)" -lt "$deadline" ] || die "$name did not become reachable within ${SSH_BOOT_TIMEOUT}s"
        sleep 3
    done
}

make_seed_iso() {
    local outfile="$1" metafile="$2" userfile="$3" netcfg="$4"
    local args=("-output" "$outfile" "-volid" "cidata" "-joliet" "-rock"
                "$metafile" "$userfile")
    [ -n "$netcfg" ] && args+=("$netcfg")
    "$(iso_tool)" "${args[@]}" 2>/dev/null
}

find_arm64_firmware() {
    for f in \
        /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
        /usr/local/share/qemu/edk2-aarch64-code.fd \
        /usr/share/qemu/edk2-aarch64-code.fd; do
        [ -f "$f" ] && echo "$f" && return
    done
}

qemu_extra_args() {
    # Returns arch-specific extra args (UEFI firmware for arm64).
    local arch="$HOST_ARCH" args=()
    if [[ "$arch" == "arm64" || "$arch" == "aarch64" ]]; then
        local fw
        fw="$(find_arm64_firmware)" || true
        if [ -n "$fw" ]; then
            args+=(-bios "$fw")
        else
            log "WARN: no aarch64 UEFI firmware found — QEMU boot may fail"
            log "      Install: brew install qemu  (includes edk2 firmware)"
        fi
    else
        args+=(-smbios "type=1,serial=ds=nocloud")
    fi
    echo "${args[@]:-}"
}

start_vm() {
    local name="$1" ssh_port="$2" user_mac="$3" lan_mac="$4" overlay="$5" seed_iso="$6"
    local socket_mode="$7"   # "listen" (VM1) or "connect" (VM2)
    local lan_netdev extra_args
    if [ "$socket_mode" = "listen" ]; then
        lan_netdev="socket,listen=127.0.0.1:${LAN_SOCKET_PORT},id=lan"
    else
        lan_netdev="socket,connect=127.0.0.1:${LAN_SOCKET_PORT},id=lan"
    fi
    extra_args="$(qemu_extra_args)"

    log "Starting $name (SSH→127.0.0.1:$ssh_port, LAN $socket_mode)"
    # shellcheck disable=SC2086
    "$QEMU_BIN" \
        -machine "$QEMU_MACHINE" \
        -cpu "$QEMU_CPU" \
        -m "$VM_MEMORY" \
        -smp "$VM_CPUS" \
        -nographic \
        -netdev "user,hostfwd=::${ssh_port}-:22,id=net0" \
        -device "${QEMU_NET_DEV},netdev=net0,mac=${user_mac}" \
        -netdev "$lan_netdev" \
        -device "${QEMU_NET_DEV},netdev=lan,mac=${lan_mac}" \
        -drive "file=${overlay},if=virtio,format=qcow2" \
        -cdrom "${seed_iso}" \
        $extra_args \
        >> "${WORK_DIR}/${name}.log" 2>&1 &
    echo $!
}

cloud_user_data() {
    local pub_key="$1" user_mac="$2" lan_mac="$3"
    # Network config is in the separate network-config file on the seed ISO;
    # that file is processed by cloud-init-local before networkd/DHCP starts.
    cat <<YAML
#cloud-config
users:
  - name: root
    ssh_authorized_keys:
      - ${pub_key}
YAML
}

# ── Clean subcommand ──────────────────────────────────────────────────────────
if [ "${1:-}" = "clean" ]; then
    log "Removing cache at $CACHE_DIR"
    rm -rf "$CACHE_DIR"
    log "Done"
    exit 0
fi

# ── Preflight checks ──────────────────────────────────────────────────────────
need "$QEMU_BIN"    "qemu"       "qemu-system-x86-64 qemu-system-arm"
need "qemu-img"     "qemu"       "qemu-utils"
need "ssh"          "(builtin)"  "openssh-client"
need "scp"          "(builtin)"  "openssh-client"
iso_tool > /dev/null  # will die with install hint if missing

for port in $VM1_SSH_PORT $VM2_SSH_PORT $LAN_SOCKET_PORT; do
    if nc -z -w1 127.0.0.1 "$port" 2>/dev/null; then
        die "Port $port is already in use. Kill lingering QEMU processes first: pkill -9 $QEMU_BIN"
    fi
done

log "Host: $HOST_OS/$HOST_ARCH  QEMU: $QEMU_BIN  accel: $QEMU_ACCEL"

# ── Work directory ────────────────────────────────────────────────────────────
mkdir -p "/Volumes/2TB-1/.tmp"
WORK_DIR="$(mktemp -d "/Volumes/2TB-1/.tmp/xray-perf-vms.XXXXXX")"
trap 'cleanup' EXIT INT TERM

cleanup() {
    log "Cleaning up..."
    kill "${VM1_PID:-}" "${VM2_PID:-}" 2>/dev/null || true
    wait "${VM1_PID:-}" "${VM2_PID:-}" 2>/dev/null || true
    log "VMs stopped. Logs: ${WORK_DIR}/vm1.log  ${WORK_DIR}/vm2.log"
    log "Run with 'clean' to remove cached disk images."
}

# ── Download base image (cached) ──────────────────────────────────────────────
mkdir -p "$CACHE_DIR"
BASE_IMG="${CACHE_DIR}/${UBUNTU_IMAGE_FILE}"
if [ ! -f "$BASE_IMG" ]; then
    log "Downloading Ubuntu 22.04 cloud image → $BASE_IMG (once, ~600 MB)..."
    curl -fL --progress-bar -o "${BASE_IMG}.tmp" "$UBUNTU_IMAGE_URL"
    mv "${BASE_IMG}.tmp" "$BASE_IMG"
    log "Download complete."
else
    log "Using cached image: $BASE_IMG"
fi

# ── SSH key pair ──────────────────────────────────────────────────────────────
SSH_KEY="${WORK_DIR}/id_ed25519"
ssh-keygen -q -t ed25519 -N "" -f "$SSH_KEY"
SSH_PUB_KEY="$(cat "${SSH_KEY}.pub")"

# ── Create overlays and seed ISOs ─────────────────────────────────────────────
for vm in vm1 vm2; do
    qemu-img create -q -f qcow2 -b "$BASE_IMG" -F qcow2 "${WORK_DIR}/${vm}.qcow2"
    qemu-img resize -q "${WORK_DIR}/${vm}.qcow2" "$DISK_SIZE"
done

for vm in vm1 vm2; do
    user_mac_var="$(echo "$vm" | tr '[:lower:]' '[:upper:]')_USER_MAC"
    user_mac="${!user_mac_var}"
    lan_mac_var="$(echo "$vm" | tr '[:lower:]' '[:upper:]')_MAC"
    lan_mac="${!lan_mac_var}"
    # Files MUST be named exactly "meta-data" and "user-data" — cloud-init
    # NoCloud datasource looks for those exact names on the cidata volume.
    seed_dir="${WORK_DIR}/${vm}-seed"
    mkdir -p "$seed_dir"
    cat > "${seed_dir}/meta-data" <<EOF
instance-id: xray-perf-${vm}
local-hostname: xray-${vm}
EOF
    cloud_user_data "$SSH_PUB_KEY" "$user_mac" "$lan_mac" > "${seed_dir}/user-data"
    # Provide network config as a *separate* network-config file so cloud-init-local
    # processes it before systemd-networkd starts (earlier than the network: stanza
    # inside user-data on some cloud-init versions).
    cat > "${seed_dir}/network-config" <<NETCFG
version: 2
ethernets:
  user-net:
    match:
      macaddress: "${user_mac}"
    dhcp4: true
    optional: false
  lan-net:
    match:
      macaddress: "${lan_mac}"
    dhcp4: false
    optional: true
NETCFG
    make_seed_iso "${WORK_DIR}/${vm}-seed.iso" \
        "${seed_dir}/meta-data" "${seed_dir}/user-data" "${seed_dir}/network-config"
done

# ── Start VMs ─────────────────────────────────────────────────────────────────
# VM1 must start first (it listens on the LAN socket).
VM1_PID="$(start_vm vm1 "$VM1_SSH_PORT" "$VM1_USER_MAC" "$VM1_MAC" \
    "${WORK_DIR}/vm1.qcow2" "${WORK_DIR}/vm1-seed.iso" listen)"
sleep 2  # give VM1's socket a moment before VM2 connects
VM2_PID="$(start_vm vm2 "$VM2_SSH_PORT" "$VM2_USER_MAC" "$VM2_MAC" \
    "${WORK_DIR}/vm2.qcow2" "${WORK_DIR}/vm2-seed.iso" connect)"

wait_for_ssh "$VM1_SSH_PORT" "vm1"
wait_for_ssh "$VM2_SSH_PORT" "vm2"

# ── Configure LAN IPs via SSH (faster than cloud-init runcmd) ────────────────
log "Configuring LAN interfaces..."
configure_lan() {
    local port="$1" mac="$2" ip="$3"
    vm_ssh "$port" bash -s <<SCRIPT
# Find the interface with this MAC (works with any naming scheme: eth0, enp0s1, etc.)
IFACE=\$(ip link | awk -v mac="$mac" '
    /^[0-9]+:/ { split(\$2, a, "@"); iface = a[1]; gsub(/:/, "", iface) }
    /link\/ether/ { if (\$2 == mac) print iface }
')
if [ -z "\$IFACE" ]; then
    echo "WARN: no interface found with mac $mac; showing all interfaces:"
    ip link | awk '/^[0-9]+:/{print} /link\/ether/{print}'
    exit 0
fi
ip addr replace $ip/30 dev "\$IFACE"
ip link set "\$IFACE" up
echo "LAN: \$IFACE -> $ip/30"
SCRIPT
}
configure_lan "$VM1_SSH_PORT" "$VM1_MAC" "$VM1_LAN_IP"
configure_lan "$VM2_SSH_PORT" "$VM2_MAC" "$VM2_LAN_IP"

# ── TCP congestion control ────────────────────────────────────────────────────
# Default to BBR on both VMs for realistic server/client behaviour.
# Override with TCP_CC=cubic (or any available cc) to test alternatives.
TCP_CC="${TCP_CC:-bbr}"
log "Setting TCP congestion control to '${TCP_CC}' on both VMs..."
set_tcp_cc() {
    local port="$1"
    vm_ssh "$port" bash -s <<SCRIPT
# Load tcp_bbr module if needed (Ubuntu 22.04 ships it but doesn't autoload).
if [ "${TCP_CC}" = "bbr" ]; then
    modprobe tcp_bbr 2>/dev/null || true
fi
# Verify the cc is available before setting it.
if grep -qw "${TCP_CC}" /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    sysctl -qw net.ipv4.tcp_congestion_control=${TCP_CC}
    sysctl -qw net.core.default_qdisc=fq
    echo "TCP cc: \$(sysctl -n net.ipv4.tcp_congestion_control)  qdisc: \$(sysctl -n net.core.default_qdisc)"
else
    echo "WARN: '${TCP_CC}' not available; available: \$(cat /proc/sys/net/ipv4/tcp_available_congestion_control)"
fi
SCRIPT
}
set_tcp_cc "$VM1_SSH_PORT"
set_tcp_cc "$VM2_SSH_PORT"

# Simulate WAN conditions via tc netem on the VM-to-VM LAN interface.
# Knobs (all one-way; RTT is 2× delay):
#   WAN_DELAY_MS  — base one-way latency in ms            (default: 100)
#   WAN_JITTER_MS — delay variation (±jitter, normal dist) (default: 0)
#   WAN_LOSS_PCT  — random packet loss percentage           (default: 0)
#
# Example — cross-country worst-case:
#   WAN_DELAY_MS=300 WAN_JITTER_MS=300 WAN_LOSS_PCT=5 ./scripts/run-xray-perf-vms.sh
WAN_DELAY_MS="${WAN_DELAY_MS:-100}"
WAN_JITTER_MS="${WAN_JITTER_MS:-0}"
WAN_LOSS_PCT="${WAN_LOSS_PCT:-0}"

# Build the netem parameter string from the knobs.
_netem_params="${WAN_DELAY_MS}ms"
[ "${WAN_JITTER_MS}" != "0" ] && _netem_params="${_netem_params} ${WAN_JITTER_MS}ms distribution normal"
[ "${WAN_LOSS_PCT}"  != "0" ] && _netem_params="${_netem_params} loss ${WAN_LOSS_PCT}%"

_netem_desc="delay=${WAN_DELAY_MS}ms"
[ "${WAN_JITTER_MS}" != "0" ] && _netem_desc="${_netem_desc} jitter=±${WAN_JITTER_MS}ms"
[ "${WAN_LOSS_PCT}"  != "0" ] && _netem_desc="${_netem_desc} loss=${WAN_LOSS_PCT}%"

log "Adding one-way netem: ${_netem_desc}  (RTT≈$(( WAN_DELAY_MS * 2 ))ms simulated)"
add_netem() {
    local port="$1" mac="$2"
    vm_ssh "$port" bash -s <<SCRIPT
IFACE=\$(ip link | awk -v mac="$mac" '
    /^[0-9]+:/ { split(\$2, a, "@"); iface = a[1]; gsub(/:/, "", iface) }
    /link\/ether/ { if (\$2 == mac) print iface }
')
[ -z "\$IFACE" ] && { echo "WARN: can't find LAN iface for netem"; exit 0; }
tc qdisc replace dev "\$IFACE" root netem delay ${_netem_params}
echo "netem: \$IFACE ${_netem_desc}"
SCRIPT
}
add_netem "$VM1_SSH_PORT" "$VM1_MAC"
add_netem "$VM2_SSH_PORT" "$VM2_MAC"

log "Verifying VM-to-VM LAN reachability..."
vm_ssh "$VM2_SSH_PORT" "ping -c2 -W2 $VM1_LAN_IP" || \
    log "WARN: VM2 cannot ping VM1 on LAN — LAN tests may fail"

# ── Pre-built binaries ────────────────────────────────────────────────────────
# These are built once on the host and SCP-ed to VMs to avoid long compile times.
DERPER_BIN="${DERPER_BIN:-/Volumes/2TB-1/.tmp/derper}"
DERPBENCH_BIN="${DERPBENCH_BIN:-/Volumes/2TB-1/.tmp/derpbench}"
[ -x "$DERPER_BIN" ]   || die "derper binary not found at $DERPER_BIN
  Build: GOOS=linux GOARCH=arm64 GOCACHE=/Volumes/2TB-1/.gocache-local GOTMPDIR=/Volumes/2TB-1/.gotmp ./tool/go build -o /Volumes/2TB-1/.tmp/derper ./cmd/derper"
[ -x "$DERPBENCH_BIN" ] || die "derpbench binary not found at $DERPBENCH_BIN
  Build: GOOS=linux GOARCH=arm64 GOCACHE=/Volumes/2TB-1/.gocache-local GOTMPDIR=/Volumes/2TB-1/.gotmp ./tool/go build -o /Volumes/2TB-1/.tmp/derpbench ./cmd/derpbench"

BENCH_DURATION="${BENCH_DURATION:-15s}"
TUNNEL_PATH="/cylonix-derp-tunnel"
REALITY_SNI="www.microsoft.com"

# ── VM1: install xray-core, run derper + xray server (stream-up) ─────────────
sep "VM1: Setting up derper + xray server (packet-up mode, censorship-safe default)"

log "Copying derper binary to VM1..."
vm_scp "$VM1_SSH_PORT" "$DERPER_BIN" "/usr/local/bin/derper"
vm_ssh "$VM1_SSH_PORT" chmod +x /usr/local/bin/derper

vm_ssh "$VM1_SSH_PORT" bash -s <<'VMSETUP'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl
bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Generate REALITY credentials
UUID=$(/usr/local/bin/xray uuid)
KEYS=$(/usr/local/bin/xray x25519)
PRIVATE_KEY=$(echo "$KEYS" | awk '/PrivateKey/{print $2}')
PUBLIC_KEY=$(echo "$KEYS"  | awk '/Password/{print $2}')
SHORT_ID=$(openssl rand -hex 4)

# xray server: VLESS+REALITY+XHTTP stream-up on :443, forwards to derper :8080
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "$UUID"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "www.microsoft.com:443",
        "serverNames": ["www.microsoft.com"],
        "privateKey": "$PRIVATE_KEY",
        "shortIds": ["$SHORT_ID"]
      },
      "xhttpSettings": {
        "host": "www.microsoft.com",
        "path": "/cylonix-derp-tunnel"
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {"redirect": "127.0.0.1:8080"}
  }]
}
EOF

# Persist credentials for the test client
echo "XRAY_UUID=$UUID"         > /root/xray-creds.env
echo "XRAY_PUBKEY=$PUBLIC_KEY" >> /root/xray-creds.env
echo "XRAY_SHORTID=$SHORT_ID"  >> /root/xray-creds.env

# Start derper on :8080 (no TLS — LAN-only, xray handles TLS on :443)
nohup /usr/local/bin/derper -a :8080 -http-port -1 -hostname 10.100.0.1 \
    -stun=false \
    >/var/log/derper.log 2>&1 &
disown $!

systemctl restart xray
sleep 2
systemctl is-active xray || { journalctl -u xray --no-pager -n 30; exit 1; }
echo "VM1 setup complete (derper on :8080, xray packet-up on :443)"
VMSETUP

# ── VM2: copy derpbench (xray is embedded in the binary — no separate install) ─
sep "VM2: Installing derpbench"

log "Copying derpbench binary to VM2..."
vm_scp "$VM2_SSH_PORT" "$DERPBENCH_BIN" "/usr/local/bin/derpbench"
vm_ssh "$VM2_SSH_PORT" chmod +x /usr/local/bin/derpbench
log "VM2 setup complete (derpbench includes embedded xray-core)"

# ── Retrieve xray credentials from VM1 ───────────────────────────────────────
log "Retrieving xray credentials from VM1..."
eval "$(vm_ssh "$VM1_SSH_PORT" cat /root/xray-creds.env)"
log "  UUID     : $XRAY_UUID"
log "  PubKey   : $XRAY_PUBKEY"
log "  ShortID  : $XRAY_SHORTID"

# derpbench_xray_flags assembles the flags to pass to derpbench for a given
# xray mode ("stream-up" or "packet-up"). If mode is empty, no xray flags are
# emitted and derpbench connects directly.
derpbench_xray_flags() {
    local mode="$1"
    if [ -z "$mode" ]; then
        echo ""
        return
    fi
    echo "-xray-uuid $XRAY_UUID -xray-pubkey $XRAY_PUBKEY -xray-shortid $XRAY_SHORTID -xray-tunnel $TUNNEL_PATH -xray-sni $REALITY_SNI -xray-mode $mode"
}

reconfigure_vm1_derper() {
    local extra_flags="$1"  # e.g. "-allow-parallel-clients" or ""
    vm_ssh "$VM1_SSH_PORT" bash -s <<DERPERSCRIPT
set -euo pipefail
pkill -f 'derper.*:8080' 2>/dev/null || true
sleep 1
nohup /usr/local/bin/derper -a :8080 -http-port -1 -hostname 10.100.0.1 \
    -stun=false $extra_flags \
    >/var/log/derper.log 2>&1 &
disown \$!
sleep 1
pgrep -a derper || { echo "ERROR: derper failed to start"; exit 1; }
echo "VM1 derper restarted with flags: '$extra_flags'"
DERPERSCRIPT
}

reconfigure_vm1_xray() {
    local mode="$1"  # "stream-up" or "packet-up"
    # Read the private key and other creds from the existing config on VM1, then
    # rewrite the full config with the desired xhttpSettings mode.
    vm_ssh "$VM1_SSH_PORT" bash -s <<CFGSCRIPT
set -euo pipefail
PRIVKEY=\$(python3 -c "import json; print(json.load(open('/usr/local/etc/xray/config.json'))['inbounds'][0]['streamSettings']['realitySettings']['privateKey'])")
UUID=\$(python3 -c "import json; print(json.load(open('/usr/local/etc/xray/config.json'))['inbounds'][0]['settings']['clients'][0]['id'])")
SHORTID=\$(python3 -c "import json; print(json.load(open('/usr/local/etc/xray/config.json'))['inbounds'][0]['streamSettings']['realitySettings']['shortIds'][0])")

if [ "$mode" = "stream-up" ]; then
    XHTTP_EXTRA='"mode": "stream-up", "scStreamUpServerSecs": "3600-7200", "scMinPostsIntervalMs": 0,'
else
    XHTTP_EXTRA=""
fi

cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "\$UUID"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "www.microsoft.com:443",
        "serverNames": ["www.microsoft.com"],
        "privateKey": "\$PRIVKEY",
        "shortIds": ["\$SHORTID"]
      },
      "xhttpSettings": {
        \${XHTTP_EXTRA}
        "host": "www.microsoft.com",
        "path": "/cylonix-derp-tunnel"
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {"redirect": "127.0.0.1:8080"}
  }]
}
EOF
systemctl restart xray
sleep 2
systemctl is-active xray || { journalctl -u xray --no-pager -n 10; exit 1; }
echo "VM1 xray reconfigured to $mode mode"
CFGSCRIPT
}

# ── Run the throughput tests ──────────────────────────────────────────────────
sep "DERP throughput tests (duration=${BENCH_DURATION}, ${_netem_desc}, RTT≈$(( WAN_DELAY_MS * 2 ))ms, tcp_cc=${TCP_CC})"
log "VM1=$VM1_LAN_IP (derper + xray server)   VM2=$VM2_LAN_IP (derpbench, embedded xray)"
log ""

# ── Test A: Baseline — direct DERP, no xray ───────────────────────────────────
sep "Test A: Direct DERP (no xray)"
vm_ssh "$VM2_SSH_PORT" \
    /usr/local/bin/derpbench -server "http://$VM1_LAN_IP:8080/derp" -d "$BENCH_DURATION"

# ── Test B: DERP via xray packet-up (censorship-safe default) ─────────────────
sep "Test B: DERP via xray VLESS+REALITY+XHTTP (packet-up — censorship-safe default)"
# VM1 xray is already configured for packet-up (the default).
# derpbench uses its embedded xray-core client (no separate xray process on VM2).
# shellcheck disable=SC2046
vm_ssh "$VM2_SSH_PORT" \
    /usr/local/bin/derpbench \
        -server "http://$VM1_LAN_IP:8080/derp" \
        $(derpbench_xray_flags "packet-up") \
        -d "$BENCH_DURATION"

# ── Test C: DERP via xray stream-up (high-throughput, more fingerprintable) ────
sep "Test C: DERP via xray VLESS+REALITY+XHTTP (stream-up — higher throughput)"
log "Reconfiguring VM1 xray to stream-up..."
reconfigure_vm1_xray "stream-up"
# shellcheck disable=SC2046
vm_ssh "$VM2_SSH_PORT" \
    /usr/local/bin/derpbench \
        -server "http://$VM1_LAN_IP:8080/derp" \
        $(derpbench_xray_flags "stream-up") \
        -d "$BENCH_DURATION"

# ── Test D: DERP via xray stream-up + parallel connections ───────────────────
XRAY_CONN_COUNT="${XRAY_CONN_COUNT:-2}"
XRAY_RECV_COUNT="${XRAY_RECV_COUNT:-${XRAY_CONN_COUNT}}"
sep "Test D: DERP via xray stream-up with ${XRAY_CONN_COUNT} senders + ${XRAY_RECV_COUNT} receivers (-allow-parallel-clients)"
log "Restarting VM1 derper with -allow-parallel-clients..."
reconfigure_vm1_derper "-allow-parallel-clients"
# VM1 xray is already in stream-up mode from Test C.
# shellcheck disable=SC2046
vm_ssh "$VM2_SSH_PORT" \
    /usr/local/bin/derpbench \
        -server "http://$VM1_LAN_IP:8080/derp" \
        $(derpbench_xray_flags "stream-up") \
        -xray-conn-count "$XRAY_CONN_COUNT" \
        -xray-recv-count "$XRAY_RECV_COUNT" \
        -d "$BENCH_DURATION"

sep "Test complete"
log ""
log "Expected results:"
log "  Test A (direct DERP)           : close to raw network speed"
log "  Test B (xray packet-up)        : censorship-safe; RTT-limited (~1400B/$(( WAN_DELAY_MS * 2 ))ms, ${_netem_desc})"
log "  Test C (xray stream-up)        : higher throughput; more fingerprintable as a tunnel"
log "  Test D (stream-up + N conns)   : parallel xray TCP streams (send+recv); should beat Test C"
log ""
log "VM logs: ${WORK_DIR}/vm1.log  ${WORK_DIR}/vm2.log"
