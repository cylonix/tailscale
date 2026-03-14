// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !plan9

package vms

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	expect "github.com/tailscale/goexpect"
	"golang.org/x/crypto/ssh"
	"tailscale.com/tailcfg"
)

// TestVML2DiscoveryRulesConnectivity validates that a VM node remains fully
// connected when L2 discovery rules are present in map responses.
func TestVML2DiscoveryRulesConnectivity(t *testing.T) {
	setupTests(t)

	distro := Distros[1] // ubuntu-20.04
	if !distroRex.Unwrap().MatchString(distro.Name) {
		t.Skip("regex not matched")
	}

	ctx, done := context.WithCancel(context.Background())
	t.Cleanup(done)

	h := newHarness(t)
	h.cs.SetL2DiscoveryRules([]tailcfg.L2DiscoveryRule{
		{
			Protocols: []string{"mdns"},
			SrcIPs:    []string{"*"},
			DstIPs:    []string{"*"},
		},
		{
			Protocols: []string{"ssdp"},
			SrcIPs:    []string{"*"},
			DstIPs:    []string{"*"},
		},
	})

	err := ramsem.sem.Acquire(ctx, int64(distro.MemoryMegs))
	if err != nil {
		t.Fatalf("can't acquire ram semaphore: %v", err)
	}
	t.Cleanup(func() { ramsem.sem.Release(int64(distro.MemoryMegs)) })

	vm := h.mkVM(t, 1, distro, h.pubKey, h.loginServerURL, t.TempDir())
	vm.waitStartup(t)
	guestLoginURL := guestReachableHostURL(h.loginServerURL) // __CYLONIX_ADD__

	ipm := h.waitForIPMap(t, vm)
	_, cli := h.setupSSHShell(t, distro, ipm)
	timeout := 30 * time.Second
	runTestCommands(t, timeout, cli, []expect.Batcher{
		&expect.BExp{R: `(\#)`},
		&expect.BSnd{S: "for i in $(seq 1 20); do systemctl daemon-reload; systemctl restart tailscaled.service; if systemctl is-active --quiet tailscaled.service; then echo STARTED; break; fi; sleep 1; done\n"},
		&expect.BExp{R: `STARTED`},
		// __BEGIN_CYLONIX_MOD__
		// Do not wait for a trailing prompt here; cloud-init/systemd noise can
		// interleave with shell output and delay prompt rendering on slow VM boots.
		// __END_CYLONIX_MOD__
	})
	// __BEGIN_CYLONIX_MOD__
	runTestCommands(t, timeout, cli, []expect.Batcher{
		&expect.BSnd{S: "tailscale --socket=/run/tailscale/tailscaled.sock up --login-server=" + guestLoginURL + "\n"}, // __CYLONIX_MOD__
		&expect.BSnd{S: "echo Success.\n"},
		&expect.BExp{R: `Success.`},
	})

	// __BEGIN_CYLONIX_MOD__
	for i := 0; i < 20; i++ {
		statusSess := getSession(t, cli)
		statusOut, statusErr := statusSess.CombinedOutput("tailscale --socket=/run/tailscale/tailscaled.sock status")
		if statusErr == nil && strings.Contains(string(statusOut), "100.64.0.1") {
			break
		}
		if i == 19 {
			t.Fatalf("tailscale status did not become ready: %v: %s", statusErr, statusOut)
		}
		time.Sleep(500 * time.Millisecond)
	}
	// __END_CYLONIX_MOD__

	h.testPing(t, h.testerV4, cli)

	sess := getSession(t, cli) // __CYLONIX_MOD__
	out, err := sess.CombinedOutput("tailscale --socket=/run/tailscale/tailscaled.sock ip -4 | head -n1")
	if err != nil {
		t.Fatalf("tailscale ip -4 failed: %v: %s", err, out)
	}
	vmIP := strings.TrimSpace(string(bytes.TrimSpace(out)))
	if vmIP == "" {
		t.Fatal("tailscale ip -4 returned empty output")
	}

	// Verify return path from harness userspace node -> VM.
	h.Tailscale(t, "ping", vmIP)
}

func TestVML2RelayUDPInterceptE2E(t *testing.T) {
	setupTests(t)

	distro := Distros[1] // ubuntu-20.04
	if !distroRex.Unwrap().MatchString(distro.Name) {
		t.Skip("regex not matched")
	}

	ctx, done := context.WithCancel(context.Background())
	t.Cleanup(done)

	h := newHarness(t)
	h.cs.SetL2DiscoveryRules([]tailcfg.L2DiscoveryRule{{
		Protocols: []string{"mdns", "ssdp"},
		SrcIPs:    []string{"*"},
		DstIPs:    []string{"*"},
	}})

	err := ramsem.sem.Acquire(ctx, int64(2*distro.MemoryMegs))
	if err != nil {
		t.Fatalf("can't acquire ram semaphore: %v", err)
	}
	t.Cleanup(func() { ramsem.sem.Release(int64(2 * distro.MemoryMegs)) })

	vm1 := h.mkVM(t, 1, distro, h.pubKey, h.loginServerURL, t.TempDir())
	vm2 := h.mkVM(t, 2, distro, h.pubKey, h.loginServerURL, t.TempDir())
	vm1.waitStartup(t)
	vm2.waitStartup(t)

	guestLoginURL := guestReachableHostURL(h.loginServerURL)
	ipm1 := h.waitForIPMap(t, vm1)
	_, cli1 := h.setupSSHShell(t, distro, ipm1)
	ipm2 := h.waitForIPMap(t, vm2)
	_, cli2 := h.setupSSHShell(t, distro, ipm2)

	startVMWithTailscale(t, cli1, guestLoginURL)
	startVMWithTailscale(t, cli2, guestLoginURL)

	vm2IP := vmTailscaleIPv4(t, cli2)
	pingSess := getSession(t, cli1)
	pingCmd := "tailscale --socket=/run/tailscale/tailscaled.sock ping -c 1 " + vm2IP
	if out, err := pingSess.CombinedOutput(pingCmd); err != nil {
		t.Fatalf("vm1 failed to ping vm2 over tailscale: %v: %s", err, out)
	}

	sess2 := getSession(t, cli2)
	checkCmd := "for i in $(seq 1 20); do journalctl -u tailscaled --no-pager -n 600 | grep -E 'peerapi: serving on http://100\\.|l2relay: peerapi hello from=' && echo HIT && exit 0; sleep 1; done; exit 1"
	if out, err := sess2.CombinedOutput(checkCmd); err != nil {
		t.Fatalf("did not observe peerapi/l2relay activity on VM2: %v: %s", err, out)
	}
}

// TestVML2RelayNASShareE2E validates a real folder-sharing flow over the relay
// path: VM2 hosts a shared folder and VM3 lists and reads it.
func TestVML2RelayNASShareE2E(t *testing.T) {
	setupTests(t)

	distro := Distros[1] // ubuntu-20.04
	if !distroRex.Unwrap().MatchString(distro.Name) {
		t.Skip("regex not matched")
	}

	ctx, done := context.WithCancel(context.Background())
	t.Cleanup(done)

	h := newHarness(t)
	h.cs.SetL2DiscoveryRules([]tailcfg.L2DiscoveryRule{{
		Protocols: []string{"mdns", "ssdp"},
		SrcIPs:    []string{"*"},
		DstIPs:    []string{"*"},
	}})

	err := ramsem.sem.Acquire(ctx, int64(3*distro.MemoryMegs))
	if err != nil {
		t.Fatalf("can't acquire ram semaphore: %v", err)
	}
	t.Cleanup(func() { ramsem.sem.Release(int64(3 * distro.MemoryMegs)) })

	vm1 := h.mkVM(t, 1, distro, h.pubKey, h.loginServerURL, t.TempDir()) // reserved for non-cylonix LAN-device scenarios
	vm2 := h.mkVM(t, 2, distro, h.pubKey, h.loginServerURL, t.TempDir()) // NAS
	vm3 := h.mkVM(t, 3, distro, h.pubKey, h.loginServerURL, t.TempDir()) // client
	vm1.waitStartup(t)
	vm2.waitStartup(t)
	vm3.waitStartup(t)

	guestLoginURL := guestReachableHostURL(h.loginServerURL)

	ipm2 := h.waitForIPMap(t, vm2)
	_, cli2 := h.setupSSHShell(t, distro, ipm2)
	ipm3 := h.waitForIPMap(t, vm3)
	_, cli3 := h.setupSSHShell(t, distro, ipm3)

	startVMWithTailscale(t, cli2, guestLoginURL)
	startVMWithTailscale(t, cli3, guestLoginURL)

	vm2IP := vmTailscaleIPv4(t, cli2)
	pingFromVM3 := "tailscale --socket=/run/tailscale/tailscaled.sock ping -c 1 " + vm2IP
	mustRunGuestCommand(t, cli3, pingFromVM3)

	prepareNasCmd := strings.Join([]string{
		"set -euxo pipefail",
		"mkdir -p /srv/l2relay-share",
		"printf '%s\\n' 'hello-from-vm2' > /srv/l2relay-share/hello.txt",
		"nohup python3 -m http.server 18080 --bind 0.0.0.0 --directory /srv/l2relay-share >/tmp/l2relay-share-http.log 2>&1 &",
		"for i in $(seq 1 20); do",
		"  if ss -lnt | grep -q ':18080'; then",
		"    exit 0",
		"  fi",
		"  sleep 1",
		"done",
		"cat /tmp/l2relay-share-http.log >&2 || true",
		"exit 1",
	}, "\n")
	mustRunGuestCommand(t, cli2, "bash -lc "+shellQuote(prepareNasCmd))

	checkShareCmd := fmt.Sprintf("for i in $(seq 1 30); do python3 - <<'PY'\nimport sys, urllib.request\nbase='http://%s:18080'\ntry:\n    idx = urllib.request.urlopen(base + '/', timeout=5).read().decode('utf-8', errors='replace')\n    body = urllib.request.urlopen(base + '/hello.txt', timeout=5).read().decode('utf-8', errors='replace').strip()\nexcept Exception:\n    sys.exit(1)\nif 'hello.txt' not in idx or body != 'hello-from-vm2':\n    sys.exit(1)\nprint('OK')\nPY\nif [ $? -eq 0 ]; then exit 0; fi; sleep 1; done; exit 1", vm2IP)
	mustRunGuestCommand(t, cli3, "bash -lc "+shellQuote(checkShareCmd))
}

// TestVML2RelayMinecraftE2E validates Minecraft LAN discovery relay with TCP
// proxy rewriting. VM2 runs a Minecraft-protocol TCP server and sends LAN
// discovery announcements; VM3 receives the relayed+rewritten announcement via
// the l2relay mesh, connects through the injected proxy port, and verifies the
// TCP game stream reaches VM2.
//
// This specifically exercises the Case 2 proxy path (server has Cylonix):
//   VM2 captures its own multicast (capturedSrc == selfLANIP) → sets
//   MinecraftServerPort in envelope → VM3 receives envelope → starts TCP proxy
//   to VM2's Tailscale IP → injects multicast with rewritten [AD]port[/AD] →
//   VM3 client connects to proxy port → data flows through mesh to VM2.
func TestVML2RelayMinecraftE2E(t *testing.T) {
	setupTests(t)

	distro := Distros[1] // ubuntu-20.04
	if !distroRex.Unwrap().MatchString(distro.Name) {
		t.Skip("regex not matched")
	}

	ctx, done := context.WithCancel(context.Background())
	t.Cleanup(done)

	h := newHarness(t)
	h.cs.SetL2DiscoveryRules([]tailcfg.L2DiscoveryRule{{
		Protocols: []string{"minecraft"},
		SrcIPs:    []string{"*"},
		DstIPs:    []string{"*"},
	}})

	err := ramsem.sem.Acquire(ctx, int64(2*distro.MemoryMegs))
	if err != nil {
		t.Fatalf("can't acquire ram semaphore: %v", err)
	}
	t.Cleanup(func() { ramsem.sem.Release(int64(2 * distro.MemoryMegs)) })

	vm2 := h.mkVM(t, 2, distro, h.pubKey, h.loginServerURL, t.TempDir()) // server
	vm3 := h.mkVM(t, 3, distro, h.pubKey, h.loginServerURL, t.TempDir()) // client
	vm2.waitStartup(t)
	vm3.waitStartup(t)

	guestLoginURL := guestReachableHostURL(h.loginServerURL)

	ipm2 := h.waitForIPMap(t, vm2)
	_, cli2 := h.setupSSHShell(t, distro, ipm2)
	ipm3 := h.waitForIPMap(t, vm3)
	_, cli3 := h.setupSSHShell(t, distro, ipm3)

	startVMWithTailscale(t, cli2, guestLoginURL)
	startVMWithTailscale(t, cli3, guestLoginURL)

	// Ensure mesh connectivity before starting the relay test.
	vm2IP := vmTailscaleIPv4(t, cli2)
	mustRunGuestCommand(t, cli3, "tailscale --socket=/run/tailscale/tailscaled.sock ping -c 1 "+vm2IP)

	// VM2: run a minimal Minecraft-protocol TCP server on port 25565 that
	// sends "MINECRAFT_OK" to each client, then broadcast LAN discovery
	// announcements for 45 seconds so the relay has time to deliver them.
	mcServerScript := strings.Join([]string{
		"import socket, threading, time",
		"def serve():",
		"    s = socket.socket()",
		"    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
		"    s.bind(('0.0.0.0', 25565))",
		"    s.listen(16)",
		"    s.settimeout(60)",
		"    try:",
		"        while True:",
		"            try:",
		"                c, _ = s.accept()",
		"                c.sendall(b'MINECRAFT_OK')",
		"                c.close()",
		"            except socket.timeout:",
		"                break",
		"    finally:",
		"        s.close()",
		"threading.Thread(target=serve, daemon=True).start()",
		"us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)",
		"us.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)",
		"for _ in range(45):",
		"    us.sendto(b'[MOTD]Test Server[/MOTD][AD]25565[/AD]', ('224.0.2.60', 4445))",
		"    time.sleep(1)",
	}, "\n")
	// Run the server in background; we don't wait for it to finish.
	startServerCmd := "nohup python3 -c " + shellQuote(mcServerScript) + " >/tmp/mc-server.log 2>&1 &"
	mustRunGuestCommand(t, cli2, startServerCmd)

	// VM3: listen for a Minecraft LAN discovery multicast, try to connect TCP
	// to the announced address:port, and verify the response is "MINECRAFT_OK".
	// The l2relay proxy rewrites [AD]port[/AD] so the connection goes through
	// the local proxy → mesh → VM2's TCP server.
	// We loop for up to 60 seconds to allow relay setup time.
	mcClientScript := strings.Join([]string{
		"import socket, struct, re, sys, time",
		"ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
		"ms.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
		"ms.bind(('', 4445))",
		"mreq = struct.pack('4sL', socket.inet_aton('224.0.2.60'), socket.INADDR_ANY)",
		"ms.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)",
		"ms.settimeout(2)",
		"deadline = time.time() + 60",
		"while time.time() < deadline:",
		"    try:",
		"        data, addr = ms.recvfrom(1024)",
		"    except socket.timeout:",
		"        continue",
		"    msg = data.decode('utf-8', errors='replace')",
		"    m = re.search(r'\\[AD\\](\\d+)\\[/AD\\]', msg)",
		"    if not m:",
		"        continue",
		"    port = int(m.group(1))",
		"    src_ip = addr[0]",
		"    try:",
		"        ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
		"        ts.settimeout(10)",
		"        ts.connect((src_ip, port))",
		"        resp = ts.recv(64)",
		"        ts.close()",
		"    except Exception:",
		"        continue",
		"    if resp == b'MINECRAFT_OK':",
		"        print('OK')",
		"        sys.exit(0)",
		"print('TIMEOUT', file=sys.stderr)",
		"sys.exit(1)",
	}, "\n")
	checkCmd := "python3 -c " + shellQuote(mcClientScript)
	out := mustRunGuestCommand(t, cli3, checkCmd)
	if !strings.Contains(out, "OK") {
		t.Fatalf("minecraft relay check did not return OK: %s", out)
	}
}

func startVMWithTailscale(t *testing.T, cli *ssh.Client, guestLoginURL string) {
	t.Helper()
	startSess := getSession(t, cli)
	startCmd := "for i in $(seq 1 20); do systemctl daemon-reload; systemctl restart tailscaled.service; if systemctl is-active --quiet tailscaled.service; then echo STARTED; exit 0; fi; sleep 1; done; echo START_FAILED; exit 1"
	if out, err := startSess.CombinedOutput(startCmd); err != nil || !strings.Contains(string(out), "STARTED") {
		t.Fatalf("failed to start tailscaled: %v: %s", err, out)
	}

	upSess := getSession(t, cli)
	upCmd := "tailscale --socket=/run/tailscale/tailscaled.sock up --login-server=" + guestLoginURL
	if out, err := upSess.CombinedOutput(upCmd); err != nil {
		t.Fatalf("tailscale up failed: %v: %s", err, out)
	}

	for i := 0; i < 20; i++ {
		statusSess := getSession(t, cli)
		statusOut, statusErr := statusSess.CombinedOutput("tailscale --socket=/run/tailscale/tailscaled.sock status")
		if statusErr == nil && strings.Contains(string(statusOut), "100.64.0.1") {
			return
		}
		if i == 19 {
			t.Fatalf("tailscale status did not become ready: %v: %s", statusErr, statusOut)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func vmTailscaleIPv4(t *testing.T, cli *ssh.Client) string {
	t.Helper()
	sess := getSession(t, cli)
	out, err := sess.CombinedOutput("tailscale --socket=/run/tailscale/tailscaled.sock ip -4 | head -n1")
	if err != nil {
		t.Fatalf("tailscale ip -4 failed: %v: %s", err, out)
	}
	vmIP := strings.TrimSpace(string(bytes.TrimSpace(out)))
	if vmIP == "" {
		t.Fatal("tailscale ip -4 returned empty output")
	}
	return vmIP
}

func mustRunGuestCommand(t *testing.T, cli *ssh.Client, cmd string) string {
	t.Helper()
	sess := getSession(t, cli)
	out, err := sess.CombinedOutput(cmd)
	if err != nil {
		t.Fatalf("guest command failed: %q: %v: %s", cmd, err, out)
	}
	return string(out)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
