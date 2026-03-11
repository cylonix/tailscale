// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !plan9

package vms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/dnstype"
)

type Harness struct {
	testerDialer   proxy.Dialer
	testerDir      string
	binaryDir      string
	cli            string
	daemon         string
	pubKey         string
	signer         ssh.Signer
	cs             *testcontrol.Server
	loginServerURL string
	testerV4       netip.Addr
	ipMu           *sync.Mutex
	ipMap          map[string]ipMapping
}

// __BEGIN_CYLONIX_ADD__
var vmGuestBins struct {
	mu   sync.Mutex
	bins map[string]guestBinPair
}

type guestBinPair struct {
	cli    string
	daemon string
}

func guestBinaries(t *testing.T, arch string) guestBinPair {
	t.Helper()
	vmGuestBins.mu.Lock()
	defer vmGuestBins.mu.Unlock()
	if vmGuestBins.bins == nil {
		vmGuestBins.bins = map[string]guestBinPair{}
	}
	if bins, ok := vmGuestBins.bins[arch]; ok {
		return bins
	}
	bins := buildGuestBinaries(t, arch)
	vmGuestBins.bins[arch] = bins
	return bins
}

func buildGuestBinaries(t *testing.T, arch string) guestBinPair {
	t.Helper()
	outDir := vmGuestBinaryCacheDir(t, arch)
	goBin := filepath.Clean("../../../tool/go")
	if _, err := os.Stat(goBin); err != nil {
		if p, lpErr := exec.LookPath("go"); lpErr == nil {
			goBin = p
		} else {
			t.Fatalf("can't find go tool: %v", err)
		}
	}
	build := func(outPath, pkg string) {
		cmd := exec.Command(goBin, "build", "-o", outPath, pkg)
		cmd.Env = append(os.Environ(),
			"GOOS=linux",
			"GOARCH="+arch,
			"CGO_ENABLED=0",
		)
		tstest.FixLogs(t)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s for linux/%s failed: %v, %s", pkg, arch, err, out)
		}
	}
	cli := filepath.Join(outDir, "tailscale")
	daemon := filepath.Join(outDir, "tailscaled")
	if _, err := os.Stat(cli); err != nil {
		build(cli, "tailscale.com/cmd/tailscale")
	}
	if _, err := os.Stat(daemon); err != nil {
		build(daemon, "tailscale.com/cmd/tailscaled")
	}
	return guestBinPair{cli: cli, daemon: daemon}
}

func vmGuestBinaryCacheDir(t *testing.T, arch string) string {
	t.Helper()
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("can't locate user cache dir: %v", err)
	}
	key := vmGuestBinaryBuildKey(t)
	dir := filepath.Join(cacheRoot, "tailscale", "vm-test", "guestbins", key, arch)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("can't create VM guest binary cache dir %q: %v", dir, err)
	}
	return dir
}

func vmGuestBinaryBuildKey(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("TS_VM_GUEST_BIN_KEY"); env != "" {
		return env
	}
	out, err := exec.Command("git", "rev-parse", "HEAD").CombinedOutput()
	if err == nil {
		rev := string(bytes.TrimSpace(out))
		if rev != "" {
			return rev
		}
	}
	// Fallback: stable key per process when git metadata isn't available.
	sum := sha256.Sum256([]byte(time.Now().UTC().Format("20060102")))
	return hex.EncodeToString(sum[:8])
}

func guestArchForDistro(d Distro) string {
	_, arch := distroForHost(d)
	if arch == "arm64" || arch == "amd64" {
		return arch
	}
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "amd64"
}

// __END_CYLONIX_ADD__

func newHarness(t *testing.T) *Harness {
	dir := t.TempDir()
	bindHost := deriveBindhost(t)
	ln, err := net.Listen("tcp", net.JoinHostPort(bindHost, "0"))
	if err != nil {
		t.Fatalf("can't make TCP listener: %v", err)
	}
	t.Cleanup(func() {
		ln.Close()
	})
	t.Logf("host:port: %s", ln.Addr())

	cs := &testcontrol.Server{
		DNSConfig: &tailcfg.DNSConfig{
			// TODO: this is wrong.
			// It is also only one of many configurations.
			// Figure out how to scale it up.
			Resolvers:    []*dnstype.Resolver{{Addr: "100.100.100.100"}, {Addr: "8.8.8.8"}},
			Domains:      []string{"record"},
			Proxied:      true,
			ExtraRecords: []tailcfg.DNSRecord{{Name: "extratest.record", Type: "A", Value: "1.2.3.4"}},
		},
	}

	derpMap := integration.RunDERPAndSTUN(t, t.Logf, bindHost)
	cs.DERPMap = derpMap

	var (
		ipMu  sync.Mutex
		ipMap = map[string]ipMapping{}
	)

	mux := http.NewServeMux()
	mux.Handle("/", cs)

	lc := &integration.LogCatcher{}
	if *verboseLogcatcher {
		lc.UseLogf(t.Logf)
		t.Cleanup(func() {
			lc.UseLogf(nil) // do not log after test is complete
		})
	}
	mux.Handle("/c/", lc)

	// This handler will let the virtual machines tell the host information about that VM.
	// This is used to maintain a list of port->IP address mappings that are known to be
	// working. This allows later steps to connect over SSH. This returns no response to
	// clients because no response is needed.
	mux.HandleFunc("/myip/", func(w http.ResponseWriter, r *http.Request) {
		ipMu.Lock()
		defer ipMu.Unlock()

		name := path.Base(r.URL.Path)
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		port, err := strconv.Atoi(name)
		if err != nil {
			log.Panicf("bad port: %v", port)
		}
		distro := r.UserAgent()
		ipMap[distro] = ipMapping{distro, port, host}
		t.Logf("%s: %v", name, host)
	})

	hs := &http.Server{Handler: mux}
	go hs.Serve(ln)

	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", "machinekey", "-N", "")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v, %s", err, out)
	}
	pubkey, err := os.ReadFile(filepath.Join(dir, "machinekey.pub"))
	if err != nil {
		t.Fatalf("can't read ssh key: %v", err)
	}

	privateKey, err := os.ReadFile(filepath.Join(dir, "machinekey"))
	if err != nil {
		t.Fatalf("can't read ssh private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		t.Fatalf("can't parse private key: %v", err)
	}

	loginServer := fmt.Sprintf("http://%s", ln.Addr())
	t.Logf("loginServer: %s", loginServer)

	binaries := integration.GetBinaries(t)
	h := &Harness{
		pubKey:         string(pubkey),
		binaryDir:      binaries.Dir,
		cli:            binaries.Tailscale.Path,
		daemon:         binaries.Tailscaled.Path,
		signer:         signer,
		loginServerURL: loginServer,
		cs:             cs,
		ipMu:           &ipMu,
		ipMap:          ipMap,
	}

	h.makeTestNode(t, loginServer)

	return h
}

func (h *Harness) Tailscale(t *testing.T, args ...string) []byte {
	t.Helper()

	args = append([]string{"--socket=" + filepath.Join(h.testerDir, "sock")}, args...)

	cmd := exec.Command(h.cli, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// makeTestNode creates a userspace tailscaled running in netstack mode that
// enables us to make connections to and from the tailscale network being
// tested. This mutates the Harness to allow tests to dial into the tailscale
// network as well as control the tester's tailscaled.
func (h *Harness) makeTestNode(t *testing.T, controlURL string) {
	dir := t.TempDir()
	h.testerDir = dir

	port, err := getProbablyFreePortNumber()
	if err != nil {
		t.Fatalf("can't get free port: %v", err)
	}

	cmd := exec.Command(
		h.daemon,
		"--tun=userspace-networking",
		"--state="+filepath.Join(dir, "state.json"),
		"--socket="+filepath.Join(dir, "sock"),
		fmt.Sprintf("--socks5-server=localhost:%d", port),
	)

	cmd.Env = append(
		os.Environ(),
		"NOTIFY_SOCKET="+filepath.Join(dir, "notify_socket"),
		"TS_LOG_TARGET="+h.loginServerURL,
	)

	err = cmd.Start()
	if err != nil {
		t.Fatalf("can't start tailscaled: %v", err)
	}

	t.Cleanup(func() {
		cmd.Process.Kill()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)

outer:
	for {
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for tailscaled to come up")
			return
		case <-ticker.C:
			conn, err := net.Dial("unix", filepath.Join(dir, "sock"))
			if err != nil {
				continue
			}

			conn.Close()
			break outer
		}
	}

	run(t, dir, h.cli,
		"--socket="+filepath.Join(dir, "sock"),
		"up",
		"--login-server="+controlURL,
		"--hostname=tester",
	)

	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), nil, &net.Dialer{})
	if err != nil {
		t.Fatalf("can't make netstack proxy dialer: %v", err)
	}
	h.testerDialer = dialer
	h.testerV4 = bytes2Netaddr(h.Tailscale(t, "ip", "-4"))
}

func bytes2Netaddr(inp []byte) netip.Addr {
	return netip.MustParseAddr(string(bytes.TrimSpace(inp)))
}
