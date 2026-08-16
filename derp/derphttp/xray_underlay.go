// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	clog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"

	// xray-core requires these blank imports so that init() functions
	// register handlers before core.StartInstance is called. The config
	// protos and most implementations (dispatcher, app/log, vless
	// outbound, reality, splithttp, tls) are registered via the direct
	// imports in xray_config_proto.go; only impl-only packages that
	// nothing else imports remain blank here. infra/conf (and with it
	// every other xray protocol: hysteria, kcp, vmess, trojan, ...) is
	// deliberately NOT imported outside tests — it inflates the iOS
	// network-extension baseline.
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	// Raw TCP transport, kept as a safety net for internal dials.
	_ "github.com/xtls/xray-core/transport/internet/tcp"

	// Fix dependency cycle caused by core import in internet package.
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"

	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
)

// WantsXRayUnderlay reports whether a DERP node is configured to use an
// xray VLESS+REALITY+XHTTP underlay tunnel.
func WantsXRayUnderlay(n *tailcfg.DERPNode) bool {
	return wantsXRayUnderlay(n)
}

// xrayConnectTimeout is the fallback setup budget for a DERP connection
// reached via an xray underlay. Unlike the plain-TLS path (which needs
// only a TCP + TLS handshake), an xray setup is a serial multi-RTT chain
// (TCP + REALITY + XHTTP + DERP HTTP upgrade + DERP key exchange). On a
// weak or throttled underlay that chain legitimately takes much longer,
// and force-closing it mid-handshake just restarts the same expensive
// sequence from zero. A patient budget lets a slow-but-advancing setup
// finish instead of thrashing in a redial loop.
//
// The budget is deliberately capped just above the server-side handshake
// ceiling rather than set arbitrarily high. Measurement (derpbench through
// a mid-handshake-outage proxy against the real relay) showed the xray
// server abandons a half-open handshake after ~20s: outages up to ~18s
// recover, but beyond ~20s the handshake cannot complete regardless of how
// long the client waits. A budget much larger than that ceiling buys no
// extra survivability and only delays the redial after a doomed attempt,
// so 22s tracks the server ceiling with a small margin. Raising it further
// only helps if the server's handshake timeout is raised in tandem.
const xrayConnectTimeout = 22 * time.Second

// regionWantsXRayUnderlay reports whether this client's DERP region has
// any node configured to use the xray underlay. It is safe to call while
// holding the client's mu (getRegion does not acquire it).
func (c *Client) regionWantsXRayUnderlay() bool {
	if c.getRegion == nil {
		return false
	}
	reg := c.getRegion()
	if reg == nil {
		return false
	}
	for _, n := range reg.Nodes {
		if wantsXRayUnderlay(n) {
			return true
		}
	}
	return false
}

func wantsXRayUnderlay(n *tailcfg.DERPNode) bool {
	if n == nil || n.XRay == nil {
		return false
	}
	return strings.TrimSpace(n.XRay.ClientUUID) != "" &&
		strings.TrimSpace(n.XRay.ServerPublicKey) != "" &&
		strings.TrimSpace(n.XRay.XHTTPTunnel) != "" &&
		strings.TrimSpace(n.XRay.RealityShortID) != ""
}

// xrayLogHandler is a clog.Handler that prefixes all xray-core log
// messages with "derphttp: xray:".
type xrayLogHandler struct{}

func (xrayLogHandler) Handle(msg clog.Message) {
	log.Printf("derphttp: xray: %s", msg.String())
}

func init() {
	clog.RegisterHandler(xrayLogHandler{})
}

// xrayNetnsControllerOnce ensures we only register the netns dialer
// controller with xray-core once.
var xrayNetnsControllerOnce sync.Once

// registerXRayNetnsController registers tailscale's netns socket
// control function with xray-core's system dialer so that all
// outbound TCP connections made by xray-core (REALITY handshake,
// XHTTP transport, DNS lookups) bypass the tailscale tunnel.
//
// Without this, when using the xray DERP peer as an exit node, the
// xray dial would be routed back into the tailscale tunnel, creating
// a routing loop.
func registerXRayNetnsController(c *Client) {
	xrayNetnsControllerOnce.Do(func() {
		// Create a net.Dialer with the netns Control function set.
		d := &net.Dialer{}
		nd := netns.FromDialer(c.logf, c.netMon, d)
		// FromDialer returns the same *net.Dialer with Control set
		// (unless SOCKS wrapping is active, in which case we can't
		// extract a raw Control, but that's fine — the controller
		// will still help for the non-SOCKS case).
		if dd, ok := nd.(*net.Dialer); ok && dd.Control != nil {
			ctl := dd.Control
			err := internet.RegisterDialerController(
				func(network, address string, conn syscall.RawConn) error {
					return ctl(network, address, conn)
				},
			)
			if err != nil {
				c.logf("derphttp: xray: failed to register netns dialer controller: %v", err)
			} else {
				c.logf("derphttp: xray: registered netns dialer controller for tunnel bypass")
			}
		} else {
			c.logf("derphttp: xray: [warning] could not extract netns Control from dialer (type %T), xray connections may not bypass tailscale tunnel", nd)
		}
	})
}

// xrayInstance holds a cached xray-core instance keyed by the xray
// config that produced it, so we can detect when the config changes.
type xrayInstance struct {
	mu       sync.Mutex
	instance *core.Instance
	// configKey is a string that uniquely identifies the xray config
	// that was used to create this instance. If the config changes
	// the instance is recreated.
	configKey string
}

// getOrCreate returns a running xray-core instance, creating one if
// needed or if the config has changed. The caller must call core.Dial
// on the returned instance to get a connection.
func (xi *xrayInstance) getOrCreate(configKey string, configBytes []byte) (*core.Instance, error) {
	xi.mu.Lock()
	defer xi.mu.Unlock()
	if xi.instance != nil && xi.configKey == configKey {
		return xi.instance, nil
	}
	// Config changed or first use; close the old instance if any.
	if xi.instance != nil {
		xi.instance.Close()
		xi.instance = nil
		xi.configKey = ""
	}
	inst, err := core.StartInstance("protobuf", configBytes)
	if err != nil {
		return nil, err
	}
	xi.instance = inst
	xi.configKey = configKey
	return inst, nil
}

func (xi *xrayInstance) close() {
	xi.mu.Lock()
	defer xi.mu.Unlock()
	if xi.instance != nil {
		xi.instance.Close()
		xi.instance = nil
		xi.configKey = ""
	}
}

// dialNodeXRay dials a DERP node through an xray-core VLESS+REALITY+XHTTP
// tunnel. xray-core handles its own DNS resolution and transport, so we
// delegate connection management entirely to it rather than doing our own
// happy-eyeballs racing.
func (c *Client) dialNodeXRay(ctx context.Context, n *tailcfg.DERPNode) (net.Conn, error) {
	if n == nil || n.XRay == nil {
		return nil, errors.New("xray config missing")
	}

	// First, try a direct local loopback connection to the DERP HTTP
	// endpoint on the same host (if present). This is useful when the
	// xray/DERP server exposes the DERP HTTP endpoint on localhost
	// (typically port 8080) — a direct connection avoids routing the
	// traffic through another xray tunnel and can improve throughput.
	// TS_DERP_XRAY_LOCAL_CLIENT_ID is the client ID of the local DERP.
	// TS_DERP_XRAY_LOCAL_PORT is the TCP port on localhost where the
	// DERP HTTP endpoint is reachable, default to 8080 if unset.
	localXrayClientID := os.Getenv("TS_DERP_XRAY_LOCAL_CLIENT_ID")
	if localXrayClientID == n.XRay.ClientUUID {
		localPort := 8080
		localXrayPort := os.Getenv("TS_DERP_XRAY_LOCAL_PORT")
		if localXrayPort != "" {
			port, err := strconv.Atoi(localXrayPort)
			if err != nil {
				err = fmt.Errorf("invalid TS_DERP_XRAY_LOCAL_PORT %q: %v", localXrayPort, err)
				c.logf("derphttp: xray: %v", err)
				return nil, err
			}
			localPort = port
		}
		addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(localPort))
		c.logf("[v2] derphttp: xray: attempting local loopback to %s", addr)
		d := &net.Dialer{}
		// Keep this probe short so we don't delay fallback to xray.
		ctxLocal, cancel := context.WithTimeout(ctx, 1*time.Second)
		conn, err := d.DialContext(ctxLocal, "tcp", addr)
		cancel()
		if err == nil {
			c.logf("derphttp: xray: local loopback connection to %s succeeded; using direct DERP connection", addr)
			return conn, nil
		}
		c.logf("derphttp: xray: local loopback to %s failed: %v; falling back to xray underlay", addr, err)
	}

	// Ensure xray-core's outbound TCP connections bypass the tailscale
	// tunnel (via SO_MARK / netns). Must be done before any core.Dial.
	registerXRayNetnsController(c)

	port := "443"
	if !c.useHTTPS() {
		port = "80"
	}
	if n.DERPPort != 0 {
		port = fmt.Sprint(n.DERPPort)
	}

	portNum, err := xnet.PortFromString(port)
	if err != nil {
		return nil, err
	}

	dst := n.HostName
	serverName := c.tlsServerName(n)
	if serverName == "" {
		serverName = dst
	}

	coreConfig, dest, configKey, err := xrayConfigForNode(n, portNum, serverName, dst)
	if err != nil {
		return nil, err
	}
	configBytes, err := proto.Marshal(coreConfig)
	if err != nil {
		return nil, err
	}

	tunnelPath := xrayTunnelPath(n.XRay.XHTTPTunnel)
	c.logf("[v2] derphttp: dialing DERP node %q via xray underlay (tunnel=%s, path=%s, dest=%s)", n.HostName, n.XRay.XHTTPTunnel, tunnelPath, dest)
	c.logf("[v2] derphttp: xray configKey: %s", configKey)

	instance, err := c.xrayInst.getOrCreate(configKey, configBytes)
	if err != nil {
		c.logf("derphttp: xray instance start failed for %q: %v", n.HostName, err)
		return nil, err
	}

	// Use a context detached from the caller's deadline for core.Dial.
	// xray-core's VLESS outbound uses the Dial context for its internal
	// bidirectional copy goroutines (postRequest/getResponse via task.Run).
	// If the caller's context (connect's 10-second timeout) expires, it
	// would cancel the xray outbound's data-copy loops, killing the tunnel
	// even though the connection is healthy.  The tunnel's lifetime is
	// governed by closing the returned net.Conn, not by context cancellation.
	xrayCtx := context.WithoutCancel(ctx)
	c.logf("[v2] derphttp: xray: calling core.Dial to %s", dest)
	t0 := time.Now()
	conn, err := core.Dial(xrayCtx, instance, dest)
	dialDur := time.Since(t0)
	if err != nil {
		c.logf("derphttp: xray dial failed for %q after %v: %v", n.HostName, dialDur, err)
		return nil, err
	}
	c.logf("derphttp: xray tunnel established to %q (core.Dial took %v)", n.HostName, dialDur)
	return &xrayDebugConn{Conn: conn, logf: c.logf}, nil
}

// XRayDialer returns a ContextDialer that dials through the embedded xray-core
// VLESS+REALITY+XHTTP underlay for n. c is used for logging, netns bypass, and
// xray instance caching. This is used by derpbench and similar test tools to
// exercise the xray underlay without needing a separate xray SOCKS5 proxy process.
func XRayDialer(c *Client, n *tailcfg.DERPNode) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return c.dialNodeXRay(ctx, n)
	}
}

// xrayDebugConn wraps an xray connection to log unexpected read/write errors.
// Expected errors during connection teardown (closed pipe after Close) are
// suppressed to avoid noisy logs.
type xrayDebugConn struct {
	net.Conn
	logf   func(format string, args ...any)
	closed atomic.Bool
}

func (c *xrayDebugConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil && !c.closed.Load() {
		c.logf("derphttp: xray conn: Read error: %v", err)
	}
	return n, err
}

func (c *xrayDebugConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil && !c.closed.Load() {
		c.logf("derphttp: xray conn: Write error: %v", err)
	}
	return n, err
}

func (c *xrayDebugConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	return c.Conn.Close()
}

// xhttpModeForConfig returns the XHTTP upload mode to use in the xray-core
// config. When mode is empty we return "" which lets xray-core auto-select:
// with REALITY (our transport) it chooses "stream-one" — a single POST whose
// response body is the bidirectional data stream. This is required for DERP's
// HTTP upgrade to work: the upgrade request is written to the POST body and
// the 101 response is read from the same HTTP response stream.
//
// "packet-up" is incompatible with this pattern: it pre-establishes a
// separate GET stream for downloads before any writes occur, so the HTTP
// upgrade response never reaches the reader (closed pipe).
//
// "stream-one" is also acceptable for censorship evasion: REALITY's TLS
// masquerading hides the content, and a single POST+response is normal
// HTTPS traffic from the GFW's perspective. Callers may pass "stream-up"
// for higher throughput in non-censored deployments (a long-lived POST with
// separate upload/download streams).
func xhttpModeForConfig(mode string) string {
	return strings.TrimSpace(mode)
}

func xrayTunnelPath(tunnel string) string {
	trimmed := strings.TrimSpace(tunnel)
	if trimmed == "" {
		return "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return trimmed
}

func xrayConfigForNode(node *tailcfg.DERPNode, port xnet.Port, serverName, dialAddr string) (*core.Config, xnet.Destination, string, error) {
	if node == nil || node.XRay == nil {
		return nil, xnet.Destination{}, "", errors.New("xray config missing")
	}
	if node.HostName == "" {
		return nil, xnet.Destination{}, "", errors.New("xray node hostname missing")
	}
	if strings.TrimSpace(dialAddr) == "" {
		dialAddr = node.HostName
	}

	xrayCfg := node.XRay
	shortID := strings.TrimSpace(xrayCfg.RealityShortID)
	if shortID == "" {
		return nil, xnet.Destination{}, "", errors.New("xray reality short id missing")
	}

	if serverName == "" {
		serverName = node.HostName
	}

	fingerprint := strings.TrimSpace(xrayCfg.RealityFingerprint)
	if fingerprint == "" {
		fingerprint = "chrome"
	}

	realityServerName := strings.TrimSpace(xrayCfg.RealityServerName)
	if realityServerName == "" {
		realityServerName = serverName
	}

	xhttpHost := realityServerName
	if xhttpHost == "" {
		xhttpHost = node.HostName
	}

	spiderX := strings.TrimSpace(xrayCfg.RealitySpiderX)
	if spiderX != "" && !strings.HasPrefix(spiderX, "/") {
		spiderX = "/" + spiderX
	}

	// stream-up sends one continuous HTTP POST for the upload
	// direction instead of a new POST per chunk (packet-up).
	// packet-up (the "auto" default on HTTP/1.1) caps throughput
	// at roughly batch_size / max(RTT, ScMinPostsIntervalMs=30ms),
	// which limits a single DERP relay connection to ~15-40 Mbps.
	// stream-up eliminates the per-POST round-trip overhead and
	// matches the server-side "stream-up" configuration.
	tunnelPath := xrayTunnelPath(xrayCfg.XHTTPTunnel)
	xhttpMode := xhttpModeForConfig(xrayCfg.XHTTPMode)

	// Build the config protos directly (see xray_config_proto.go) instead
	// of going through infra/conf, which links every xray protocol into
	// the binary. Equivalence with the old conf-based construction is
	// enforced by TestXrayProtoConfigEquivalence.
	coreConfig, err := buildXrayCoreProtoConfig(xrayProtoParams{
		dialAddr:          dialAddr,
		port:              uint16(port),
		clientUUID:        xrayCfg.ClientUUID,
		serverPublicKey:   xrayCfg.ServerPublicKey,
		realityShortID:    shortID,
		fingerprint:       fingerprint,
		realityServerName: realityServerName,
		spiderX:           spiderX,
		xhttpHost:         xhttpHost,
		tunnelPath:        tunnelPath,
		xhttpMode:         xhttpMode,
	})
	if err != nil {
		return nil, xnet.Destination{}, "", err
	}

	// Build a config key for instance caching. If any of these fields
	// change the xray-core instance needs to be recreated.
	configKey := strings.Join([]string{
		dialAddr, fmt.Sprint(port),
		xrayCfg.ClientUUID, xrayCfg.ServerPublicKey,
		xrayCfg.XHTTPTunnel, shortID, fingerprint,
		realityServerName, spiderX, xhttpMode,
	}, "|")

	dest := xnet.TCPDestination(xnet.ParseAddress(dialAddr), port)
	return coreConfig, dest, configKey, nil
}
