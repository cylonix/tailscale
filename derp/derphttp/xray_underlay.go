// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"context"
	"encoding/json"
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
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"

	// xray-core requires these blank imports so that init() functions
	// register protobuf types (e.g. proxyman.InboundConfig) and handlers
	// before core.StartInstance is called.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	// DNS, logging, routing, and policy are referenced by the default config.
	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/router"

	// VLESS outbound proxy.
	_ "github.com/xtls/xray-core/proxy/vless/outbound"

	// Freedom outbound (used as direct connector by default config).
	_ "github.com/xtls/xray-core/proxy/freedom"

	// Transports and TLS needed for REALITY + XHTTP.
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"

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
		c.logf("derphttp: xray: attempting local loopback to %s", addr)
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
	c.logf("derphttp: dialing DERP node %q via xray underlay (tunnel=%s, path=%s, dest=%s)", n.HostName, n.XRay.XHTTPTunnel, tunnelPath, dest)
	c.logf("derphttp: xray configKey: %s", configKey)

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
	c.logf("derphttp: xray: calling core.Dial to %s", dest)
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

	vlessSettings := conf.VLessOutboundConfig{
		Address:    &conf.Address{Address: xnet.ParseAddress(dialAddr)},
		Port:       uint16(port),
		Id:         xrayCfg.ClientUUID,
		Flow:       "", // vision flow is incompatible with xhttp transport
		Encryption: "none",
	}
	settingsBytes, err := json.Marshal(&vlessSettings)
	if err != nil {
		return nil, xnet.Destination{}, "", err
	}
	settings := json.RawMessage(settingsBytes)

	transport := conf.TransportProtocol("xhttp")
	tunnelPath := xrayTunnelPath(xrayCfg.XHTTPTunnel)
	stream := &conf.StreamConfig{
		Network:  &transport,
		Security: "reality",
		REALITYSettings: &conf.REALITYConfig{
			ServerName:  realityServerName,
			PublicKey:   xrayCfg.ServerPublicKey,
			ShortId:     shortID,
			Fingerprint: fingerprint,
			SpiderX:     spiderX,
		},
		XHTTPSettings: &conf.SplitHTTPConfig{
			Host: xhttpHost,
			Path: tunnelPath,
		},
	}

	config := &conf.Config{
		LogConfig: &conf.LogConfig{LogLevel: "warning"},
		OutboundConfigs: []conf.OutboundDetourConfig{
			{
				Protocol:      "vless",
				Settings:      &settings,
				StreamSetting: stream,
			},
		},
	}

	coreConfig, err := config.Build()
	if err != nil {
		return nil, xnet.Destination{}, "", err
	}

	// Build a config key for instance caching. If any of these fields
	// change the xray-core instance needs to be recreated.
	configKey := strings.Join([]string{
		dialAddr, fmt.Sprint(port),
		xrayCfg.ClientUUID, xrayCfg.ServerPublicKey,
		xrayCfg.XHTTPTunnel, shortID, fingerprint,
		realityServerName, spiderX,
	}, "|")

	dest := xnet.TCPDestination(xnet.ParseAddress(dialAddr), port)
	return coreConfig, dest, configKey, nil
}
