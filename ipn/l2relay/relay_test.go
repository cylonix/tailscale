// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package l2relay

import (
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
	"tailscale.com/wgengine/filter"
)

type testBackend struct {
	nm *netmap.NetworkMap
}

func (b *testBackend) NetMon() *netmon.Monitor                                   { return nil }
func (b *testBackend) NetMap() *netmap.NetworkMap                                { return b.nm }
func (b *testBackend) L2DiscoveryAllowed(src, dst netip.Addr, proto string) bool { return true }
func (b *testBackend) Dialer() *tsdial.Dialer                                    { return nil }
func (b *testBackend) Filter() *filter.Filter                                    { return nil }
func (b *testBackend) PeerAPIBase(peer tailcfg.NodeView) string                  { return "" }

func TestL2RelayDuplicateDetection(t *testing.T) {
	m := newL2RelayManager(&testBackend{})
	env := &l2RelayEnvelope{
		OriginNodeID: 1,
		OriginBootID: "boot",
		Seq:          42,
		Proto:        l2ProtoMDNS,
	}
	if dup := m.isDuplicate(env); dup {
		t.Fatal("first message should not be duplicate")
	}
	if dup := m.isDuplicate(env); !dup {
		t.Fatal("second message should be duplicate")
	}
}

func TestL2RelayLeaderElectionByRank(t *testing.T) {
	m := newL2RelayManager(&testBackend{})
	m.selfNodeID = 10
	m.segmentID = "seg-a"
	m.segmentStrong = true
	m.rank = 100

	from := (&tailcfg.Node{
		ID: tailcfg.NodeID(20),
	}).View()
	m.recordHello(from, l2RelayHello{
		SegmentID:     "seg-a",
		SegmentStrong: true,
		Rank:          200,
		At:            time.Now(),
	})
	leader := m.leaderBySeg["seg-a"]
	if leader.LeaderID != 20 {
		t.Fatalf("leader id=%v, want 20", leader.LeaderID)
	}

	m.recordHello((&tailcfg.Node{
		ID: tailcfg.NodeID(30),
	}).View(), l2RelayHello{
		SegmentID:     "seg-a",
		SegmentStrong: true,
		Rank:          50,
		At:            time.Now(),
	})
	leader = m.leaderBySeg["seg-a"]
	if leader.LeaderID != 20 {
		t.Fatalf("leader changed to %v unexpectedly", leader.LeaderID)
	}
}

func TestL2RelayWeakSegmentNoSuppression(t *testing.T) {
	m := newL2RelayManager(&testBackend{})
	m.selfNodeID = 10
	m.segmentID = "seg-weak"
	m.segmentStrong = false
	m.rank = 100
	m.selfCanRelayQuery = true
	m.leaderBySeg["seg-weak"] = l2RelayLeader{
		SegmentID: "seg-weak",
		LeaderID:  20,
		LeaseTill: time.Now().Add(10 * time.Second),
	}
	if !m.canForwardCaptured() {
		t.Fatal("weak segment should not be suppressed by leader record")
	}
}

func TestL2RelayRecordLeader(t *testing.T) {
	m := newL2RelayManager(&testBackend{})
	msg := l2RelayLeader{
		SegmentID: "seg-b",
		LeaderID:  tailcfg.NodeID(7),
		LeaseTill: time.Now().Add(10 * time.Second),
	}
	m.recordLeader((&tailcfg.Node{ID: 7}).View(), msg)
	got, ok := m.leaderBySeg["seg-b"]
	if !ok || got.LeaderID != 7 {
		t.Fatalf("leader record missing/invalid: %+v", got)
	}
}

func TestRewriteSSDPForPeer(t *testing.T) {
	in := "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nLOCATION: http://192.168.0.2:631/ipp/print\r\n\r\n"
	out := string(rewriteSSDPForPeer([]byte(in), netip.MustParseAddr("100.64.0.5")))
	if !strings.Contains(out, "LOCATION: http://100.64.0.5:631/ipp/print") {
		t.Fatalf("rewritten LOCATION missing, got: %q", out)
	}
}

func TestRewriteWSDResponseXAddrsHost(t *testing.T) {
	in := []byte(`<?xml version="1.0" encoding="UTF-8"?><soap:Envelope><soap:Body><wsd:ProbeMatches><wsd:ProbeMatch><wsd:XAddrs>http://Randy-ds124-4T:5357/d62da19f-c076-4f87-841f-21f7b8ba76e3</wsd:XAddrs></wsd:ProbeMatch></wsd:ProbeMatches></soap:Body></soap:Envelope>`)
	out, changed := rewriteWSDResponseXAddrsHost(in, "nas.example.ts.net")
	if !changed {
		t.Fatal("expected xaddr rewrite")
	}
	if got := string(out); !strings.Contains(got, "<wsd:XAddrs>http://nas.example.ts.net:5357/d62da19f-c076-4f87-841f-21f7b8ba76e3</wsd:XAddrs>") {
		t.Fatalf("rewritten XAddrs missing, got: %q", got)
	}
}

func TestRewriteWSDResponseXAddrsHostMultiple(t *testing.T) {
	in := []byte(`<wsd:XAddrs>http://foo:5357/a https://bar/b</wsd:XAddrs>`)
	out, changed := rewriteWSDResponseXAddrsHost(in, "peer.tailnet.ts.net")
	if !changed {
		t.Fatal("expected xaddr rewrite")
	}
	if got := string(out); got != `<wsd:XAddrs>http://peer.tailnet.ts.net:5357/a https://peer.tailnet.ts.net/b</wsd:XAddrs>` {
		t.Fatalf("unexpected rewrite: %q", got)
	}
}

func TestRewriteWSDResponseXAddrsForcePort(t *testing.T) {
	in := []byte(`<wsd:XAddrs>http://foo:5357/a https://bar/b</wsd:XAddrs>`)
	out, changed := rewriteWSDResponseXAddrs(in, "peer.tailnet.ts.net", l2RelayWSDProxyPort)
	if !changed {
		t.Fatal("expected xaddr rewrite")
	}
	if got := string(out); got != `<wsd:XAddrs>http://peer.tailnet.ts.net:35357/a https://peer.tailnet.ts.net:35357/b</wsd:XAddrs>` {
		t.Fatalf("unexpected rewrite: %q", got)
	}
}

func TestRewriteWSDHTTPPubComputerHost(t *testing.T) {
	in := []byte(`<pub:Computer>Randy-ds124-4T/Workgroup:WORKGROUP</pub:Computer>`)
	out, changed := rewriteWSDHTTPPubComputerHost(in, "randy-ds124-4t.cy317840.cylonix.org")
	if !changed {
		t.Fatal("expected pub:Computer rewrite")
	}
	got := string(out)
	want := `<pub:Computer>randy-ds124-4t.cy317840.cylonix.org/Workgroup:WORKGROUP</pub:Computer>`
	if got != want {
		t.Fatalf("unexpected rewrite: got=%q want=%q", got, want)
	}
}

func TestWSDQueryShapedWithWSDPrefix(t *testing.T) {
	payload := []byte(`<?xml version="1.0"?><soap:Envelope><soap:Body><wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe></soap:Body></soap:Envelope>`)
	if !isWSDQueryShaped(payload) {
		t.Fatal("expected wsd prefixed probe to be query-shaped")
	}
	_, interested, ok := summarizeWSDPacket(payload)
	if !ok || !interested {
		t.Fatalf("expected interested=true for prefixed probe, ok=%v interested=%v", ok, interested)
	}
}

func TestWSDQueryShapedWithDiscoveryActionURL(t *testing.T) {
	payload := []byte(`<?xml version="1.0"?><soap:Envelope><soap:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action></soap:Header></soap:Envelope>`)
	if !isWSDQueryShaped(payload) {
		t.Fatal("expected discovery action URL to be query-shaped")
	}
	_, interested, ok := summarizeWSDPacket(payload)
	if !ok || !interested {
		t.Fatalf("expected interested=true for discovery action URL, ok=%v interested=%v", ok, interested)
	}
}

func TestSummarizeDiscoveryPayloadSSDPPrinter(t *testing.T) {
	p := []byte("NOTIFY * HTTP/1.1\r\nST: upnp:rootdevice\r\nLOCATION: http://192.168.0.2:631/ipp/print\r\nSERVER: CUPS/2.4\r\n\r\n")
	summary, printerLike := summarizeDiscoveryPayload(l2ProtoSSDP, p)
	if !printerLike {
		t.Fatal("expected printer_like for SSDP payload with ipp printer endpoint")
	}
	if !strings.Contains(summary, "location=") {
		t.Fatalf("expected location field in summary, got: %q", summary)
	}
}

func TestFilterRelayOnlinePeers(t *testing.T) {
	m := newL2RelayManager(&testBackend{})
	in := []tailcfg.NodeView{
		(&tailcfg.Node{
			ID:     1,
			Cap:    tailcfg.L2RelaySupportCapabilityVersion,
			CapMap: tailcfg.NodeCapMap{tailcfg.NodeCanInjectL2Discovery: []tailcfg.RawMessage{"can inject"}},
			Online: ptr.To(true),
		}).View(),
		(&tailcfg.Node{ID: 2, Cap: tailcfg.L2RelaySupportCapabilityVersion, Online: ptr.To(false)}).View(),
		(&tailcfg.Node{ID: 3, Cap: tailcfg.L2RelaySupportCapabilityVersion}).View(),
	}
	got := m.filterRelayOnlinePeers(in, "test")
	if len(got) != 1 {
		t.Fatalf("filtered len=%d, want 1", len(got))
	}
	if got[0].ID() != 1 {
		t.Fatalf("filtered id=%v, want 1", got[0].ID())
	}
}

func TestParseMinecraftAD(t *testing.T) {
	cases := []struct {
		payload  string
		wantPort uint16
		wantOK   bool
	}{
		{"[MOTD]My Server[/MOTD][AD]25565[/AD]", 25565, true},
		{"[AD] 19132 [/AD]", 19132, true},
		{"[AD]0[/AD]", 0, false},
		{"no tags here", 0, false},
		{"[AD][/AD]", 0, false},
		{"[AD]99999[/AD]", 0, false},
	}
	for _, c := range cases {
		port, ok := parseMinecraftAD([]byte(c.payload))
		if ok != c.wantOK || port != c.wantPort {
			t.Errorf("parseMinecraftAD(%q) = (%d, %v), want (%d, %v)", c.payload, port, ok, c.wantPort, c.wantOK)
		}
	}
}

func TestRewriteMinecraftAD(t *testing.T) {
	original := []byte("[MOTD]Test Server[/MOTD][AD]25565[/AD]")
	out, changed := rewriteMinecraftAD(original, 12345)
	if !changed {
		t.Fatal("expected change")
	}
	if got := string(out); got != "[MOTD]Test Server[/MOTD][AD]12345[/AD]" {
		t.Fatalf("unexpected rewrite: %q", got)
	}
	// Rewriting to same port should not change.
	_, changed = rewriteMinecraftAD(out, 12345)
	if changed {
		t.Fatal("same port should not change")
	}
}

func TestMinecraftProxy(t *testing.T) {
	// Start a real TCP server that echoes "MINECRAFT_OK".
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serverPort := uint16(ln.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("MINECRAFT_OK"))
			}(c)
		}
	}()

	// Set up manager with a peer at 127.0.0.1 (the test TCP server).
	const originID = tailcfg.NodeID(42)
	b := &testBackend{nm: &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID:        100,
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")},
		}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				ID:        originID,
				Addresses: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
			}).View(),
		},
	}}
	m := newL2RelayManager(b)

	var injectedPayload []byte
	m.injectPacketHook = func(_ l2RelayProto, payload []byte) {
		injectedPayload = append([]byte(nil), payload...)
	}

	env := &l2RelayEnvelope{
		OriginNodeID:        originID,
		MinecraftServerPort: serverPort,
		Payload:             []byte("[MOTD]Test[/MOTD][AD]25565[/AD]"),
	}
	m.injectMinecraftWithProxy(netip.AddrPort{}, env)

	if injectedPayload == nil {
		t.Fatal("inject hook was not called")
	}
	proxyPort, ok := parseMinecraftAD(injectedPayload)
	if !ok || proxyPort == 0 {
		t.Fatalf("injected payload has no valid [AD]port[/AD]: %q", injectedPayload)
	}
	if proxyPort == 25565 {
		t.Fatalf("port was not rewritten (still 25565)")
	}

	// Connect to the proxy port and verify end-to-end.
	conn, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(proxyPort))))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if got := string(buf[:n]); got != "MINECRAFT_OK" {
		t.Fatalf("proxy response: %q, want %q", got, "MINECRAFT_OK")
	}
}

func TestL2RelayUDPHandlerPathE2E(t *testing.T) {
	b := &testBackend{nm: &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID:        100,
			CapMap:    tailcfg.NodeCapMap{tailcfg.NodeCanInjectL2Discovery: []tailcfg.RawMessage{"can inject"}},
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")},
		}).View(),
	}}
	m := newL2RelayManager(b)
	m.selfCanRelayQuery = true

	src := netip.MustParseAddrPort("100.64.0.20:41000")
	dst := netip.MustParseAddrPort("100.64.0.10:41642")
	handler, intercept := m.udpHandlerForFlow(src, dst)
	if !intercept || handler == nil {
		t.Fatalf("udpHandlerForFlow intercept=%v handlerNil=%v, want true,false", intercept, handler == nil)
	}

	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer ln.Close()

	go handler(ln)

	c, err := net.DialUDP("udp4", nil, ln.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer c.Close()

	raw, err := json.Marshal(l2RelayEnvelope{
		OriginNodeID: 200,
		OriginBootID: "boot",
		Seq:          1,
		Proto:        l2ProtoWSD,
		Hops:         1,
		Payload:      []byte(`<?xml version="1.0"?><soap:Envelope><soap:Body><wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe></soap:Body></soap:Envelope>`),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := c.Write(raw); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(m.recentMessage) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for envelope processing")
}
