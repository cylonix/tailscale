// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package l2relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/filter"
)

var (
	multicastMDNS      = netip.MustParseAddr("224.0.0.251")
	multicastWSD       = netip.MustParseAddr("239.255.255.250")
	multicastMinecraft = netip.MustParseAddr("224.0.2.60")
	cgnatRange         = netip.MustParsePrefix("100.64.0.0/10")
)

const (
	l2RelayDataPort = 41642
	l2RelayReadTTL  = 3 * time.Second
	l2RelayMaxSize  = 64 << 10
	// Keep peer relay sends short to avoid head-of-line stalls in capture paths.
	l2RelayPeerSendTimeout = 5 * time.Second
	// Bound concurrent relay HTTP sends so bursty multicast capture doesn't
	// fan out unbounded goroutines.
	l2RelayMaxConcurrentPeerSends = 8
)

type l2RelayProto string

const (
	l2ProtoMDNS      l2RelayProto = "mdns"
	l2ProtoSSDP      l2RelayProto = "ssdp"
	l2ProtoWSD       l2RelayProto = "wsd"
	l2ProtoNetBIOS   l2RelayProto = "netbios"
	l2ProtoMinecraft l2RelayProto = "minecraft"
)

type l2RelayEnvelope struct {
	OriginNodeID    tailcfg.NodeID `json:"origin_node_id"`
	OriginBootID    string         `json:"origin_boot_id"`
	Seq             uint64         `json:"seq"`
	Proto           l2RelayProto   `json:"proto"`
	Hops            uint8          `json:"hops"`
	MDNSQuerySig    string         `json:"mdns_query_sig,omitempty"`
	MDNSQueryKey    string         `json:"mdns_query_key,omitempty"`
	WSDQueryKey     string         `json:"wsd_query_key,omitempty"`
	NetBIOSQueryKey string         `json:"netbios_query_key,omitempty"`
	NetBIOSPort     uint16         `json:"netbios_port,omitempty"`
	// MinecraftServerPort is set when the Minecraft server runs on the same node
	// as the capturing Cylonix agent. The remote injector uses this to set up a
	// TCP proxy to the origin node's Tailscale IP, enabling cross-LAN play without
	// subnet routing.
	MinecraftServerPort uint16 `json:"minecraft_server_port,omitempty"`
	// MDNSReplySourceIP carries the source IP of a unicast mDNS reply captured via PAT.
	// The destination peer may use this as a fallback target when SRV target A records are absent.
	MDNSReplySourceIP string `json:"mdns_reply_source_ip,omitempty"`
	Payload           []byte `json:"payload"`
}

type l2RelayHello struct {
	SegmentID     string    `json:"segment_id"`
	SegmentStrong bool      `json:"segment_strong,omitempty"`
	Rank          uint64    `json:"rank"`
	RelayDataPort uint16    `json:"relay_data_port,omitempty"`
	At            time.Time `json:"at"`
}

type l2RelayLeader struct {
	SegmentID string         `json:"segment_id"`
	LeaderID  tailcfg.NodeID `json:"leader_id"`
	LeaseTill time.Time      `json:"lease_till"`
}

type l2RelayPeerState struct {
	segmentID     string
	segmentStrong bool
	rank          uint64
	relayDataPort uint16
	lastHello     time.Time
	lastSeen      time.Time
}

type mdnsPATDestination struct {
	querier netip.AddrPort
	at      time.Time
}

type mdnsAliasTarget struct {
	target string
	at     time.Time
}

type minecraftProxy struct {
	localPort uint16
	cancel    func()
	lastSeen  time.Time
}

type l2RelayManager struct {
	b Backend

	bootID string
	seq    atomic.Uint64

	mu                 sync.Mutex
	selfNodeID         tailcfg.NodeID
	selfCanRelayQuery  bool
	selfCanInjectQuery bool
	segmentID          string
	segmentStrong      bool
	rank               uint64
	peers              map[tailcfg.NodeID]l2RelayPeerState
	leaderBySeg        map[string]l2RelayLeader
	recentMessage      map[string]time.Time
	recentInjected     map[string]time.Time
	recentSummary      map[string]time.Time
	recentCaptured     map[string]time.Time
	mdnsQuerier4       netip.AddrPort
	mdnsQuerier4At     time.Time
	mdnsQuerier6       netip.AddrPort
	mdnsQuerier6At     time.Time
	mdnsPATByQuery     map[string]mdnsPATDestination
	wsdPATByQuery      map[string]mdnsPATDestination
	netbiosPATByQuery  map[string]mdnsPATDestination
	mdnsAliasByName    map[string]mdnsAliasTarget
	proxyByUpstream    map[string]*l2RelayTCPProxy
	mcProxies          map[string]*minecraftProxy // keyed by "originNodeID:serverPort"

	captureParent    context.Context
	captureCancel    context.CancelFunc
	captureEnabled   bool
	unregisterNetMon func()
	sendSem          chan struct{}

	// test hooks
	sendEnvelopeHook func(dst netip.Addr, env l2RelayEnvelope)
	injectPacketHook func(proto l2RelayProto, payload []byte)
}

type l2RelayTCPProxy struct {
	key       string
	relayBase string
	upstream  string
	localPort uint16
	ln        net.Listener
}

// Logging with normal rate limiting.
var (
	limitedLogf = logger.RateLimitedFn(log.Printf, 10*time.Second, 5, 50)
	logf        = logger.RateLimitedFn(log.Printf, 1*time.Second, 10, 50)
)

func (m *l2RelayManager) logf(format string, args ...any) {
	if debugL2RelayVerbose() || runtime.GOOS == "windows" {
		format = strings.TrimPrefix(format, "[v1] ")
		format = strings.TrimPrefix(format, "[v2] ")
		log.Printf(format, args...)
		return
	}
	logf(format, args...)
}

func (m *l2RelayManager) limitedLogf(format string, args ...any) {
	if debugL2RelayVerbose() || runtime.GOOS == "windows" {
		format = strings.TrimPrefix(format, "[v1] ")
		format = strings.TrimPrefix(format, "[v2] ")
		log.Printf(format, args...)
		return
	}
	limitedLogf(format, args...)
}

func (m *l2RelayManager) lockRelayMu(caller string) time.Time {
	waitStart := time.Now()
	m.mu.Lock()
	lockedAt := time.Now()
	if debugL2RelayLock() {
		m.logf("l2relay: lock acquire caller=%q wait=%s", caller, lockedAt.Sub(waitStart))
	}
	return lockedAt
}

func (m *l2RelayManager) unlockRelayMu(caller string, lockedAt time.Time) {
	if debugL2RelayLock() {
		m.logf("l2relay: lock release caller=%q held=%s", caller, time.Since(lockedAt))
	}
	m.mu.Unlock()
}

var (
	debugL2RelayEnabledOpt = envknob.RegisterOptBool("TS_DEBUG_L2RELAY_ENABLED")

	// Use lookup per call for now during beta to allow turning on and off
	// verbose logging. If this becomes a performance concern, we can switch t
	// either check this value at each hello tick or only during initialization.
	debugL2RelayVerbose = envknob.RegisterBoolWithLookUpPerCall("TS_DEBUG_L2RELAY_VERBOSE")
)

func debugL2RelayEnabled() bool {
	if v, ok := debugL2RelayEnabledOpt().Get(); ok {
		return v
	}
	return true
}

func newL2RelayManager(b Backend) *l2RelayManager {
	if !debugL2RelayEnabled() {
		return nil
	}
	nm := b.NetMap()
	var selfNodeID tailcfg.NodeID
	var selfCanRelayQuery bool
	var selfCanInjectQuery bool
	if nm != nil && nm.SelfNode.Valid() {
		selfNodeID = nm.SelfNode.ID()
		selfCanRelayQuery = nm.SelfNode.HasCap(tailcfg.NodeCanRelayL2Discovery)
		selfCanInjectQuery = nm.SelfNode.HasCap(tailcfg.NodeCanInjectL2Discovery) ||
			nm.SelfNode.HasCap(tailcfg.NodeHasL2DiscoverableService)
	}
	m := &l2RelayManager{
		b:                  b,
		bootID:             randomBootID(),
		selfNodeID:         selfNodeID,
		selfCanRelayQuery:  selfCanRelayQuery,
		selfCanInjectQuery: selfCanInjectQuery,
		peers:              make(map[tailcfg.NodeID]l2RelayPeerState),
		leaderBySeg:        make(map[string]l2RelayLeader),
		recentMessage:      make(map[string]time.Time),
		recentInjected:     make(map[string]time.Time),
		recentSummary:      make(map[string]time.Time),
		recentCaptured:     make(map[string]time.Time),
		mdnsPATByQuery:     make(map[string]mdnsPATDestination),
		wsdPATByQuery:      make(map[string]mdnsPATDestination),
		netbiosPATByQuery:  make(map[string]mdnsPATDestination),
		mdnsAliasByName:    make(map[string]mdnsAliasTarget),
		proxyByUpstream:    make(map[string]*l2RelayTCPProxy),
		mcProxies:          make(map[string]*minecraftProxy),
		captureEnabled:     true,
		sendSem:            make(chan struct{}, l2RelayMaxConcurrentPeerSends),
	}
	if mon := b.NetMon(); mon != nil {
		m.unregisterNetMon = mon.RegisterChangeCallback(m.onNetworkChange)
	}
	m.logf("l2relay: manager init bootID=%q", m.bootID)
	return m
}

// l2DiscoveryAllowed reports whether discovery relay traffic should be allowed.
// The decision is an AND of L3 policy and explicit L2 discovery policy rules.
func (m *l2RelayManager) l2DiscoveryAllowed(src, dst netip.Addr, proto string, isInput bool) bool {
	nm := m.b.NetMap()
	if nm == nil {
		return false
	}
	var rules []tailcfg.L2DiscoveryRule
	rules = nm.L2DiscoveryRules.AsSlice()
	return allowed(src, dst, proto, isInput, m.b.Filter(), rules, m.logf)
}

func (m *l2RelayManager) shouldLogSummarySig(sig string) bool {
	if sig == "" {
		return true
	}
	now := time.Now()
	lockedAt := m.lockRelayMu("shouldLogSummarySig")
	defer m.unlockRelayMu("shouldLogSummarySig", lockedAt)
	for k, at := range m.recentSummary {
		if now.Sub(at) > 5*time.Second {
			delete(m.recentSummary, k)
		}
	}
	if at, ok := m.recentSummary[sig]; ok && now.Sub(at) <= time.Second {
		return false
	}
	m.recentSummary[sig] = now
	return true
}

func (m *l2RelayManager) shouldSuppressCapturedSig(proto l2RelayProto, src string, sig string, window time.Duration) bool {
	if src == "" || sig == "" || window <= 0 {
		return false
	}
	key := string(proto) + "|" + src + "|" + sig
	now := time.Now()
	lockedAt := m.lockRelayMu("shouldSuppressCapturedSig")
	defer m.unlockRelayMu("shouldSuppressCapturedSig", lockedAt)
	for k, at := range m.recentCaptured {
		if now.Sub(at) > window {
			delete(m.recentCaptured, k)
		}
	}
	if at, ok := m.recentCaptured[key]; ok && now.Sub(at) <= window {
		return true
	}
	m.recentCaptured[key] = now
	return false
}

func randomBootID() string {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Best-effort fallback; format still deterministic enough for dedupe keys.
		return fmt.Sprintf("boot-%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

func (m *l2RelayManager) setNetMap(nm *netmap.NetworkMap) {
	var cancel context.CancelFunc
	var startCtx context.Context
	lockedAt := m.lockRelayMu("setNetMap")
	defer func() {
		m.unlockRelayMu("setNetMap", lockedAt)
		if cancel != nil {
			cancel()
		}
		if startCtx != nil {
			m.startCaptureLoops(startCtx)
		}
	}()
	oldCanRelay := m.selfCanRelayQuery
	oldCanInject := m.selfCanInjectQuery
	if nm != nil && nm.SelfNode.Valid() {
		m.selfNodeID = nm.SelfNode.ID()
		m.selfCanRelayQuery = nm.SelfNode.HasCap(tailcfg.NodeCanRelayL2Discovery)
		m.selfCanInjectQuery = nm.SelfNode.HasCap(tailcfg.NodeCanInjectL2Discovery) ||
			nm.SelfNode.HasCap(tailcfg.NodeHasL2DiscoverableService)
	} else {
		m.selfNodeID = 0
		m.selfCanRelayQuery = false
		m.selfCanInjectQuery = false
	}
	m.segmentID, m.segmentStrong, m.rank = m.computeSegmentLocked(nm)
	if oldCanRelay != m.selfCanRelayQuery || oldCanInject != m.selfCanInjectQuery {
		m.logf("l2relay: setNetMap self caps changed relay(old=%v new=%v) inject(old=%v new=%v)",
			oldCanRelay, m.selfCanRelayQuery, oldCanInject, m.selfCanInjectQuery)
	}
	m.limitedLogf("[v2] l2relay: setNetMap selfNodeID=%d canRelay=%v canInject=%v segmentID=%q strong=%v rank=%d",
		m.selfNodeID, m.selfCanRelayQuery, m.selfCanInjectQuery, m.segmentID, m.segmentStrong, m.rank)
	cancel, startCtx = m.reconcileCaptureStateLocked("setNetMap")
}

func (m *l2RelayManager) startCapture(ctx context.Context) {
	if ctx == nil {
		return
	}
	var cancel context.CancelFunc
	var startCtx context.Context
	lockedAt := m.lockRelayMu("startCapture")
	if m.captureParent == nil {
		m.captureParent = ctx
	}
	cancel, startCtx = m.reconcileCaptureStateLocked("startCapture")
	m.unlockRelayMu("startCapture", lockedAt)
	if cancel != nil {
		cancel()
	}
	if startCtx != nil {
		m.startCaptureLoops(startCtx)
	}
}

func (m *l2RelayManager) close() {
	lockedAt := m.lockRelayMu("close")
	cancel := m.captureCancel
	unregisterNetMon := m.unregisterNetMon
	m.captureCancel = nil
	m.captureParent = nil
	m.unregisterNetMon = nil
	m.unlockRelayMu("close", lockedAt)

	if cancel != nil {
		cancel()
	}
	if unregisterNetMon != nil {
		unregisterNetMon()
	}
}

func (m *l2RelayManager) unregisterNetworkChangeCallback() {
	lockedAt := m.lockRelayMu("unregisterNetworkChangeCallback")
	unregisterNetMon := m.unregisterNetMon
	m.unregisterNetMon = nil
	m.unlockRelayMu("unregisterNetworkChangeCallback", lockedAt)

	if unregisterNetMon != nil {
		unregisterNetMon()
	}
}

func (m *l2RelayManager) setCaptureEnabled(enabled bool) {
	var cancel context.CancelFunc
	var startCtx context.Context
	lockedAt := m.lockRelayMu("setCaptureEnabled")
	if m.captureEnabled == enabled {
		m.unlockRelayMu("setCaptureEnabled", lockedAt)
		return
	}
	m.captureEnabled = enabled
	cancel, startCtx = m.reconcileCaptureStateLocked("setCaptureEnabled")
	m.unlockRelayMu("setCaptureEnabled", lockedAt)
	if cancel != nil {
		cancel()
	}
	if startCtx != nil {
		m.startCaptureLoops(startCtx)
	}
}

func (m *l2RelayManager) captureEnabledState() bool {
	lockedAt := m.lockRelayMu("captureEnabledState")
	defer m.unlockRelayMu("captureEnabledState", lockedAt)
	return m.captureEnabled
}

func (m *l2RelayManager) onNetworkChange(delta *netmon.ChangeDelta) {
	if delta == nil || (!delta.Major && !delta.TimeJumped) {
		return
	}
	nm := m.b.NetMap()
	var cancel context.CancelFunc
	var startCtx context.Context
	lockedAt := m.lockRelayMu("onNetworkChange")
	m.segmentID, m.segmentStrong, m.rank = m.computeSegmentLocked(nm)
	m.logf("l2relay: netmon change major=%v time_jumped=%v segmentID=%q strong=%v rank=%d", delta.Major, delta.TimeJumped, m.segmentID, m.segmentStrong, m.rank)
	cancel, startCtx = m.restartCaptureLocked("network-change")
	m.unlockRelayMu("onNetworkChange", lockedAt)
	if cancel != nil {
		cancel()
	}
	if startCtx != nil {
		m.startCaptureLoops(startCtx)
	}
}

func (m *l2RelayManager) shouldRunCaptureLocked() bool {
	return m.captureParent != nil && m.captureEnabled && m.selfCanRelayQuery
}

func (m *l2RelayManager) reconcileCaptureStateLocked(reason string) (cancel context.CancelFunc, startCtx context.Context) {
	shouldRun := m.shouldRunCaptureLocked()
	if !shouldRun {
		if m.captureCancel != nil {
			cancel = m.captureCancel
			m.captureCancel = nil
			m.logf("l2relay: capture stop reason=%s", reason)
		}
		return cancel, nil
	}
	if m.captureCancel == nil {
		startCtx, m.captureCancel = context.WithCancel(m.captureParent)
		m.logf("l2relay: capture start reason=%s", reason)
	}
	return cancel, startCtx
}

func (m *l2RelayManager) restartCaptureLocked(reason string) (cancel context.CancelFunc, startCtx context.Context) {
	if !m.shouldRunCaptureLocked() {
		return m.reconcileCaptureStateLocked(reason)
	}
	if m.captureCancel != nil {
		cancel = m.captureCancel
	}
	startCtx, m.captureCancel = context.WithCancel(m.captureParent)
	m.logf("l2relay: capture restart reason=%s", reason)
	return cancel, startCtx
}

func (m *l2RelayManager) startCaptureLoops(ctx context.Context) {
	m.logf("l2relay: starting multicast capture loops")
	go m.startIPv4MulticastCapture(ctx, l2ProtoMDNS)
	//go m.startIPv4MulticastCapture(ctx, l2ProtoSSDP)
	go m.startIPv4MulticastCapture(ctx, l2ProtoWSD)
	go m.startIPv4MulticastCapture(ctx, l2ProtoMinecraft)
	//go m.captureNetBIOSLoop(ctx, 137)
	//go m.captureNetBIOSLoop(ctx, 138)
	//go m.captureMulticastLoopV6(ctx, l2ProtoMDNS)
	//go m.listenRelayUDP(ctx, "udp4", fmt.Sprintf(":%d", l2RelayDataPort))
	//go m.listenRelayUDP(ctx, "udp6", fmt.Sprintf("[::]:%d", l2RelayDataPort))
}

func (m *l2RelayManager) startIPv4MulticastCapture(ctx context.Context, proto l2RelayProto) {
	m.captureMulticastLoop(ctx, proto)
}

// tunOutboundCaptureFunc returns a tstun.FilterFunc suitable for use as
// tstun.Wrapper.PreFilterPacketOutboundCapture, or nil on platforms where it
// is not needed.
//
// On Windows, locally-sourced multicast packets are routed through the tunnel
// interface and dropped by the main filter before the OS can deliver them to
// the multicast UDP sockets that captureMulticastLoopOnInterface uses. This
// hook intercepts those packets before the filter runs so the relay can still
// observe and forward them. On all other platforms the OS multicast loopback
// delivers the packets to the socket normally, so no hook is needed.
func (m *l2RelayManager) tunOutboundCaptureFunc() tstun.FilterFunc {
	if runtime.GOOS != "windows" {
		return nil
	}
	return func(p *packet.Parsed, _ *tstun.Wrapper) filter.Response {
		m.captureFromParsedPacket(p)
		return filter.Accept
	}
}

// captureFromParsedPacket handles a packet seen via the tun outbound capture
// hook. It replicates the logic of captureMulticastLoopOnInterface for packets
// that arrive through the TUN device rather than an OS multicast socket.
func (m *l2RelayManager) captureFromParsedPacket(p *packet.Parsed) {
	if p.IPProto != ipproto.UDP {
		return
	}
	var proto l2RelayProto
	switch {
	case p.Dst.Addr() == multicastMDNS && p.Dst.Port() == 5353:
		proto = l2ProtoMDNS
	case p.Dst.Addr() == multicastWSD && p.Dst.Port() == 3702:
		proto = l2ProtoWSD
	case p.Dst.Addr() == multicastMinecraft && p.Dst.Port() == 4445:
		proto = l2ProtoMinecraft
	default:
		return
	}
	payload := p.Payload()
	if len(payload) == 0 {
		return
	}
	src := &net.UDPAddr{
		IP:   p.Src.Addr().AsSlice(),
		Port: int(p.Src.Port()),
	}
	// mDNS loop guard: injected mDNS packets use an ephemeral source port,
	// not 5353, so this check is sufficient to suppress bounce-backs.
	if proto == l2ProtoMDNS && src.Port != 5353 {
		return
	}
	// Copy payload — p.Payload() is a slice into the packet buffer which may
	// be reused after this call returns.
	buf := make([]byte, len(payload))
	copy(buf, payload)
	// Loop guard: check (sig, IP, port) against recently injected entries.
	// Covers WSD (no reliable port-based guard) and mDNS (belt-and-suspenders
	// for the case where injection bound port 5353 via SO_REUSEADDR).
	if proto == l2ProtoMDNS || proto == l2ProtoWSD || proto == l2ProtoMinecraft {
		if m.isRecentlyInjected(proto, buf, p.Src, 2*time.Second) {
			m.limitedLogf("l2relay: tun capture %s bounce-back suppressed src=%v sig=%s", proto, p.Src, relayRawSig(buf))
			return
		}
	}
	queryKey := m.observeLocalDiscoverySource(proto, src, buf)
	m.forwardCaptured(proto, buf, queryKey, src)
}

func (m *l2RelayManager) computeSegmentLocked(nm *netmap.NetworkMap) (segmentID string, segmentStrong bool, rank uint64) {
	if nm == nil {
		return "", false, 0
	}
	state := m.b.NetMon().InterfaceState()
	if state == nil {
		return "", false, 0
	}
	ifName := state.DefaultRouteInterface
	if ifName == "" {
		return "", false, 0
	}
	var pfx string
	if ipps := state.InterfaceIPs[ifName]; len(ipps) > 0 {
		p := ipps[0].Masked()
		pfx = p.String()
	}
	gw, _, _ := m.b.NetMon().GatewayAndSelfIP()
	gwMAC, gwMACOK := DefaultGatewayMAC(gw)
	segmentStrong = gwMACOK
	if !gwMACOK {
		m.limitedLogf("[v2] l2relay: segment gw-mac unavailable gw=%v", gw)
	}
	salt := nm.Domain
	in := fmt.Sprintf("segv2|pfx=%s|gw=%s|gwmac=%s", pfx, gw, gwMAC)
	sum := sha256.Sum256([]byte(salt + "|" + in))
	segmentID = base64.RawURLEncoding.EncodeToString(sum[:12])
	rank = uint64(sum[12])<<56 | uint64(sum[13])<<48 | uint64(sum[14])<<40 | uint64(sum[15])<<32 |
		uint64(sum[16])<<24 | uint64(sum[17])<<16 | uint64(sum[18])<<8 | uint64(sum[19])
	return segmentID, segmentStrong, rank
}

func (m *l2RelayManager) captureMulticastLoop(ctx context.Context, proto l2RelayProto) {
	m.captureMulticastLoopOnInterface(ctx, proto, nil)
}

func (m *l2RelayManager) captureMulticastLoopOnInterface(ctx context.Context, proto l2RelayProto, ifi *net.Interface) {
	group := ""
	port := 0
	switch proto {
	case l2ProtoMDNS:
		group, port = "224.0.0.251", 5353
	case l2ProtoSSDP:
		group, port = "239.255.255.250", 1900
	case l2ProtoWSD:
		group, port = "239.255.255.250", 3702
	case l2ProtoMinecraft:
		// Minecraft Java Edition LAN discovery: server broadcasts to 224.0.2.60:4445.
		group, port = "224.0.2.60", 4445
	default:
		return
	}

	addr := &net.UDPAddr{IP: net.ParseIP(group), Port: port}
	conn, err := net.ListenMulticastUDP("udp4", ifi, addr)
	if err != nil {
		if ifi != nil {
			m.logf("l2relay: capture listen %s failed on if=%s: %v", proto, ifi.Name, err)
		} else {
			m.logf("l2relay: capture listen %s failed: %v", proto, err)
		}
		return
	}
	if ifi != nil {
		m.logf("l2relay: capture listen %s started on if=%s %s:%d", proto, ifi.Name, group, port)
	} else {
		m.logf("l2relay: capture listen %s started on %s:%d", proto, group, port)
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(l2RelayMaxSize)

	buf := make([]byte, l2RelayMaxSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			m.logf("l2relay: capture read %s terminating: %v", proto, err)
			return
		}
		// Loop guards:
		// - mDNS: injected packets use an ephemeral source port, not 5353, so
		//   the port check here is sufficient to suppress bounce-backs.
		// - WSD/Minecraft: both real queries and injected probes use ephemeral
		//   ports, so we use isRecentlyInjected keyed on (sig, IP, port) to
		//   suppress only packets whose exact local address was used for injection.
		if n <= 0 {
			continue
		}
		if proto == l2ProtoMDNS && src.Port != port {
			m.limitedLogf("l2relay: capture invalid mdns packet src.Port %v != port %v", src.Port, port)
			continue
		}
		if proto == l2ProtoMDNS || proto == l2ProtoWSD || proto == l2ProtoMinecraft {
			if capturedSrc, ok := udpAddrPort(src); ok {
				if m.isRecentlyInjected(proto, buf[:n], capturedSrc, 2*time.Second) {
					m.limitedLogf("l2relay: capture %s bounce-back suppressed src=%v sig=%s", proto, src, relayRawSig(buf[:n]))
					continue
				}
			}
		}
		mdnsQueryKey := m.observeLocalDiscoverySource(proto, src, buf[:n])
		m.forwardCaptured(proto, buf[:n], mdnsQueryKey, src)
	}
}

func (m *l2RelayManager) captureMulticastLoopV6(ctx context.Context, proto l2RelayProto) {
	group := ""
	port := 0
	switch proto {
	case l2ProtoMDNS:
		group, port = "ff02::fb", 5353
	default:
		return
	}

	addr := &net.UDPAddr{IP: net.ParseIP(group), Port: port}
	conn, err := net.ListenMulticastUDP("udp6", nil, addr)
	if err != nil {
		m.logf("l2relay: capture v6 listen %s failed: %v", proto, err)
		return
	}
	m.logf("l2relay: capture v6 listen %s started on [%s]:%d", proto, group, port)
	defer conn.Close()
	_ = conn.SetReadBuffer(l2RelayMaxSize)

	buf := make([]byte, l2RelayMaxSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			m.logf("l2relay: capture v6 read %s terminating: %v", proto, err)
			return
		}
		if src.Port != port || n <= 0 {
			continue
		}
		if !m.allowCapturedSourceIP(src.IP) {
			m.limitedLogf("l2relay: capture v6 drop %s from disallowed src=%v", proto, src)
			continue
		}
		mdnsQueryKey := m.observeLocalDiscoverySource(proto, src, buf[:n])
		m.forwardCaptured(proto, buf[:n], mdnsQueryKey, src)
	}
}

func (m *l2RelayManager) allowCapturedSourceIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()

	st := m.b.NetMon().InterfaceState()
	if st != nil {
		ifName := st.DefaultRouteInterface
		if ifName != "" {
			pfxs := st.InterfaceIPs[ifName]
			if len(pfxs) > 0 {
				for _, pfx := range pfxs {
					if pfx.Contains(addr) {
						return true
					}
				}
			}
		}
	}

	// Fallback: permit likely-LAN source addresses when interface-prefix
	// matching is unavailable or incomplete.
	_, selfIP, ok := m.b.NetMon().GatewayAndSelfIP()
	if addr.Is4() {
		if addr.IsPrivate() || addr.IsLinkLocalUnicast() {
			return true
		}
		if ok && selfIP.Is4() {
			return netip.PrefixFrom(selfIP, 24).Contains(addr)
		}
		return false
	}
	if addr.Is6() {
		if addr.IsLinkLocalUnicast() || isIPv6UniqueLocal(addr) {
			return true
		}
		if ok && selfIP.Is6() {
			return netip.PrefixFrom(selfIP, 64).Contains(addr)
		}
		return false
	}
	return false
}

func isIPv6UniqueLocal(addr netip.Addr) bool {
	if !addr.Is6() {
		return false
	}
	b := addr.As16()
	return (b[0] & 0xfe) == 0xfc // fc00::/7
}

func (m *l2RelayManager) observeLocalDiscoverySource(proto l2RelayProto, src *net.UDPAddr, payload []byte) string {
	if src == nil {
		return ""
	}
	switch proto {
	case l2ProtoMDNS:
		if !isMDNSQueryShaped(payload) {
			return ""
		}
	case l2ProtoWSD:
		if !isWSDQueryShaped(payload) {
			return ""
		}
	case l2ProtoNetBIOS:
		if src.Port != 137 && src.Port != 138 {
			return ""
		}
		if src.Port == 137 && !isNBNSQuery(payload) {
			return ""
		}
	default:
		return ""
	}
	if _, interested := summarizeDiscoveryPayload(proto, payload); !interested {
		return ""
	}
	ap, ok := udpAddrPort(src)
	if !ok {
		return ""
	}
	sig := relayRawSig(payload)
	patSig := sig
	if proto == l2ProtoMDNS {
		// Always allocate a key for local interested mDNS queries so remote
		// forced-QU replies can be delivered back via PAT unicast.
		// If alias stripping rewrites the query before relay, track the rewritten sig
		// in logs for easier path correlation.
		if rewritten, changed, _ := m.rewriteMDNSQueryAliasToOriginal(payload); changed {
			patSig = relayRawSig(rewritten)
		}
	}
	queryKey := randomBootID()
	lockedAt := m.lockRelayMu("observeLocalDiscoverySource")
	now := time.Now()
	if ap.Addr().Is6() {
		m.mdnsQuerier6 = ap
		m.mdnsQuerier6At = now
	} else {
		m.mdnsQuerier4 = ap
		m.mdnsQuerier4At = now
	}
	if queryKey != "" {
		switch proto {
		case l2ProtoMDNS:
			for k, v := range m.mdnsPATByQuery {
				if now.Sub(v.at) > 20*time.Second {
					delete(m.mdnsPATByQuery, k)
				}
			}
			m.mdnsPATByQuery[queryKey] = mdnsPATDestination{querier: ap, at: now}
		case l2ProtoWSD:
			for k, v := range m.wsdPATByQuery {
				if now.Sub(v.at) > 20*time.Second {
					delete(m.wsdPATByQuery, k)
				}
			}
			m.wsdPATByQuery[queryKey] = mdnsPATDestination{querier: ap, at: now}
		case l2ProtoNetBIOS:
			for k, v := range m.netbiosPATByQuery {
				if now.Sub(v.at) > 20*time.Second {
					delete(m.netbiosPATByQuery, k)
				}
			}
			m.netbiosPATByQuery[queryKey] = mdnsPATDestination{querier: ap, at: now}
		}
	}
	m.unlockRelayMu("observeLocalDiscoverySource", lockedAt)
	m.limitedLogf("[v1] l2relay: %s query observed src=%v sig=%s pat_sig=%s pat_key=%s", proto, ap, sig, patSig, queryKey)
	return queryKey
}

func mdnsHostLookupQuestions(payload []byte) []string {
	var msg dnsmessage.Message
	if err := msg.Unpack(payload); err != nil {
		return nil
	}
	if msg.Header.Response {
		return nil
	}
	out := make([]string, 0, len(msg.Questions))
	seen := map[string]bool{}
	for _, q := range msg.Questions {
		if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA && q.Type != dnsmessage.TypeHTTPS {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(q.Name.String())), ".")
		if name == "" || !strings.HasSuffix(name, ".local") {
			continue
		}
		k := fmt.Sprintf("%s/%s", name, q.Type.String())
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}

func (m *l2RelayManager) forwardCaptured(proto l2RelayProto, payload []byte, queryKey string, capturedSrc *net.UDPAddr) {
	sig := relayRawSig(payload)
	if len(payload) == 0 || len(payload) > l2RelayMaxSize {
		m.limitedLogf("l2relay: drop captured proto=%s invalid size=%d", proto, len(payload))
		return
	}
	if !m.canForwardCaptured() {
		m.limitedLogf("l2relay: drop captured proto=%s not leader or not enabled to relay query", proto)
		return
	}
	nm := m.b.NetMap()
	if nm == nil || !nm.SelfNode.Valid() {
		m.limitedLogf("l2relay: drop captured proto=%s no netmap/self", proto)
		return
	}
	selfIP, ok := m.selfTailscaleIP()
	if !ok {
		m.limitedLogf("l2relay: drop captured proto=%s no self tailscale IPv4", proto)
		return
	}

	targets := m.targetPeersForRelay(nm)
	relayPayload := payload
	src := ""
	if capturedSrc != nil {
		src = capturedSrc.String()
	}
	if m.shouldSuppressCapturedSig(proto, src, sig, 1500*time.Millisecond) {
		m.limitedLogf("l2relay: drop captured src=%s proto=%s sig=%s reason=duplicate_src_sig_window", src, proto, sig)
		return
	}
	minecraftServerPort := uint16(0)
	switch proto {
	case l2ProtoMDNS:
		summary, interested := summarizeDiscoveryPayload(proto, payload)
		if !isMDNSQueryShaped(payload) || !interested {
			if interested {
				m.logf("[v2] l2relay: drop captured src=%s proto=%s sig=%s reason=mdns_not_interesting_query payload_summary=%s", src, proto, sig, summary)
			} else {
				m.limitedLogf("[v1] l2relay: drop captured src=%s proto=%s sig=%s reason=mdns_not_interesting_query payload_summary=%s", src, proto, sig, summary)
			}
			return
		}
		if isMDNSQueryShaped(payload) {
			if rewritten, changed, rewrites := m.rewriteMDNSQueryAliasToOriginal(payload); changed {
				relayPayload = rewritten
				m.logf("[v1] l2relay: mdns alias strip before relay src=%s orig_sig=%s relay_sig=%s rewrites=%q", src, sig, relayRawSig(relayPayload), rewrites)
			}
		}
	case l2ProtoSSDP:
		summary, interested := summarizeDiscoveryPayload(proto, payload)
		if !interested {
			m.limitedLogf("l2relay: drop captured src=%s proto=%s sig=%s reason=ssdp_not_interesting payload_summary=%s", src, proto, sig, summary)
			return
		}
	case l2ProtoMinecraft:
		// If the Minecraft server is running on this Cylonix node (capturedSrc
		// matches our own LAN IP), record the server port in the envelope so
		// the remote injecting node can proxy directly to our Tailscale IP.
		// If the server is on a different machine on this LAN (no Cylonix),
		// the envelope field is left zero and the remote node injects as-is,
		// requiring subnet routing for connectivity.
		if capturedSrc != nil {
			if srcIP, ok := netip.AddrFromSlice(capturedSrc.IP); ok {
				srcIP = srcIP.Unmap()
				if selfLANIP, ok2 := m.selfLANIPv4ForRelay(); ok2 && srcIP == selfLANIP {
					if port, ok3 := parseMinecraftAD(payload); ok3 {
						minecraftServerPort = port
					}
				}
			}
		}
	case l2ProtoWSD:
		summary, interested := summarizeDiscoveryPayload(proto, payload)
		if (!isWSDQueryShaped(payload) && !isWSDAnnounce(payload)) || !interested {
			if interested {
				m.logf("l2relay: drop captured src=%s proto=%s sig=%s reason=wsd_not_interesting_query payload_summary=%s", src, proto, sig, summary)
			} else {
				m.limitedLogf("l2relay: drop captured src=%s proto=%s sig=%s reason=wsd_not_interesting_query payload_summary=%s", src, proto, sig, summary)
			}
			return
		}
		// For WSD announcements, rewrite XAddrs host only when the announce
		// originates from this node itself (self LAN IP), so we don't rewrite
		// announcements from other LAN devices.
		if isWSDAnnounce(payload) && capturedSrc != nil {
			if srcIP, ok := netip.AddrFromSlice(capturedSrc.IP); ok {
				srcIP = srcIP.Unmap()
				if selfLANIP, ok := m.selfLANIPv4ForRelay(); ok && srcIP == selfLANIP {
					if selfName := strings.TrimSuffix(nm.SelfNode.Name(), "."); selfName != "" {
						forcePort := uint16(0)
						if debugL2RelayWSDHTTPProxyRewrite() {
							forcePort = l2RelayWSDProxyPort
						}
						if rewritten, changed := rewriteWSDResponseXAddrs(relayPayload, selfName, forcePort); changed {
							m.logf("l2relay: wsd announce xaddr rewrite src=%s host=%q force_port=%d orig_sig=%s relay_sig=%s", src, selfName, forcePort, sig, relayRawSig(rewritten))
							relayPayload = rewritten
						}
					}
				}
			}
		}
	case l2ProtoNetBIOS:
		summary, interested := summarizeDiscoveryPayload(proto, payload)
		nbPort := uint16(0)
		if capturedSrc != nil {
			nbPort = uint16(capturedSrc.Port)
		}
		if nbPort == 0 || !interested {
			m.limitedLogf("[v1] l2relay: drop captured src=%s proto=%s sig=%s reason=netbios_not_interesting payload_summary=%s", src, proto, sig, summary)
			return
		}
	default:
		m.limitedLogf("[v1] l2relay: drop captured src=%s sig=%s proto=%s bytes=%d targets=%d. Unsupported. Skip", src, sig, proto, len(payload), len(targets))
		return
	}
	if summary, interested := summarizeDiscoveryPayload(proto, payload); summary != "" {
		if interested && m.shouldLogSummarySig(sig) {
			m.limitedLogf("[v2] l2relay: captured payload summary src=%s sig=%s proto=%s interesting=%v %s", src, sig, proto, interested, summary)
		}
	}
	m.limitedLogf("[v1] l2relay: forwarding captured src=%s sig=%s proto=%s bytes=%d targets=%d", src, sig, proto, len(payload), len(targets))
	for _, p := range targets {
		dstIP := nodeIP(p, netip.Addr.Is4)
		if !dstIP.IsValid() {
			m.limitedLogf("[v1] l2relay: skip target src=%s peer=%d reason=no_tailscale_ipv4", src, p.ID())
			continue
		}
		if !m.l2DiscoveryAllowed(selfIP, dstIP, string(proto), false) {
			m.limitedLogf("[v1] l2relay: policy denied src=%s proto=%s src=%v dst=%v", src, proto, selfIP, dstIP)
			continue
		}
		m.limitedLogf("[v1] l2relay: relay send candidate src=%s sig=%s proto=%s peer=%d dst=%v", src, sig, proto, p.ID(), dstIP)
		wirePayload := relayPayload
		if proto == l2ProtoSSDP {
			wirePayload = rewriteSSDPForPeer(payload, dstIP)
		}
		env := l2RelayEnvelope{
			OriginNodeID: nm.SelfNode.ID(),
			OriginBootID: m.bootID,
			Seq:          m.seq.Add(1),
			Proto:        proto,
			Hops:         1,
			Payload:      wirePayload,
		}
		if proto == l2ProtoMDNS && isMDNSQueryShaped(payload) && queryKey != "" {
			env.MDNSQueryKey = queryKey
		}
		if proto == l2ProtoWSD && isWSDQueryShaped(payload) && queryKey != "" {
			env.WSDQueryKey = queryKey
		}
		if proto == l2ProtoNetBIOS && capturedSrc != nil {
			env.NetBIOSPort = uint16(capturedSrc.Port)
			if queryKey != "" && ((env.NetBIOSPort == 137 && isNBNSQuery(payload)) || env.NetBIOSPort == 138) {
				env.NetBIOSQueryKey = queryKey
			}
		}
		if proto == l2ProtoMDNS && isMDNSResponse(payload) && capturedSrc != nil {
			if srcIP, ok := netip.AddrFromSlice(capturedSrc.IP); ok {
				srcIP = srcIP.Unmap()
				if srcIP.Is4() {
					env.MDNSReplySourceIP = srcIP.String()
				}
			}
		}
		if proto == l2ProtoMinecraft && minecraftServerPort > 0 {
			env.MinecraftServerPort = minecraftServerPort
		}
		m.sendEnvelopeToPeerAsync(dstIP, p, env)
	}
}

func (m *l2RelayManager) canForwardCaptured() bool {
	lockedAt := m.lockRelayMu("canForwardCaptured")
	defer m.unlockRelayMu("canForwardCaptured", lockedAt)
	if !m.selfCanRelayQuery {
		m.limitedLogf("[v1] l2relay: cannot forward captured: self relay capability disabled")
		return false
	}
	if m.selfNodeID.IsZero() {
		// No self node ID means we don't know who we are in the netmap
		// and we can't set origin_node_id in envelopes,
		m.limitedLogf("[v1] l2relay: cannot forward captured: self node ID unknown")
		return false
	}
	if !m.segmentStrong {
		return true
	}
	if m.segmentID == "" {
		return true
	}
	leader, ok := m.leaderBySeg[m.segmentID]
	if !ok || leader.LeaderID.IsZero() {
		// Bootstrap mode until leader is known.
		return true
	}
	if leader.LeaderID != m.selfNodeID {
		m.logf("l2relay: leader gate deny self=%d leader=%d segment=%q", m.selfNodeID, leader.LeaderID, m.segmentID)
	}
	return leader.LeaderID == m.selfNodeID
}

func (m *l2RelayManager) targetPeersForRelay(nm *netmap.NetworkMap) []tailcfg.NodeView {
	lockedAt := m.lockRelayMu("targetPeersForRelay")
	segmentStrong := m.segmentStrong
	defer m.unlockRelayMu("targetPeersForRelay", lockedAt)
	onlineOnly := m.filterRelayOnlinePeers(nm.Peers, "data")
	if !segmentStrong {
		// Weak segment identity cannot safely suppress peers across overlapping RFC1918 LANs.
		return onlineOnly
	}

	byID := make(map[tailcfg.NodeID]tailcfg.NodeView, len(onlineOnly))
	for _, p := range onlineOnly {
		byID[p.ID()] = p
	}
	var targets []tailcfg.NodeView
	seen := make(map[tailcfg.NodeID]bool)
	for seg, leader := range m.leaderBySeg {
		if seg == "" || leader.LeaderID == 0 {
			continue
		}
		if seg == m.segmentID {
			continue
		}
		if p, ok := byID[leader.LeaderID]; ok && !seen[p.ID()] {
			seen[p.ID()] = true
			targets = append(targets, p)
		}
	}
	if len(targets) > 0 {
		return targets
	}
	// Bootstrap fallback before leaders are learned.
	return onlineOnly
}

func (m *l2RelayManager) sendEnvelopeToPeerAsync(dstIP netip.Addr, peer tailcfg.NodeView, env l2RelayEnvelope) {
	if m.sendEnvelopeHook != nil {
		// Keep test hooks deterministic.
		m.sendEnvelopeToPeer(dstIP, peer, env)
		return
	}
	select {
	case m.sendSem <- struct{}{}:
		go func() {
			defer func() { <-m.sendSem }()
			m.sendEnvelopeToPeer(dstIP, peer, env)
		}()
	default:
		m.limitedLogf("l2relay: drop send queue full peer=%v dst=%v proto=%s seq=%d", peer.Name(), dstIP, env.Proto, env.Seq)
	}
}

func (m *l2RelayManager) sendEnvelopeToPeer(dstIP netip.Addr, peer tailcfg.NodeView, env l2RelayEnvelope) {
	if m.sendEnvelopeHook != nil {
		m.sendEnvelopeHook(dstIP, env)
		return
	}
	sig := relayEnvelopeSig(&env)
	base, ok := m.peerAPIBaseForPeer(peer)
	if !ok {
		m.logf("l2relay: drop send no peerapi base peer=%v dst=%v sig=%s", peer.Name(), dstIP, sig)
		return
	}
	b, err := json.Marshal(&env)
	if err != nil {
		m.logf("l2relay: json marshal failed peer=%v dst=%v sig=%s err=%v", peer.Name(), dstIP, sig, err)
		return
	}
	if env.MDNSQueryKey != "" {
		var wire struct {
			MDNSQueryKey string `json:"mdns_query_key,omitempty"`
		}
		if err := json.Unmarshal(b, &wire); err != nil {
			m.logf("l2relay: drop send failed to verify wire query key peer=%v dst=%v sig=%s err=%v", peer.Name(), dstIP, sig, err)
			return
		}
		if wire.MDNSQueryKey != env.MDNSQueryKey {
			m.logf("l2relay: drop send wire query key mismatch peer=%v dst=%v sig=%s env_query_key=%q wire_query_key=%q", peer.Name(), dstIP, sig, env.MDNSQueryKey, wire.MDNSQueryKey)
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), l2RelayPeerSendTimeout)
	defer cancel()
	url := base + "/v0/l2relay/envelope"
	queryKey := env.MDNSQueryKey
	querySig := env.MDNSQuerySig
	switch env.Proto {
	case l2ProtoWSD:
		queryKey = env.WSDQueryKey
		querySig = ""
	case l2ProtoNetBIOS:
		queryKey = env.NetBIOSQueryKey
		querySig = ""
	}
	m.limitedLogf("[v2] l2relay: http send attempt peer=%v dst=%v proto=%s seq=%d payload_bytes=%d query_key=%q query_sig=%s sig=%s url=%q", peer.Name(), dstIP, env.Proto, env.Seq, len(env.Payload), queryKey, querySig, sig, url)
	res, err := m.postPeerAPIJSON(ctx, url, b)
	if err != nil {
		m.logf("[v1] l2relay: http send failed peer=%v dst=%v sig=%s err=%v", peer.Name(), dstIP, sig, err)
		return
	}
	m.limitedLogf("[v2] l2relay: sent proto=%s seq=%d origin=%d/%s dst=%v peer=%v status=%s bytes=%d wire_bytes=%d sig=%s", env.Proto, env.Seq, env.OriginNodeID, env.OriginBootID, dstIP, peer.Name(), res.Status, len(env.Payload), len(b), sig)
}

func (m *l2RelayManager) peerAPIBaseForPeer(peer tailcfg.NodeView) (string, bool) {
	if !peer.Valid() {
		return "", false
	}
	return m.b.PeerAPIBase(peer), true
}

func (m *l2RelayManager) handleIncomingEnvelope(src netip.AddrPort, selfAddr netip.Addr, raw []byte) error {
	m.logf("[v1] l2relay: incoming envelope raw from=%v bytes=%d", src, len(raw))
	var env l2RelayEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		m.logf("l2relay: drop incoming malformed envelope from=%v err=%v", src, err)
		return err
	}
	sig := relayEnvelopeSig(&env)
	m.logf("[v1] l2relay: incoming envelope decoded from=%v proto=%s hops=%d origin=%d/%s seq=%d payload_bytes=%d sig=%s", src, env.Proto, env.Hops, env.OriginNodeID, env.OriginBootID, env.Seq, len(env.Payload), sig)
	if env.Hops == 0 || len(env.Payload) == 0 || env.Proto == "" {
		m.logf("l2relay: drop incoming invalid envelope from=%v proto=%q hops=%d bytes=%d", src, env.Proto, env.Hops, len(env.Payload))
		return fmt.Errorf("invalid envelope proto=%q hops=%d bytes=%d", env.Proto, env.Hops, len(env.Payload))
	}
	isResp := m.isResponseEnvelope(&env)
	lockedAt := m.lockRelayMu("handleIncomingEnvelope.cap")
	selfCanRelay := m.selfCanRelayQuery
	selfCanInject := m.selfCanInjectQuery
	m.unlockRelayMu("handleIncomingEnvelope.cap", lockedAt)
	if isResp {
		if !selfCanRelay {
			m.logf("[v2] l2relay: drop incoming envelope from=%v proto=%s reason=self relay capability disabled for response", src, env.Proto)
			return nil
		}
	} else {
		if !selfCanInject {
			m.logf("[v2] l2relay: drop incoming envelope from=%v proto=%s reason=self inject capability disabled for query", src, env.Proto)
			return nil
		}
	}
	if m.isDuplicate(&env) {
		m.logf("[v2] l2relay: drop duplicate envelope from=%v key=%s", src, m.dedupeKey(&env))
		return nil
	}

	if !m.l2DiscoveryAllowed(src.Addr(), selfAddr, string(env.Proto), true) {
		m.logf("[v1] l2relay: drop incoming policy deny proto=%s src=%v dst=%v", env.Proto, src.Addr(), selfAddr)
		return fmt.Errorf("policy denied")
	}
	m.logf("l2relay: accept incoming proto=%s from=%v origin=%d/%s seq=%d bytes=%d sig=%s", env.Proto, src, env.OriginNodeID, env.OriginBootID, env.Seq, len(env.Payload), sig)
	payloadSig := relayRawSig(env.Payload)
	summary, interested := summarizeDiscoveryPayload(env.Proto, env.Payload)
	if summary != "" {
		if interested && m.shouldLogSummarySig(payloadSig) {
			m.logf("[v2] l2relay: incoming payload summary sig=%s proto=%s interesting=%v %s", payloadSig, env.Proto, interested, summary)
		}
	}
	if env.Proto == l2ProtoNetBIOS {
		m.handleIncomingNetBIOSEnvelope(src, &env)
		return nil
	}
	if env.Proto == l2ProtoSSDP {
		if !interested {
			m.logf("[v2] l2relay: ssdp packet dropped from=%v sig=%s reason=not_interesting", src, payloadSig)
			return nil
		}
		m.injectToLocalDiscovery(env.Proto, env.Payload)
		m.logf("[v2] l2relay: ssdp injected from=%v sig=%s", src, payloadSig)
		return nil
	}
	if env.Proto == l2ProtoMinecraft {
		if env.MinecraftServerPort > 0 {
			m.injectMinecraftWithProxy(src, &env)
		} else {
			m.injectToLocalDiscovery(env.Proto, env.Payload)
		}
		m.logf("[v2] l2relay: minecraft injected from=%v sig=%s proxy_port=%d", src, payloadSig, env.MinecraftServerPort)
		return nil
	}
	if env.Proto == l2ProtoMDNS {
		isReplyEnvelope := strings.TrimSpace(env.MDNSQuerySig) != "" || strings.TrimSpace(env.MDNSReplySourceIP) != ""
		// Reply-path envelopes can still be query-shaped (qd>0) when the
		// responder sends a known-answer style packet. Classify by envelope
		// metadata first so we do not re-inject responses as queries.
		if isReplyEnvelope {
			rewrittenForProxy := false
			replySrcIP, _ := netip.ParseAddr(strings.TrimSpace(env.MDNSReplySourceIP))
			if rewritten, changed := m.rewriteMDNSResponseForRelayProxy(src.Addr(), env.Payload, replySrcIP); changed {
				if rewritten == nil {
					m.logf("l2relay: mdns response dropped after proxy rewrite src=%v orig_sig=%s query_key=%s query_sig=%s", src, payloadSig, env.MDNSQueryKey, env.MDNSQuerySig)
					return nil
				}
				env.Payload = rewritten
				rewrittenForProxy = true
				m.logf("l2relay: mdns response rewritten for proxy src=%v sig=%s (from %s)", src, relayRawSig(env.Payload), payloadSig)
			}
			if dumps, ok := detailedMDNSPacketLines(env.Payload); ok {
				for i, dump := range dumps {
					m.logf("l2relay: mdns response detail[%d] src=%v query_key=%s query_sig=%s payload_sig=%s %s", i, src, env.MDNSQueryKey, env.MDNSQuerySig, relayRawSig(env.Payload), dump)
				}
			}
			patDelivered := false
			if env.MDNSQueryKey != "" {
				m.logf("l2relay: mdns pat destination receive src=%v query_key=%s query_sig=%s payload_sig=%s", src, env.MDNSQueryKey, env.MDNSQuerySig, relayRawSig(env.Payload))
				if delivered, newPayload := m.injectToMDNSPATDestination(env.MDNSQueryKey, env.Payload); delivered {
					patDelivered = true
					env.Payload = newPayload
					m.logf("[v2] l2relay: mdns pat destination delivered src=%v query_key=%s query_sig=%s payload_sig=%s", src, env.MDNSQueryKey, env.MDNSQuerySig, relayRawSig(env.Payload))
					// FIXME: add to multicast injection to ensure delivery for now.
					m.injectToLocalDiscovery(env.Proto, newPayload)
				} else {
					m.logf("[v2] l2relay: mdns pat destination miss src=%v query_key=%s query_sig=%s payload_sig=%s", src, env.MDNSQueryKey, env.MDNSQuerySig, relayRawSig(env.Payload))
				}
			} else {
				m.logf("l2relay: mdns response dropped without query key src=%v query_sig=%s payload_sig=%s rewritten=%v", src, env.MDNSQuerySig, relayRawSig(env.Payload), rewrittenForProxy)
				return errors.New("no query key in mdns response envelope")
			}
			m.logf("l2relay: mdns response handled src=%v query_key=%s query_sig=%s payload_sig=%s pat_delivered=%v rewritten=%v", src, env.MDNSQueryKey, env.MDNSQuerySig, relayRawSig(env.Payload), patDelivered, rewrittenForProxy)
			return nil
		}
		// Queries received from peers.
		if isMDNSQueryShaped(env.Payload) {
			if !interested {
				m.logf("[v2] l2relay: mdns query-shaped packet from=%v sig=%s dropped reason=not_printer_like", src, payloadSig)
				return nil
			}
			if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
				m.logf("[v2] l2relay: mdns query from=%v sig=%s dropped on darwin/iOS due to OS-level mDNS responder behavior", src, payloadSig)
				return nil
			}
			m.rewriteIncomingMDNSQueryForInject(&env)
			env.MDNSQuerySig = relayRawSig(env.Payload)
			injected := m.injectIncomingMDNSQueryWithPAT(src, &env)
			if injected {
				return nil
			}
			m.logf("[v1] l2relay: mdns query inject failed from=%v sig=%s", src, payloadSig)
			return errors.New("failed to inject query")
		}
		// Pure responses without reply metadata are dropped in the deterministic model.
		m.logf("[v2] l2relay: mdns packet dropped from=%v sig=%s reason=no_reply_metadata", src, payloadSig)
		return nil
	}
	if env.Proto == l2ProtoWSD {
		isResp := isWSDResponse(env.Payload)
		isQuery := isWSDQueryShaped(env.Payload)
		isAnnounce := isWSDAnnounce(env.Payload)
		if env.WSDQueryKey != "" && isResp {
			m.logf("[v1] l2relay: wsd pat destination receive src=%v query_key=%s payload_sig=%s", src, env.WSDQueryKey, relayRawSig(env.Payload))
			if delivered, newPayload := m.injectToWSDPATDestination(env.WSDQueryKey, env.Payload); delivered {
				env.Payload = newPayload
				m.logf("[v1] l2relay: wsd pat destination delivered src=%v query_key=%s payload_sig=%s", src, env.WSDQueryKey, relayRawSig(env.Payload))
			} else {
				m.logf("[v1] l2relay: wsd pat destination miss src=%v query_key=%s payload_sig=%s", src, env.WSDQueryKey, relayRawSig(env.Payload))
			}
			return nil
		}
		// Backward/forward-compat fallback: if sender already classified this as
		// a query (query key present) and receiver parser can't shape-classify it,
		// still inject it as query instead of dropping as "no_reply_metadata".
		if env.WSDQueryKey != "" && !isResp && !isAnnounce && !isQuery {
			isQuery = true
			m.logf("[v1] l2relay: wsd query fallback by query key src=%v query_key=%s payload_sig=%s", src, env.WSDQueryKey, payloadSig)
		}
		if isQuery {
			if !interested {
				m.logf("[v1] l2relay: wsd query-shaped packet from=%v sig=%s dropped reason=not_interesting", src, payloadSig)
				return nil
			}
			if injected := m.injectIncomingWSDQueryWithPAT(src, &env); injected {
				return nil
			}
			m.logf("[v1] l2relay: wsd query inject failed from=%v sig=%s", src, payloadSig)
			return nil
		}
		if isAnnounce {
			if !interested {
				m.logf("[v1] l2relay: wsd announce packet from=%v sig=%s dropped reason=not_interesting", src, payloadSig)
				return nil
			}
			m.injectToLocalDiscovery(l2ProtoWSD, env.Payload)
			m.logf("[v1] l2relay: wsd announce injected from=%v sig=%s", src, payloadSig)
			return nil
		}
		m.logf("[v1] l2relay: wsd packet dropped from=%v sig=%s reason=no_reply_metadata query_key=%q is_query=%v is_response=%v is_announce=%v", src, payloadSig, env.WSDQueryKey, isQuery, isResp, isAnnounce)
		return nil
	}
	return nil
}

func (m *l2RelayManager) dedupeKey(env *l2RelayEnvelope) string {
	return fmt.Sprintf("%d|%s|%d|%s", env.OriginNodeID, env.OriginBootID, env.Seq, env.Proto)
}

func relayEnvelopeSig(env *l2RelayEnvelope) string {
	if env == nil {
		return "nil"
	}
	sum := sha256.Sum256(env.Payload)
	return fmt.Sprintf("%d/%s/%d/%s/%x", env.OriginNodeID, env.OriginBootID, env.Seq, env.Proto, sum[:4])
}

func relayRawSig(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%x", sum[:4])
}

func (m *l2RelayManager) isResponseEnvelope(env *l2RelayEnvelope) bool {
	if env == nil {
		return false
	}
	switch env.Proto {
	case l2ProtoMDNS:
		if strings.TrimSpace(env.MDNSQuerySig) != "" || strings.TrimSpace(env.MDNSReplySourceIP) != "" {
			return true
		}
		return strings.TrimSpace(env.MDNSQueryKey) != "" && isMDNSResponse(env.Payload)
	case l2ProtoWSD:
		return strings.TrimSpace(env.WSDQueryKey) != "" && isWSDResponse(env.Payload)
	case l2ProtoNetBIOS:
		return env.NetBIOSPort == 137 && strings.TrimSpace(env.NetBIOSQueryKey) != "" && isNBNSResponse(env.Payload)
	default:
		return false
	}
}

// noteInjectedPayload records a payload that was just injected onto the local
// network so that captureMulticastLoopOnInterface can suppress the bounce-back.
// localAddr is the local UDP address used for the inject send (IP + ephemeral
// port). Pass netip.AddrPort{} for protocols whose loop guard does not require
// source-address precision (e.g. mDNS uses the port-5353 check; NetBIOS uses
// payload-only dedup).
func (m *l2RelayManager) noteInjectedPayload(proto l2RelayProto, payload []byte, localAddr netip.AddrPort) {
	if len(payload) == 0 {
		return
	}
	k := fmt.Sprintf("%s|%s|%s", proto, relayRawSig(payload), localAddr)
	now := time.Now()
	lockedAt := m.lockRelayMu("noteInjectedPayload")
	defer m.unlockRelayMu("noteInjectedPayload", lockedAt)
	for key, at := range m.recentInjected {
		if now.Sub(at) > 2*time.Second {
			delete(m.recentInjected, key)
		}
	}
	m.recentInjected[k] = now
}

// isRecentlyInjected returns true if the same payload was recently injected
// from capturedSrc (IP + port). For WSD this provides precise loop detection:
// only the exact (sig, IP, port) triple used during injection is suppressed,
// so Relay-B's own real queries (different ephemeral port) still pass through.
// Pass netip.AddrPort{} for protocols that use payload-only dedup.
func (m *l2RelayManager) isRecentlyInjected(proto l2RelayProto, payload []byte, capturedSrc netip.AddrPort, maxAge time.Duration) bool {
	if len(payload) == 0 {
		return false
	}
	k := fmt.Sprintf("%s|%s|%s", proto, relayRawSig(payload), capturedSrc)
	now := time.Now()
	lockedAt := m.lockRelayMu("isRecentlyInjected")
	defer m.unlockRelayMu("isRecentlyInjected", lockedAt)
	for key, at := range m.recentInjected {
		if now.Sub(at) > 2*time.Second {
			delete(m.recentInjected, key)
		}
	}
	at, ok := m.recentInjected[k]
	return ok && now.Sub(at) <= maxAge
}

func (m *l2RelayManager) isDuplicate(env *l2RelayEnvelope) bool {
	lockedAt := m.lockRelayMu("isDuplicate")
	defer m.unlockRelayMu("isDuplicate", lockedAt)

	now := time.Now()
	for k, t := range m.recentMessage {
		if now.Sub(t) > 30*time.Second {
			delete(m.recentMessage, k)
		}
	}
	k := m.dedupeKey(env)
	if _, ok := m.recentMessage[k]; ok {
		return true
	}
	m.recentMessage[k] = now
	return false
}

func (m *l2RelayManager) selfTailscaleIP() (netip.Addr, bool) {
	nm := m.b.NetMap()
	if nm == nil || !nm.SelfNode.Valid() {
		return netip.Addr{}, false
	}
	addrs := nm.SelfNode.Addresses()
	for i := range addrs.Len() {
		p := addrs.At(i)
		if p.IsSingleIP() && p.Addr().Is4() {
			return p.Addr(), true
		}
	}
	return netip.Addr{}, false
}

func (m *l2RelayManager) selfLANIPv4ForRelay() (netip.Addr, bool) {
	st := m.b.NetMon().InterfaceState()
	if st == nil {
		return netip.Addr{}, false
	}
	ifName := st.DefaultRouteInterface
	if ifName == "" {
		return netip.Addr{}, false
	}
	for _, pfx := range st.InterfaceIPs[ifName] {
		ip := pfx.Addr().Unmap()
		if !ip.IsValid() || !ip.Is4() {
			continue
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || cgnatRange.Contains(ip) {
			continue
		}
		return ip, true
	}
	return netip.Addr{}, false
}

func (m *l2RelayManager) injectToLocalDiscovery(proto l2RelayProto, payload []byte) {
	if m.injectPacketHook != nil {
		m.injectPacketHook(proto, slices.Clone(payload))
		return
	}
	payloadSig := relayRawSig(payload)
	if summary, interested := summarizeDiscoveryPayload(proto, payload); summary != "" {
		if interested && m.shouldLogSummarySig(payloadSig) {
			m.logf("[v2] l2relay: inject local sig=%s proto=%s interesting=%v %s", payloadSig, proto, interested, summary)
		}
	}
	switch proto {
	case l2ProtoMDNS:
		m.injectToLocalMulticast(payload, "udp4", "224.0.0.251:5353", proto, payloadSig)
		m.injectToLocalMulticast(payload, "udp6", "[ff02::fb]:5353", proto, payloadSig)
	case l2ProtoSSDP:
		m.injectToLocalMulticast(payload, "udp4", "239.255.255.250:1900", proto, payloadSig)
	case l2ProtoWSD:
		m.injectToLocalMulticast(payload, "udp4", "239.255.255.250:3702", proto, payloadSig)
	case l2ProtoMinecraft:
		// Minecraft Java Edition LAN discovery: inject to 224.0.2.60:4445.
		// The announcement carries the remote server's original LAN IP; no
		// address rewriting is done, so the discovered server is only
		// reachable if a routed path exists (e.g., the two LANs share a
		// subnet or the user has subnet routing enabled).
		m.injectToLocalMulticast(payload, "udp4", "224.0.2.60:4445", proto, payloadSig)
	default:
		m.logf("l2relay: unknown proto for injection: %q", proto)
	}
}

func (m *l2RelayManager) injectIncomingMDNSQueryWithPAT(src netip.AddrPort, env *l2RelayEnvelope) bool {
	if env == nil || env.OriginNodeID == 0 || len(env.Payload) == 0 {
		return false
	}
	v4ok := m.injectIncomingMDNSQueryWithPATNetwork("udp4", "224.0.0.251:5353", src, env)
	v6ok := m.injectIncomingMDNSQueryWithPATNetwork("udp6", "[ff02::fb]:5353", src, env)
	return v4ok || v6ok
}

func (m *l2RelayManager) injectIncomingMDNSQueryWithPATNetwork(network, dst string, src netip.AddrPort, env *l2RelayEnvelope) bool {
	ra, err := net.ResolveUDPAddr(network, dst)
	if err != nil {
		m.logf("l2relay: mdns pat resolve error network=%s dst=%s err=%v", network, dst, err)
		return false
	}
	var lc *net.UDPConn
	if network == "udp6" {
		lc, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0})
	} else {
		lc, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	}
	if err != nil {
		m.logf("l2relay: mdns pat listen error network=%s err=%v", network, err)
		return false
	}
	wirePayload := env.Payload
	if rewritten, changed := forceMDNSQueryQU(wirePayload); changed {
		wirePayload = rewritten
		m.logf("l2relay: mdns pat force qu network=%s origin=%d/%s seq=%d orig_sig=%s query_sig=%s", network, env.OriginNodeID, env.OriginBootID, env.Seq, relayRawSig(env.Payload), relayRawSig(wirePayload))
	}
	if _, err := lc.WriteToUDP(wirePayload, ra); err != nil {
		m.logf("l2relay: mdns pat inject write error network=%s dst=%s err=%v", network, dst, err)
		lc.Close()
		return false
	}
	if ua, ok := lc.LocalAddr().(*net.UDPAddr); ok {
		if ap, ok := udpAddrPort(ua); ok {
			m.noteInjectedPayload(l2ProtoMDNS, wirePayload, ap)
		}
	}
	m.logf("l2relay: mdns pat inject query network=%s local=%v dst=%s origin=%d/%s seq=%d query_sig=%s", network, lc.LocalAddr(), dst, env.OriginNodeID, env.OriginBootID, env.Seq, relayRawSig(wirePayload))
	reqEnv := *env
	reqEnv.Payload = wirePayload
	go m.readMDNSPATReplies(network, src, &reqEnv, lc)
	return true
}

func (m *l2RelayManager) readMDNSPATReplies(network string, src netip.AddrPort, req *l2RelayEnvelope, c *net.UDPConn) {
	defer c.Close()
	last := time.Now()
	buf := make([]byte, l2RelayMaxSize)
	for {
		if time.Since(last) > 12*time.Second {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, ua, err := c.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			m.logf("l2relay: mdns pat read stop network=%s local=%v err=%v", network, c.LocalAddr(), err)
			return
		}
		last = time.Now()
		if n <= 0 || ua == nil {
			continue
		}
		raw := slices.Clone(buf[:n])
		if summary, interested := summarizeDiscoveryPayload(l2ProtoMDNS, raw); summary != "" {
			if interested && m.shouldLogSummarySig(relayRawSig(raw)) {
				m.limitedLogf("[v1] l2relay: mdns pat observed packet network=%s local=%v from=%v bytes=%d interesting=%v %s", network, c.LocalAddr(), ua, len(raw), interested, summary)
			}
		}
		if ua.Port != 5353 {
			m.logf("[v2] l2relay: mdns pat drop packet network=%s local=%v from=%v reason=source_port_not_5353", network, c.LocalAddr(), ua)
			continue
		}
		if !allowMDNSPATReplySource(ua.IP) {
			m.logf("[v2] l2relay: mdns pat drop packet network=%s local=%v from=%v reason=source_not_lan_or_linklocal", network, c.LocalAddr(), ua)
			continue
		}
		if !isMDNSResponse(raw) {
			m.logf("[v2] l2relay: mdns pat drop packet network=%s local=%v from=%v reason=qr_false", network, c.LocalAddr(), ua)
			continue
		}
		m.limitedLogf("[v1] l2relay: mdns pat captured reply network=%s local=%v from=%v bytes=%d req_origin=%d/%s req_seq=%d sig=%s", network, c.LocalAddr(), ua, len(raw), req.OriginNodeID, req.OriginBootID, req.Seq, relayRawSig(raw))
		replySrc, _ := netip.AddrFromSlice(ua.IP)
		m.forwardMDNSPATReplyToOrigin(src, req, raw, replySrc.Unmap())
	}
}

func allowMDNSPATReplySource(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.IsPrivate() || addr.IsLinkLocalUnicast()
	}
	if addr.Is6() {
		return addr.IsLinkLocalUnicast() || isIPv6UniqueLocal(addr)
	}
	return false
}

func (m *l2RelayManager) forwardMDNSPATReplyToOrigin(src netip.AddrPort, req *l2RelayEnvelope, payload []byte, replySrcIP netip.Addr) {
	if req == nil || req.OriginNodeID == 0 || len(payload) == 0 {
		return
	}
	payload = m.rewriteMDNSResponsePrefixForForward(src, req, payload)
	nm := m.b.NetMap()
	if nm == nil || !nm.SelfNode.Valid() {
		return
	}
	selfIP, ok := m.selfTailscaleIP()
	if !ok {
		return
	}
	peer, ok := peerNode(nm, req.OriginNodeID)
	if !ok || !peer.Valid() {
		m.logf("[v1] l2relay: peer not found for id %v", req.OriginNodeID)
		return
	}
	if online, ok := peer.Online().GetOk(); !ok || !online {
		m.logf("[v2] l2relay: mdns pat drop reply peer offline peer=%d sig=%s", req.OriginNodeID, relayRawSig(payload))
		return
	}
	dstIP := nodeIP(peer, netip.Addr.Is4)
	if !dstIP.IsValid() {
		m.logf("[v1] l2relay: mdns pat drop reply no origin peer=%d sig=%s", req.OriginNodeID, relayRawSig(payload))
		return
	}

	if !m.l2DiscoveryAllowed(selfIP, dstIP, string(l2ProtoMDNS), false) {
		m.limitedLogf("[v1] l2relay: mdns pat drop reply policy deny src=%v dst=%v", selfIP, dstIP)
		return
	}
	env := l2RelayEnvelope{
		OriginNodeID: nm.SelfNode.ID(),
		OriginBootID: m.bootID,
		Seq:          m.seq.Add(1),
		Proto:        l2ProtoMDNS,
		Hops:         1,
		MDNSQuerySig: req.MDNSQuerySig,
		MDNSQueryKey: req.MDNSQueryKey,
		Payload:      payload,
	}
	if env.MDNSQuerySig == "" {
		env.MDNSQuerySig = relayRawSig(req.Payload)
	}
	if env.MDNSQueryKey == "" {
		if env.MDNSQuerySig == "" {
			m.logf("[v1] l2relay: mdns pat drop reply missing query key and sig req_origin=%d/%s req_seq=%d src_peer=%v reply_sig=%s", req.OriginNodeID, req.OriginBootID, req.Seq, src, relayRawSig(payload))
			return
		}
		// No query key but we have a sig: forward anyway so the receiver can
		// at least multicast-inject the response (PAT delivery will miss, but
		// the injectToLocalDiscovery fallback path still serves plain clients).
		m.limitedLogf("[v1] l2relay: mdns pat forward reply without query key req_origin=%d/%s req_seq=%d req_query_sig=%s src_peer=%v reply_sig=%s", req.OriginNodeID, req.OriginBootID, req.Seq, env.MDNSQuerySig, src, relayRawSig(payload))
	}
	if replySrcIP.IsValid() {
		replySrcIP = replySrcIP.Unmap()
		if debugRewriteMDNSSelfAddress() && replySrcIP.Is4() && shouldRewriteMDNSSelfAddressForQuery(req.Payload) {
			if selfLANIP, ok := m.selfLANIPv4ForRelay(); ok && selfLANIP == replySrcIP {
				if selfTailIP, tailOK := m.selfTailscaleIP(); tailOK {
					selfTailIP = selfTailIP.Unmap()
					if selfTailIP.Is4() {
						if rewritten, changed := rewriteMDNSResponseIPv4Address(payload, replySrcIP, selfTailIP); changed {
							m.logf("l2relay: mdns pat reply self-address rewrite src_peer=%v req_query_key=%s req_query_sig=%s from=%v to=%v payload_sig=%s", src, env.MDNSQueryKey, env.MDNSQuerySig, replySrcIP, selfTailIP, relayRawSig(rewritten))
							payload = rewritten
						}
						replySrcIP = selfTailIP
					}
				}
			}
		}
		if replySrcIP.Is4() {
			env.MDNSReplySourceIP = replySrcIP.String()
		}
	}
	env.Payload = payload
	m.limitedLogf("[v1] l2relay: mdns pat forward reply origin_peer=%d dst=%v req_origin=%d/%s req_seq=%d req_query_key=%s req_query_sig=%s src_peer=%v reply_sig=%s", req.OriginNodeID, dstIP, req.OriginNodeID, req.OriginBootID, req.Seq, env.MDNSQueryKey, env.MDNSQuerySig, src, relayRawSig(payload))
	m.sendEnvelopeToPeerAsync(dstIP, peer, env)
}

func (m *l2RelayManager) injectToMDNSPATDestination(queryKey string, payload []byte) (bool, []byte) {
	lockedAt := m.lockRelayMu("injectToMDNSPATDestination")
	now := time.Now()
	for k, v := range m.mdnsPATByQuery {
		if now.Sub(v.at) > 20*time.Second {
			delete(m.mdnsPATByQuery, k)
		}
	}
	dst, ok := m.mdnsPATByQuery[queryKey]
	if !ok || !dst.querier.IsValid() {
		m.unlockRelayMu("injectToMDNSPATDestination", lockedAt)
		m.logf("[v1] l2relay: mdns pat destination missing query_key=%s", queryKey)
		return false, nil
	}
	if now.Sub(dst.at) > 20*time.Second {
		delete(m.mdnsPATByQuery, queryKey)
		m.unlockRelayMu("injectToMDNSPATDestination", lockedAt)
		m.logf("[v1] l2relay: mdns pat destination stale query_key=%s", queryKey)
		return false, nil
	}
	m.unlockRelayMu("injectToMDNSPATDestination", lockedAt)
	m.limitedLogf("[v1] l2relay: mdns pat destination hit query_key=%s dst=%v age_ms=%d", queryKey, dst.querier, time.Since(dst.at).Milliseconds())
	var network string
	if dst.querier.Addr().Is6() {
		network = "udp6"
	} else {
		network = "udp4"
	}
	ua := net.UDPAddrFromAddrPort(dst.querier)
	// Prefer sending from mDNS source port 5353; some host stacks ignore responses
	// that don't originate from 5353. Fall back to ephemeral source on bind failure.
	c, err := m.listenMDNSSourcePort(network)
	if err != nil {
		m.logf("[v1] l2relay: mdns pat destination 5353 bind failed query_key=%s dst=%v network=%s err=%v; falling back to ephemeral", queryKey, dst.querier, network, err)
		c, err = net.ListenPacket(network, "")
		if err != nil {
			m.logf("[v1] l2relay: mdns pat destination listen error query_key=%s dst=%v err=%v", queryKey, dst.querier, err)
			return false, nil
		}
	}
	defer c.Close()
	if _, err := c.WriteTo(payload, ua); err != nil {
		m.logf("[v1] l2relay: mdns pat destination write error query_key=%s local=%v dst=%v err=%v", queryKey, c.LocalAddr(), dst.querier, err)
		return false, nil
	}
	m.limitedLogf("[v1] l2relay: mdns pat destination injected query_key=%s local=%v dst=%v bytes=%d payload_sig=%s", queryKey, c.LocalAddr(), dst.querier, len(payload), relayRawSig(payload))
	return true, payload
}

func (m *l2RelayManager) listenMDNSSourcePort(network string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(_ string, _ string, c syscall.RawConn) error {
			if err := c.Control(func(fd uintptr) {
				SetReuseAddr(fd)
			}); err != nil {
				return err
			}
			return nil
		},
	}
	if network == "udp6" {
		return lc.ListenPacket(context.Background(), "udp6", "[::]:5353")
	}
	return lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:5353")
}

func isMDNSQueryShaped(payload []byte) bool {
	var msg dnsmessage.Message
	if err := msg.Unpack(payload); err != nil {
		return false
	}
	return len(msg.Questions) > 0
}

func forceMDNSQueryQU(payload []byte) ([]byte, bool) {
	var msg dnsmessage.Message
	if err := msg.Unpack(payload); err != nil {
		return payload, false
	}
	if msg.Header.Response || len(msg.Questions) == 0 {
		return payload, false
	}
	changed := false
	for i := range msg.Questions {
		c := uint16(msg.Questions[i].Class)
		if c&0x8000 != 0 {
			continue
		}
		msg.Questions[i].Class = dnsmessage.Class(c | 0x8000)
		changed = true
	}
	if !changed {
		return payload, false
	}
	b, err := msg.Pack()
	if err != nil {
		return payload, false
	}
	return b, true
}

func isMDNSResponse(payload []byte) bool {
	var msg dnsmessage.Message
	if err := msg.Unpack(payload); err != nil {
		return false
	}
	return msg.Header.Response
}

var relayInterestedMDNSTokens = []string{
	// Printing (AirPrint / IPP / raw PDL)
	"_ipp._tcp",
	"_ipps._tcp",
	"_printer._tcp",
	"_universal._sub._ipp._tcp",
	"_pdl-datastream._tcp",
	"airprint",
	// Scanning (eSCL / Bonjour scanner — multifunction printers)
	"_scanner._tcp",
	"_uscan._tcp",
	"_uscans._tcp",
	// NAS / network storage
	"_smb._tcp",
	"_adisk._tcp",
	"_afpovertcp._tcp",
	"_webdav._tcp",
	"_webdavs._tcp",
	"_nfs._tcp",
	// Gaming (LAN game discovery)
	"_nvstream._tcp",
	"_steam-remoteplay._tcp",
}

var relaySMBMDNSTokens = []string{
	"_smb._tcp",
	"_adisk._tcp",
	"_afpovertcp._tcp",
	"_webdav._tcp",
	"_webdavs._tcp",
	"_nfs._tcp",
}

var debugRewriteMDNSSelfAddressOpt = envknob.RegisterOptBool("TS_DEBUG_L2RELAY_REWRITE_SELF_ADDRESS")
var debugL2RelayLock = envknob.RegisterBool("TS_DEBUG_L2RELAY_LOCK")

func debugRewriteMDNSSelfAddress() bool {
	if v, ok := debugRewriteMDNSSelfAddressOpt().Get(); ok {
		return v
	}
	return true
}

func containsAnyMDNSToken(s string, tokens []string) bool {
	for _, t := range tokens {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}

func isSMBMDNSPacket(payload []byte) bool {
	var msg dnsmessage.Message
	if err := msg.Unpack(payload); err != nil {
		return containsAnyMDNSToken(strings.ToLower(string(payload)), relaySMBMDNSTokens)
	}
	checkName := func(name string) bool {
		return containsAnyMDNSToken(canonicalMDNSName(name), relaySMBMDNSTokens)
	}
	for _, q := range msg.Questions {
		if checkName(q.Name.String()) {
			return true
		}
	}
	checkRecords := func(records []dnsmessage.Resource) bool {
		for i := range records {
			if checkName(records[i].Header.Name.String()) {
				return true
			}
			switch b := records[i].Body.(type) {
			case *dnsmessage.PTRResource:
				if checkName(b.PTR.String()) {
					return true
				}
			case *dnsmessage.SRVResource:
				if checkName(b.Target.String()) {
					return true
				}
			}
		}
		return false
	}
	return checkRecords(msg.Answers) || checkRecords(msg.Authorities) || checkRecords(msg.Additionals)
}

func shouldRewriteMDNSSelfAddressForQuery(payload []byte) bool {
	if isSMBMDNSPacket(payload) {
		return true
	}
	return len(mdnsHostLookupQuestions(payload)) > 0
}

func canonicalMDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func (m *l2RelayManager) resolveMDNSAliasTarget(name string) (string, bool) {
	key := canonicalMDNSName(name)
	if key == "" {
		return "", false
	}
	now := time.Now()
	lockedAt := m.lockRelayMu("resolveMDNSAliasTarget")
	defer m.unlockRelayMu("resolveMDNSAliasTarget", lockedAt)
	for k, v := range m.mdnsAliasByName {
		if now.Sub(v.at) > 2*time.Hour {
			delete(m.mdnsAliasByName, k)
		}
	}
	v, ok := m.mdnsAliasByName[key]
	if !ok || v.target == "" {
		return "", false
	}
	return v.target, true
}

func (m *l2RelayManager) rewriteMDNSQueryAliasToOriginal(payload []byte) ([]byte, bool, []string) {
	var msg dnsmessage.Message
	if err := msg.Unpack(payload); err != nil {
		return payload, false, nil
	}
	// Some mDNS stacks send cache-refresh traffic with qd>0 and known answers
	// while still setting qr=true. Treat any packet with questions as query-shaped
	// for alias stripping on the outbound path; skip pure responses (qd=0).
	if len(msg.Questions) == 0 {
		return payload, false, nil
	}
	rewrites := make([]string, 0, 4)
	changed := false
	seen := map[string]bool{}
	rewriteName := func(n dnsmessage.Name) (dnsmessage.Name, bool) {
		orig := strings.TrimSuffix(n.String(), ".")
		target, ok := m.resolveMDNSAliasTarget(orig)
		if !ok {
			return n, false
		}
		nn, err := dnsmessage.NewName(strings.TrimSuffix(target, ".") + ".")
		if err != nil {
			return n, false
		}
		k := orig + "->" + target
		if !seen[k] {
			rewrites = append(rewrites, k)
			seen[k] = true
		}
		return nn, true
	}
	for i := range msg.Questions {
		if nn, ok := rewriteName(msg.Questions[i].Name); ok {
			msg.Questions[i].Name = nn
			changed = true
		}
	}
	rewriteRecords := func(records []dnsmessage.Resource) {
		for i := range records {
			if nn, ok := rewriteName(records[i].Header.Name); ok {
				records[i].Header.Name = nn
				changed = true
			}
			switch b := records[i].Body.(type) {
			case *dnsmessage.SRVResource:
				if nn, ok := rewriteName(b.Target); ok {
					b.Target = nn
					changed = true
				}
			case *dnsmessage.PTRResource:
				if nn, ok := rewriteName(b.PTR); ok {
					b.PTR = nn
					changed = true
				}
			}
		}
	}
	rewriteRecords(msg.Answers)
	rewriteRecords(msg.Authorities)
	rewriteRecords(msg.Additionals)
	if !changed {
		return payload, false, nil
	}
	b, err := msg.Pack()
	if err != nil {
		return payload, false, nil
	}
	return b, true, rewrites
}

func (m *l2RelayManager) rewriteIncomingMDNSQueryAliasesForInject(payload []byte) ([]byte, bool) {
	rewritten, changed, rewrites := m.rewriteMDNSQueryAliasToOriginal(payload)
	if changed {
		m.logf("l2relay: mdns alias strip before inject orig_sig=%s inject_sig=%s rewrites=%q", relayRawSig(payload), relayRawSig(rewritten), rewrites)
	}
	return rewritten, changed
}

func (m *l2RelayManager) rewriteIncomingMDNSQueryForInject(env *l2RelayEnvelope) {
	if env == nil || env.Proto != l2ProtoMDNS {
		return
	}
	if rewritten, changed := m.rewriteIncomingMDNSQueryAliasesForInject(env.Payload); changed {
		env.Payload = rewritten
	}
}

func (m *l2RelayManager) rewriteMDNSResponsePrefixForForward(src netip.AddrPort, req *l2RelayEnvelope, payload []byte) []byte {
	return payload
}

func (m *l2RelayManager) ensureTCPProxy(relayBase, upstream string) (uint16, error) {
	key := relayBase + "|" + upstream
	lockedAt := m.lockRelayMu("ensureTCPProxy.lookup")
	if p, ok := m.proxyByUpstream[key]; ok {
		port := p.localPort
		m.unlockRelayMu("ensureTCPProxy.lookup", lockedAt)
		return port, nil
	}
	m.unlockRelayMu("ensureTCPProxy.lookup", lockedAt)

	ln, err := net.Listen("tcp4", ":0")
	if err != nil {
		return 0, err
	}
	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok || ta.Port <= 0 || ta.Port > 65535 {
		ln.Close()
		return 0, fmt.Errorf("unexpected listener addr: %v", ln.Addr())
	}
	p := &l2RelayTCPProxy{
		key:       key,
		relayBase: relayBase,
		upstream:  upstream,
		localPort: uint16(ta.Port),
		ln:        ln,
	}

	lockedAt = m.lockRelayMu("ensureTCPProxy.install")
	if existing, ok := m.proxyByUpstream[key]; ok {
		port := existing.localPort
		m.unlockRelayMu("ensureTCPProxy.install", lockedAt)
		ln.Close()
		return port, nil
	}
	m.proxyByUpstream[key] = p
	m.unlockRelayMu("ensureTCPProxy.install", lockedAt)

	m.logf("l2relay: tcp proxy started key=%q relay=%q upstream=%q local_port=%d", key, relayBase, upstream, p.localPort)
	go m.serveTCPProxy(p)
	return p.localPort, nil
}

func (m *l2RelayManager) serveTCPProxy(p *l2RelayTCPProxy) {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			m.logf("l2relay: tcp proxy accept stop key=%q err=%v", p.key, err)
			return
		}
		go m.handleTCPProxyConn(p, c)
	}
}

func (m *l2RelayManager) handleTCPProxyConn(p *l2RelayTCPProxy, local net.Conn) {
	defer local.Close()
	m.logf("l2relay: tcp proxy local accept key=%q local=%q remote=%q", p.key, local.LocalAddr(), local.RemoteAddr())
	remote, err := m.dialRelayProxyTCP(p.relayBase, p.upstream)
	if err != nil {
		m.logf("[v1] l2relay: tcp proxy dial failed key=%q err=%v", p.key, err)
		return
	}
	defer remote.Close()
	m.logf("l2relay: tcp proxy relay connected key=%q relay=%q upstream=%q", p.key, p.relayBase, p.upstream)

	done := make(chan struct{}, 2)
	go func() {
		n, err := m.copyProxyStreamWithPreview("local->relay", p.key, remote, local)
		m.logf("l2relay: tcp proxy local->relay done key=%q bytes=%d err=%v", p.key, n, err)
		closeWrite(remote)
		done <- struct{}{}
	}()
	go func() {
		n, err := m.copyProxyStreamWithPreview("relay->local", p.key, local, remote)
		m.logf("l2relay: tcp proxy relay->local done key=%q bytes=%d err=%v", p.key, n, err)
		closeWrite(local)
		done <- struct{}{}
	}()
	<-done
	<-done
	m.logf("l2relay: tcp proxy local session ended key=%q", p.key)
}

func closeWrite(c net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func (m *l2RelayManager) copyProxyStreamWithPreview(dir, key string, dst io.Writer, src io.Reader) (int64, error) {
	var preview limitedCapture
	n, err := io.Copy(dst, io.TeeReader(src, &preview))
	if text, ok := preview.preview(); ok {
		logChunkedPreview(m.logf, dir, key, len(preview.buf), text)
	}
	return n, err
}

func logChunkedPreview(logf func(format string, args ...any), dir, key string, n int, text string) {
	const maxChunk = 350
	if len(text) <= maxChunk {
		logf("l2relay: tcp proxy %s preview[0] key=%q bytes=%d text=%q", dir, key, n, text)
		return
	}
	chunks := splitPreviewChunks(text, maxChunk)
	for i, chunk := range chunks {
		logf("l2relay: tcp proxy %s preview[%d/%d] key=%q bytes=%d text=%q", dir, i+1, len(chunks), key, n, chunk)
	}
}

func splitPreviewChunks(s string, maxChunk int) []string {
	if len(s) <= maxChunk {
		return []string{s}
	}
	var out []string
	for len(s) > 0 {
		if len(s) <= maxChunk {
			out = append(out, s)
			break
		}
		cut := maxChunk
		for cut > maxChunk/2 && cut < len(s) && s[cut] != ' ' {
			cut--
		}
		if cut <= maxChunk/2 {
			cut = maxChunk
		}
		out = append(out, s[:cut])
		s = s[cut:]
		for len(s) > 0 && s[0] == ' ' {
			s = s[1:]
		}
	}
	return out
}

type limitedCapture struct {
	buf []byte
}

func (c *limitedCapture) Write(p []byte) (int, error) {
	const maxPreview = 4096
	if len(c.buf) < maxPreview {
		remain := maxPreview - len(c.buf)
		if len(p) > remain {
			c.buf = append(c.buf, p[:remain]...)
		} else {
			c.buf = append(c.buf, p...)
		}
	}
	return len(p), nil
}

func (c *limitedCapture) preview() (string, bool) {
	if s, ok := c.httpHeaderPreview(); ok {
		return s, true
	}
	if s, ok := c.tlsPreview(); ok {
		return s, true
	}
	if len(c.buf) == 0 || looksBinary(c.buf) {
		return "", false
	}
	s := string(c.buf)
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s, true
}

func (c *limitedCapture) tlsPreview() (string, bool) {
	b := c.buf
	if len(b) < 5 {
		return "", false
	}
	contentType := b[0]
	if contentType < 20 || contentType > 23 {
		return "", false
	}
	recVerMaj, recVerMin := b[1], b[2]
	recLen := int(b[3])<<8 | int(b[4])
	if recLen <= 0 {
		return fmt.Sprintf("tls={record_type=%d version=%d.%d len=%d}", contentType, recVerMaj, recVerMin, recLen), true
	}
	if 5+recLen > len(b) {
		recLen = len(b) - 5
	}
	body := b[5 : 5+recLen]
	switch contentType {
	case 21:
		if len(body) >= 2 {
			return fmt.Sprintf("tls={alert level=%d desc=%d version=%d.%d}", body[0], body[1], recVerMaj, recVerMin), true
		}
		return fmt.Sprintf("tls={alert version=%d.%d len=%d}", recVerMaj, recVerMin, recLen), true
	case 22:
		if len(body) < 4 {
			return fmt.Sprintf("tls={handshake version=%d.%d len=%d}", recVerMaj, recVerMin, recLen), true
		}
		hsType := body[0]
		hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
		if 4+hsLen > len(body) {
			hsLen = len(body) - 4
		}
		hs := body[4 : 4+hsLen]
		switch hsType {
		case 1:
			sni, alpns := parseTLSClientHelloMetadata(hs)
			return fmt.Sprintf("tls={record=handshake version=%d.%d hs=client_hello sni=%q alpn=%q}", recVerMaj, recVerMin, sni, alpns), true
		case 2:
			return fmt.Sprintf("tls={record=handshake version=%d.%d hs=server_hello}", recVerMaj, recVerMin), true
		case 11:
			return fmt.Sprintf("tls={record=handshake version=%d.%d hs=certificate}", recVerMaj, recVerMin), true
		default:
			return fmt.Sprintf("tls={record=handshake version=%d.%d hs_type=%d}", recVerMaj, recVerMin, hsType), true
		}
	case 23:
		return fmt.Sprintf("tls={application_data version=%d.%d len=%d}", recVerMaj, recVerMin, recLen), true
	default:
		return fmt.Sprintf("tls={record_type=%d version=%d.%d len=%d}", contentType, recVerMaj, recVerMin, recLen), true
	}
}

func parseTLSClientHelloMetadata(hs []byte) (sni string, alpns []string) {
	if len(hs) < 2+32+1 {
		return "", nil
	}
	i := 0
	// legacy_version + random
	i += 2 + 32
	if i >= len(hs) {
		return "", nil
	}
	sessLen := int(hs[i])
	i++
	if i+sessLen > len(hs) {
		return "", nil
	}
	i += sessLen
	if i+2 > len(hs) {
		return "", nil
	}
	csLen := int(hs[i])<<8 | int(hs[i+1])
	i += 2
	if i+csLen > len(hs) {
		return "", nil
	}
	i += csLen
	if i >= len(hs) {
		return "", nil
	}
	compLen := int(hs[i])
	i++
	if i+compLen > len(hs) {
		return "", nil
	}
	i += compLen
	if i+2 > len(hs) {
		return "", nil
	}
	extLen := int(hs[i])<<8 | int(hs[i+1])
	i += 2
	if i+extLen > len(hs) {
		extLen = len(hs) - i
	}
	end := i + extLen
	for i+4 <= end {
		extType := int(hs[i])<<8 | int(hs[i+1])
		ln := int(hs[i+2])<<8 | int(hs[i+3])
		i += 4
		if i+ln > end {
			break
		}
		ext := hs[i : i+ln]
		i += ln
		switch extType {
		case 0: // server_name
			if len(ext) < 2 {
				continue
			}
			j := 2
			for j+3 <= len(ext) {
				nameType := ext[j]
				nameLen := int(ext[j+1])<<8 | int(ext[j+2])
				j += 3
				if j+nameLen > len(ext) {
					break
				}
				if nameType == 0 {
					sni = string(ext[j : j+nameLen])
					break
				}
				j += nameLen
			}
		case 16: // alpn
			if len(ext) < 2 {
				continue
			}
			j := 2
			for j < len(ext) {
				nameLen := int(ext[j])
				j++
				if j+nameLen > len(ext) {
					break
				}
				alpns = append(alpns, string(ext[j:j+nameLen]))
				j += nameLen
			}
		}
	}
	return sni, alpns
}

func (c *limitedCapture) httpHeaderPreview() (string, bool) {
	if len(c.buf) == 0 {
		return "", false
	}
	lead := string(c.buf)
	if !(strings.HasPrefix(lead, "GET ") ||
		strings.HasPrefix(lead, "POST ") ||
		strings.HasPrefix(lead, "HEAD ") ||
		strings.HasPrefix(lead, "PUT ") ||
		strings.HasPrefix(lead, "DELETE ") ||
		strings.HasPrefix(lead, "OPTIONS ") ||
		strings.HasPrefix(lead, "HTTP/1.")) {
		return "", false
	}
	end, sepLen := findHTTPHeaderEnd(c.buf)
	if end < 0 {
		end = len(c.buf)
		sepLen = 0
	}
	used := end + sepLen
	// If an interim 1xx response is followed by another HTTP status line in the
	// same captured prefix, include the next header block too.
	if strings.HasPrefix(lead, "HTTP/1.") && used < len(c.buf) {
		rest := c.buf[used:]
		for len(rest) > 0 && (rest[0] == '\r' || rest[0] == '\n') {
			used++
			rest = c.buf[used:]
		}
		if bytes.HasPrefix(rest, []byte("HTTP/1.")) {
			end2, sepLen2 := findHTTPHeaderEnd(rest)
			if end2 >= 0 {
				used += end2 + sepLen2
			} else {
				used = len(c.buf)
			}
		}
	}
	headerBytes := c.buf[:used]
	s := string(headerBytes)
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	if ipp, ok := ippPayloadPreview(c.buf, used, headerBytes); ok {
		s += " " + ipp
	}
	return s, true
}

func findHTTPHeaderEnd(b []byte) (end int, sepLen int) {
	if idx := bytes.Index(b, []byte("\r\n\r\n")); idx >= 0 {
		return idx, 4
	}
	if idx := bytes.Index(b, []byte("\n\n")); idx >= 0 {
		return idx, 2
	}
	return -1, 0
}

func ippPayloadPreview(buf []byte, headerLen int, headerBytes []byte) (string, bool) {
	if !bytes.Contains(bytes.ToLower(headerBytes), []byte("content-type: application/ipp")) {
		return "", false
	}
	if headerLen+8 > len(buf) {
		return "", false
	}
	body := buf[headerLen:]
	verMajor := body[0]
	verMinor := body[1]
	code := uint16(body[2])<<8 | uint16(body[3])
	reqID := uint32(body[4])<<24 | uint32(body[5])<<16 | uint32(body[6])<<8 | uint32(body[7])
	meta := fmt.Sprintf("ipp={ver=%d.%d code=0x%04x reqid=%d", verMajor, verMinor, code, reqID)
	if attrs := ippAttributePreview(body[8:]); attrs != "" {
		meta += " " + attrs
	}
	meta += "}"
	return meta, true
}

func ippAttributePreview(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	const maxAttrs = 200
	var parts []string
	var currentGroup string
	var lastName string
	i := 0
	for i < len(body) && len(parts) < maxAttrs {
		tag := body[i]
		i++
		switch tag {
		case 0x01:
			currentGroup = "op"
			continue
		case 0x02:
			currentGroup = "job"
			continue
		case 0x03:
			if currentGroup == "" {
				return strings.Join(parts, " ")
			}
			currentGroup = "end"
			return strings.Join(parts, " ")
		case 0x04:
			currentGroup = "printer"
			continue
		case 0x05:
			currentGroup = "unsupported"
			continue
		}
		if i+4 > len(body) {
			break
		}
		nameLen := int(body[i])<<8 | int(body[i+1])
		i += 2
		if i+nameLen > len(body) {
			break
		}
		name := string(body[i : i+nameLen])
		i += nameLen
		if nameLen == 0 {
			name = lastName
		} else {
			lastName = name
		}
		valLen := int(body[i])<<8 | int(body[i+1])
		i += 2
		if i+valLen > len(body) {
			break
		}
		val := body[i : i+valLen]
		i += valLen
		if name == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s=%s", currentGroup, name, ippValueString(tag, val)))
	}
	return strings.Join(parts, " ")
}

func ippValueString(tag byte, val []byte) string {
	switch tag {
	case 0x21, 0x23: // integer, enum
		if len(val) == 4 {
			n := int32(val[0])<<24 | int32(val[1])<<16 | int32(val[2])<<8 | int32(val[3])
			return strconv.FormatInt(int64(n), 10)
		}
	case 0x22: // boolean
		if len(val) == 1 {
			if val[0] == 0 {
				return "false"
			}
			return "true"
		}
	case 0x44, 0x45, 0x47, 0x48, 0x49, 0x4a:
		// keyword, uri, charset, naturalLanguage, mimeMediaType, memberAttrName
		return strconv.Quote(string(val))
	case 0x41, 0x42, 0x43:
		// textWithoutLanguage, nameWithoutLanguage, reserved text tags
		return strconv.Quote(string(val))
	}
	if len(val) == 0 {
		return `""`
	}
	if !looksBinary(val) {
		return strconv.Quote(string(val))
	}
	return fmt.Sprintf("<%d-bytes>", len(val))
}

func looksBinary(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	var bad int
	for _, c := range b {
		switch {
		case c == 0:
			return true
		case c == '\n' || c == '\r' || c == '\t':
			continue
		case c >= 0x20 && c <= 0x7e:
			continue
		default:
			bad++
		}
	}
	return bad > len(b)/8
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (m *l2RelayManager) dialRelayProxyTCP(relayBase, upstream string) (net.Conn, error) {
	if relayBase == "" {
		return nil, errors.New("empty relay base")
	}
	u, err := url.Parse(relayBase)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid relay base host: %q", relayBase)
	}
	m.logf("l2relay: tcp proxy opening relay tunnel relay=%q upstream=%q", u.Host, upstream)
	conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		return nil, err
	}
	req := "POST /v0/l2relay/proxy/tcp HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Tailscale-L2Relay-Target: " + upstream + "\r\n" +
		"Content-Length: 0\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}
	m.logf("l2relay: tcp proxy relay response relay=%q status=%q", u.Host, strings.TrimSpace(statusLine))
	if !strings.Contains(statusLine, " 101 ") {
		conn.Close()
		return nil, fmt.Errorf("proxy open failed: %s", strings.TrimSpace(statusLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		if line == "\r\n" {
			break
		}
	}
	if br.Buffered() == 0 {
		return conn, nil
	}
	return &bufferedConn{Conn: conn, r: br}, nil
}

func (m *l2RelayManager) rewriteMDNSResponseForRelayProxy(srcAddr netip.Addr, payload []byte, replySrcIP netip.Addr) ([]byte, bool) {
	_ = srcAddr
	_ = replySrcIP
	return payload, false
}

func rewriteMDNSResponseIPv4Address(payload []byte, fromIP, toIP netip.Addr) ([]byte, bool) {
	fromIP = fromIP.Unmap()
	toIP = toIP.Unmap()
	if !fromIP.IsValid() || !toIP.IsValid() || !fromIP.Is4() || !toIP.Is4() || fromIP == toIP {
		return payload, false
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(payload); err != nil || !msg.Header.Response {
		return payload, false
	}
	from4 := fromIP.As4()
	to4 := toIP.As4()
	changed := false
	rewrite := func(records []dnsmessage.Resource) {
		for i := range records {
			a, ok := records[i].Body.(*dnsmessage.AResource)
			if !ok {
				continue
			}
			if a.A == from4 {
				a.A = to4
				changed = true
			}
		}
	}
	rewrite(msg.Answers)
	rewrite(msg.Authorities)
	rewrite(msg.Additionals)
	if !changed {
		return payload, false
	}
	rebuilt, err := msg.Pack()
	if err != nil {
		return payload, false
	}
	return rebuilt, true
}

func (m *l2RelayManager) injectToLocalMulticast(payload []byte, network, dst string, proto l2RelayProto, sig string) {
	ra, err := net.ResolveUDPAddr(network, dst)
	if err != nil {
		m.logf("l2relay: local inject resolve error sig=%s network=%s dst=%s err=%v", sig, network, dst, err)
		return
	}

	var c net.PacketConn
	if proto == l2ProtoMDNS {
		c, err = m.listenMDNSSourcePort(network)
		if err != nil {
			m.logf("l2relay: local inject 5353 bind failed sig=%s network=%s dst=%s err=%v; falling back to ephemeral", sig, network, dst, err)
		}
	}
	if c == nil {
		c, err = net.ListenPacket(network, "")
		if err != nil {
			m.logf("l2relay: local inject listen error sig=%s network=%s dst=%s err=%v", sig, network, dst, err)
			return
		}
	}
	defer c.Close()
	if _, err := c.WriteTo(payload, ra); err != nil {
		m.logf("l2relay: local inject write error sig=%s network=%s dst=%s err=%v", sig, network, dst, err)
		return
	}
	// Record (sig, local IP, local port) for mDNS and WSD so the capture loop
	// can suppress bounce-backs by exact address match.
	// mDNS uses this as a belt-and-suspenders guard: listenMDNSSourcePort
	// binds port 5353 with SO_REUSEADDR, so injection may succeed with
	// src port 5353 — bypassing the port-5353 capture filter.
	if proto == l2ProtoMDNS || proto == l2ProtoWSD || proto == l2ProtoMinecraft {
		if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
			if ap, ok := udpAddrPort(ua); ok {
				m.noteInjectedPayload(proto, payload, ap)
			}
		}
	}
	m.logf("l2relay: injected local proto=%s sig=%s network=%s local=%v dst=%s bytes=%d note=\"OS host stack may still filter multicast delivery\"", proto, sig, network, c.LocalAddr(), dst, len(payload))
}

func summarizeDiscoveryPayload(proto l2RelayProto, payload []byte) (summary string, interested bool) {
	lower := strings.ToLower(string(payload))
	switch proto {
	case l2ProtoSSDP:
		lines := strings.Split(string(payload), "\r\n")
		var st, nt, usn, location, server string
		for _, ln := range lines {
			ll := strings.ToLower(ln)
			switch {
			case strings.HasPrefix(ll, "st:"):
				st = strings.TrimSpace(ln[3:])
			case strings.HasPrefix(ll, "nt:"):
				nt = strings.TrimSpace(ln[3:])
			case strings.HasPrefix(ll, "usn:"):
				usn = strings.TrimSpace(ln[4:])
			case strings.HasPrefix(ll, "location:"):
				location = strings.TrimSpace(ln[9:])
			case strings.HasPrefix(ll, "server:"):
				server = strings.TrimSpace(ln[7:])
			}
		}
		interested = strings.Contains(lower, "printer") || strings.Contains(lower, "ipp") || strings.Contains(lower, ":631/")
		return fmt.Sprintf("st=%q nt=%q usn=%q location=%q server=%q", st, nt, usn, location, server), interested
	case l2ProtoWSD:
		if s, i, ok := summarizeWSDPacket(payload); ok {
			return s, i
		}
		interested = strings.Contains(lower, "probe")
		return fmt.Sprintf("parse=raw contains_probe=%v contains_probe_matches=%v contains_printer=%v contains_smb=%v", strings.Contains(lower, "probe"), strings.Contains(lower, "probematches"), strings.Contains(lower, "printer"), strings.Contains(lower, "smb")), interested
	case l2ProtoNetBIOS:
		if s, i, ok := summarizeNetBIOSPacket(payload); ok {
			return s, i
		}
		return fmt.Sprintf("bytes=%d", len(payload)), false
	case l2ProtoMDNS:
		if s, p, ok := summarizeMDNSPacket(payload); ok {
			return s, p
		}
		interested = containsAnyMDNSToken(lower, relayInterestedMDNSTokens) || len(mdnsHostLookupQuestions(payload)) > 0
		return fmt.Sprintf("parse=raw contains_ipp=%v contains_ipps=%v contains_printer=%v contains_airprint=%v contains_smb=%v contains_adisk=%v host_lookup=%v", strings.Contains(lower, "_ipp._tcp"), strings.Contains(lower, "_ipps._tcp"), strings.Contains(lower, "_printer._tcp"), strings.Contains(lower, "airprint"), strings.Contains(lower, "_smb._tcp"), strings.Contains(lower, "_adisk._tcp"), len(mdnsHostLookupQuestions(payload)) > 0), interested
	default:
		return fmt.Sprintf("bytes=%d", len(payload)), false
	}
}

func summarizeMDNSPacket(payload []byte) (summary string, interested bool, ok bool) {
	var m dnsmessage.Message
	if err := m.Unpack(payload); err != nil {
		return "", false, false
	}
	const maxList = 4
	names := make([]string, 0, maxList*2)
	questions := make([]string, 0, maxList)
	answers := make([]string, 0, maxList)
	ptrKnownCache := make([]string, 0, maxList)
	hasPTRQuery := false

	addName := func(s string) {
		if len(names) >= maxList*2 {
			return
		}
		ls := strings.ToLower(s)
		names = append(names, ls)
	}
	addQ := func(s string) {
		if len(questions) < maxList {
			questions = append(questions, s)
		}
	}
	addA := func(s string) {
		if len(answers) < maxList {
			answers = append(answers, s)
		}
	}
	for _, q := range m.Questions {
		n := strings.TrimSuffix(q.Name.String(), ".")
		addName(n)
		qu := (uint16(q.Class) & 0x8000) != 0
		addQ(fmt.Sprintf("%s/%s(qu=%v)", n, q.Type.String(), qu))
		if q.Type == dnsmessage.TypePTR {
			hasPTRQuery = true
		}
	}
	for _, a := range m.Answers {
		n := strings.TrimSuffix(a.Header.Name.String(), ".")
		addName(n)
		switch b := a.Body.(type) {
		case *dnsmessage.PTRResource:
			ptr := strings.TrimSuffix(b.PTR.String(), ".")
			addName(ptr)
			addA(fmt.Sprintf("%s/PTR->%s", n, ptr))
			if !m.Header.Response && hasPTRQuery && len(ptrKnownCache) < maxList {
				ptrKnownCache = append(ptrKnownCache, fmt.Sprintf("%s->%s(ttl=%ds)", n, ptr, a.Header.TTL))
			}
		case *dnsmessage.SRVResource:
			tgt := strings.TrimSuffix(b.Target.String(), ".")
			addName(tgt)
			addA(fmt.Sprintf("%s/SRV->%s:%d", n, tgt, b.Port))
		case *dnsmessage.TXTResource:
			txt := ""
			if len(b.TXT) > 0 {
				txt = b.TXT[0]
			}
			addA(fmt.Sprintf("%s/TXT(%d,%q)", n, len(b.TXT), txt))
		default:
			addA(fmt.Sprintf("%s/%s", n, a.Header.Type.String()))
		}
	}

	for _, n := range names {
		if containsAnyMDNSToken(n, relayInterestedMDNSTokens) {
			interested = true
			break
		}
	}
	if !interested && len(mdnsHostLookupQuestions(payload)) > 0 {
		interested = true
	}
	knownCache := ""
	if len(ptrKnownCache) > 0 {
		knownCache = fmt.Sprintf(" ptr_known_cache=%q", ptrKnownCache)
	}
	return fmt.Sprintf("parse=dns qr=%v opcode=%v qd=%d an=%d ns=%d ar=%d q=%q a=%q%s", m.Header.Response, m.Header.OpCode, len(m.Questions), len(m.Answers), len(m.Authorities), len(m.Additionals), questions, answers, knownCache), interested, true
}

func detailedMDNSPacketLines(payload []byte) ([]string, bool) {
	var m dnsmessage.Message
	if err := m.Unpack(payload); err != nil {
		return nil, false
	}
	lines := []string{
		fmt.Sprintf("dns_hdr={qr=%v opcode=%v qd=%d an=%d ns=%d ar=%d}",
			m.Header.Response,
			m.Header.OpCode,
			len(m.Questions),
			len(m.Answers),
			len(m.Authorities),
			len(m.Additionals),
		),
	}
	for i, q := range m.Questions {
		lines = append(lines, fmt.Sprintf("q[%d]=%s", i, formatMDNSQuestion(q)))
	}
	for i, r := range m.Answers {
		lines = append(lines, fmt.Sprintf("an[%d]=%s", i, formatMDNSResource(r)))
	}
	for i, r := range m.Authorities {
		lines = append(lines, fmt.Sprintf("ns[%d]=%s", i, formatMDNSResource(r)))
	}
	for i, r := range m.Additionals {
		lines = append(lines, fmt.Sprintf("ar[%d]=%s", i, formatMDNSResource(r)))
	}
	return lines, true
}

func formatMDNSQuestion(q dnsmessage.Question) string {
	name := strings.TrimSuffix(q.Name.String(), ".")
	qu := (uint16(q.Class) & 0x8000) != 0
	return fmt.Sprintf("%s %s qu=%v", name, q.Type.String(), qu)
}

func formatMDNSResource(r dnsmessage.Resource) string {
	name := strings.TrimSuffix(r.Header.Name.String(), ".")
	base := fmt.Sprintf("%s %s ttl=%d", name, r.Header.Type.String(), r.Header.TTL)
	switch b := r.Body.(type) {
	case *dnsmessage.PTRResource:
		return fmt.Sprintf("%s ptr=%s", base, strings.TrimSuffix(b.PTR.String(), "."))
	case *dnsmessage.SRVResource:
		return fmt.Sprintf("%s target=%s port=%d pri=%d weight=%d", base, strings.TrimSuffix(b.Target.String(), "."), b.Port, b.Priority, b.Weight)
	case *dnsmessage.TXTResource:
		txt := make([]string, 0, len(b.TXT))
		for _, s := range b.TXT {
			txt = append(txt, strconv.Quote(s))
		}
		return fmt.Sprintf("%s txt=%s", base, strings.Join(txt, ","))
	case *dnsmessage.AResource:
		ip := net.IPv4(b.A[0], b.A[1], b.A[2], b.A[3])
		return fmt.Sprintf("%s addr=%s", base, ip.String())
	case *dnsmessage.AAAAResource:
		var ip [16]byte
		copy(ip[:], b.AAAA[:])
		return fmt.Sprintf("%s addr=%s", base, netip.AddrFrom16(ip))
	default:
		return base
	}
}

func rewriteSSDPForPeer(payload []byte, peerIP netip.Addr) []byte {
	lines := strings.Split(string(payload), "\r\n")
	for i, ln := range lines {
		if !strings.HasPrefix(strings.ToLower(ln), "location:") {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(ln, "LOCATION:"))
		if raw == strings.TrimSpace(strings.TrimPrefix(ln, "location:")) {
			raw = strings.TrimSpace(strings.TrimPrefix(ln, "location:"))
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		_, port, err := net.SplitHostPort(u.Host)
		if err != nil && strings.Contains(u.Host, ":") {
			continue
		}
		if err != nil {
			port = ""
		}
		if port != "" {
			u.Host = net.JoinHostPort(peerIP.String(), port)
		} else {
			u.Host = peerIP.String()
		}
		lines[i] = "LOCATION: " + u.String()
	}
	return []byte(strings.Join(lines, "\r\n"))
}

func (m *l2RelayManager) snapshotHello() l2RelayHello {
	lockedAt := m.lockRelayMu("snapshotHello")
	defer m.unlockRelayMu("snapshotHello", lockedAt)
	return l2RelayHello{
		SegmentID:     m.segmentID,
		SegmentStrong: m.segmentStrong,
		Rank:          m.rank,
		RelayDataPort: l2RelayDataPort,
		At:            time.Now(),
	}
}

func (m *l2RelayManager) recordHello(from tailcfg.NodeView, hello l2RelayHello) {
	if hello.SegmentID == "" {
		m.limitedLogf("[v2] l2relay: ignoring hello with empty segment from=%v", from.Name())
		return
	}
	now := time.Now()
	lockedAt := m.lockRelayMu("recordHello")
	ps := m.peers[from.ID()]
	ps.segmentID = hello.SegmentID
	ps.segmentStrong = hello.SegmentStrong
	ps.rank = hello.Rank
	if hello.RelayDataPort != 0 {
		ps.relayDataPort = hello.RelayDataPort
	} else if ps.relayDataPort == 0 {
		ps.relayDataPort = l2RelayDataPort
	}
	if hello.At.IsZero() {
		ps.lastHello = now
	} else {
		ps.lastHello = hello.At
	}
	ps.lastSeen = now
	m.peers[from.ID()] = ps
	m.electLeaderLocked(hello.SegmentID)
	m.unlockRelayMu("recordHello", lockedAt)
	m.limitedLogf("[v2] l2relay: hello update from=%v segment=%q rank=%d relay_port=%d",
		from.Name(), hello.SegmentID, hello.Rank, ps.relayDataPort)
}

func (m *l2RelayManager) recordLeader(from tailcfg.NodeView, msg l2RelayLeader) error {
	if msg.LeaderID != tailcfg.NodeID(0) && msg.LeaderID != from.ID() {
		m.limitedLogf("[v1] l2relay: peerapi leader reject from=%d claimed=%d segment=%q", from.ID(), msg.LeaderID, msg.SegmentID)
		return errors.New("invalid leader")
	}

	if msg.SegmentID == "" {
		return errors.New("invalid segment ID")
	}
	now := time.Now()
	if msg.LeaseTill.IsZero() {
		msg.LeaseTill = now.Add(30 * time.Second)
	}
	lockedAt := m.lockRelayMu("recordLeader")
	m.leaderBySeg[msg.SegmentID] = msg
	m.unlockRelayMu("recordLeader", lockedAt)
	m.limitedLogf("[v2] l2relay: leader update segment=%q leader=%d lease_till=%s", msg.SegmentID, msg.LeaderID, msg.LeaseTill.Format(time.RFC3339Nano))
	return nil
}

func (m *l2RelayManager) electLeaderLocked(segmentID string) {
	if !m.segmentStrong || segmentID == "" {
		return
	}
	prevLeader := m.leaderBySeg[segmentID].LeaderID
	bestID := tailcfg.NodeID(0)
	bestRank := uint64(0)

	if m.segmentID == segmentID && m.segmentID != "" {
		selfID := m.selfNodeIDLocked()
		bestID = selfID
		bestRank = m.rank
	}
	for id, ps := range m.peers {
		if ps.segmentID != segmentID {
			continue
		}
		if !ps.segmentStrong {
			continue
		}
		if bestID == 0 || ps.rank > bestRank || (ps.rank == bestRank && id > bestID) {
			bestID = id
			bestRank = ps.rank
		}
	}
	if bestID == 0 {
		return
	}
	m.leaderBySeg[segmentID] = l2RelayLeader{
		SegmentID: segmentID,
		LeaderID:  bestID,
		LeaseTill: time.Now().Add(30 * time.Second),
	}
	if prevLeader != bestID {
		m.logf("l2relay: elected leader segment=%q leader=%d rank=%d prev=%d", segmentID, bestID, bestRank, prevLeader)
	}
}

func (m *l2RelayManager) selfNodeIDLocked() tailcfg.NodeID {
	return m.selfNodeID
}

func (m *l2RelayManager) maybeSendHelloToPeers(ctx context.Context) {
	// Apple clients can participate as query/response forwarders, but should not
	// advertise relay-leader hello traffic because they cannot inject multicast.
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		m.logf("[v2] l2relay: hello tick skipped (apple platform goos=%q)", runtime.GOOS)
		return
	}
	lockedAt := m.lockRelayMu("maybeSendHelloToPeers.cap")
	selfCanRelay := m.selfCanRelayQuery
	m.unlockRelayMu("maybeSendHelloToPeers.cap", lockedAt)
	if !selfCanRelay {
		m.logf("[v2] l2relay: hello tick skipped (self relay capability disabled)")
		return
	}
	hello := m.snapshotHello()
	if hello.SegmentID == "" {
		m.logf("[v2] l2relay: hello tick skipped (empty segment)")
		return
	}
	nm := m.b.NetMap()
	if nm == nil {
		m.logf("[v2] l2relay: hello tick skipped (no netmap)")
		return
	}
	peers := m.filterRelayOnlinePeers(nm.Peers, "hello")
	selfIP, ok := m.selfTailscaleIP()
	if !ok {
		m.logf("[v2] l2relay: hello tick skipped (no self tailscale IPv4)")
		return
	}
	sent := 0
	for _, p := range peers {
		dstIP := nodeIP(p, netip.Addr.Is4)
		if !dstIP.IsValid() {
			continue
		}
		if !m.l2DiscoveryAllowed(selfIP, dstIP, string(l2ProtoMDNS), false) {
			continue
		}
		base := m.b.PeerAPIBase(p)
		if base == "" {
			continue
		}
		// Each peer gets its own timeout derived from the cancellable root context,
		// not from the shared parent tick context whose budget is eaten sequentially.
		go func(base string) {
			peerCtx, cancel := context.WithTimeout(ctx, l2RelayPeerSendTimeout)
			defer cancel()
			m.sendHello(peerCtx, base, hello)
		}(base)
		sent++
	}
	m.limitedLogf("[v1] l2relay: hello tick segment=%q rank=%d sent=%d online_peers=%d", hello.SegmentID, hello.Rank, sent, len(peers))
	m.maybeSendLeaderToPeers(ctx, nm)
}

func (m *l2RelayManager) sendHello(ctx context.Context, base string, hello l2RelayHello) {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(&hello); err != nil {
		return
	}
	res, err := m.postPeerAPIJSON(ctx, base+"/v0/l2relay/hello", body.Bytes())
	if err != nil {
		m.logf("l2relay: hello post failed base=%q err=%v", base, err)
		return
	}
	m.limitedLogf("[v1] l2relay: hello post ok base=%q status=%s", base, res.Status)
}

func (m *l2RelayManager) maybeSendLeaderToPeers(ctx context.Context, nm *netmap.NetworkMap) {
	lockedAt := m.lockRelayMu("maybeSendLeaderToPeers")
	segmentStrong := m.segmentStrong
	leader, ok := m.leaderBySeg[m.segmentID]
	selfID := m.selfNodeID
	m.unlockRelayMu("maybeSendLeaderToPeers", lockedAt)
	if !segmentStrong {
		return
	}
	if !ok || leader.LeaderID != selfID || leader.SegmentID == "" {
		return
	}
	selfIP, ok := m.selfTailscaleIP()
	if !ok {
		return
	}
	peers := m.filterRelayOnlinePeers(nm.Peers, "leader")
	sent := 0
	for _, p := range peers {
		dstIP := nodeIP(p, netip.Addr.Is4)
		if !dstIP.IsValid() {
			continue
		}
		if !m.l2DiscoveryAllowed(selfIP, dstIP, string(l2ProtoMDNS), false) {
			continue
		}
		base := m.b.PeerAPIBase(p)
		if base == "" {
			continue
		}
		var body bytes.Buffer
		if err := json.NewEncoder(&body).Encode(&leader); err != nil {
			continue
		}
		payload := body.Bytes()
		go func(base string, payload []byte) {
			peerCtx, cancel := context.WithTimeout(ctx, l2RelayPeerSendTimeout)
			defer cancel()
			res, err := m.postPeerAPIJSON(peerCtx, base+"/v0/l2relay/leader", payload)
			if err != nil {
				m.logf("l2relay: leader post failed base=%q err=%v", base, err)
				return
			}
			m.limitedLogf("[v2] l2relay: leader post ok base=%q status=%s leader=%d segment=%q", base, res.Status, leader.LeaderID, leader.SegmentID)
		}(base, payload)
		sent++
	}
	m.limitedLogf("[v1] l2relay: leader announce sent=%d online_peers=%d leader=%d segment=%q", sent, len(peers), leader.LeaderID, leader.SegmentID)
}

func (m *l2RelayManager) postPeerAPIJSON(parent context.Context, url string, payload []byte) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(parent, l2RelayPeerSendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Keep l2relay UDP-like control traffic isolated from the shared PeerAPI
	// HTTP transport. A sleepy peer timing out should not churn the common
	// peerapi idle pool used by other features or trigger retry/reset behavior.
	tr := m.b.Dialer().PeerAPITransport().Clone()
	tr.DisableKeepAlives = true
	tr.MaxIdleConns = 0
	tr.MaxIdleConnsPerHost = 0
	tr.MaxConnsPerHost = 2
	client := &http.Client{Transport: tr}

	res, err := client.Do(req)
	if err != nil {
		tr.CloseIdleConnections()
		return nil, err
	}
	res.Body.Close()
	tr.CloseIdleConnections()
	return res, nil
}

func (m *l2RelayManager) filterRelayOnlinePeers(peers []tailcfg.NodeView, path string) []tailcfg.NodeView {
	ret := make([]tailcfg.NodeView, 0, len(peers))
	skipCap := 0
	skipOffline := 0
	for _, p := range peers {
		if !p.HasCap(tailcfg.NodeCanInjectL2Discovery) && !p.HasCap(tailcfg.NodeHasL2DiscoverableService) {
			skipCap++
			continue
		}
		if online, ok := p.Online().GetOk(); !ok || !online {
			skipOffline++
			continue
		}
		ret = append(ret, p)
	}
	m.limitedLogf("[v1] l2relay: peer filter path=%s total=%d eligible=%d skip_cap=%d skip_offline=%d", path, len(peers), len(ret), skipCap, skipOffline)
	return ret
}
