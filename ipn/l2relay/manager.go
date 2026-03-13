// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package l2relay

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"

	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/types/nettype"
	"tailscale.com/wgengine/filter"
)

type Proto = l2RelayProto

const (
	ProtoMDNS      Proto = l2ProtoMDNS
	ProtoSSDP      Proto = l2ProtoSSDP
	ProtoWSD       Proto = l2ProtoWSD
	ProtoNetBIOS   Proto = l2ProtoNetBIOS
	ProtoMinecraft Proto = l2ProtoMinecraft
)

type Envelope = l2RelayEnvelope
type Hello = l2RelayHello
type Leader = l2RelayLeader

const (
	DataPort = l2RelayDataPort
	MaxSize  = l2RelayMaxSize
)

type Backend interface {
	NetMon() *netmon.Monitor
	NetMap() *netmap.NetworkMap
	Dialer() *tsdial.Dialer
	Filter() *filter.Filter
	PeerAPIBase(peer tailcfg.NodeView) string
}

type Manager struct {
	m *l2RelayManager
}

func NewManager(b Backend) *Manager {
	m := newL2RelayManager(b)
	if m == nil {
		return nil
	}
	return &Manager{m: m}
}

func (m *Manager) SetNetMap(nm *netmap.NetworkMap) {
	if m == nil || m.m == nil {
		return
	}
	m.m.setNetMap(nm)
}

func (m *Manager) StartCapture(ctx context.Context) {
	if m == nil || m.m == nil {
		return
	}
	m.m.startCapture(ctx)
}

func (m *Manager) SetCaptureEnabled(enabled bool) {
	if m == nil || m.m == nil {
		return
	}
	m.m.setCaptureEnabled(enabled)
}

func (m *Manager) Close() {
	if m == nil || m.m == nil {
		return
	}
	m.m.close()
}

func (m *Manager) UnregisterNetworkChangeCallbackForTest() {
	if m == nil || m.m == nil {
		return
	}
	m.m.unregisterNetworkChangeCallback()
}

func (m *Manager) CaptureEnabled() bool {
	if m == nil || m.m == nil {
		return false
	}
	return m.m.captureEnabledState()
}

func (m *Manager) MaybeSendHelloToPeers(ctx context.Context) {
	if m == nil || m.m == nil {
		return
	}
	m.m.maybeSendHelloToPeers(ctx)
}

func (m *Manager) UDPHandlerForFlow(src, dst netip.AddrPort) (func(nettype.ConnPacketConn), bool) {
	if m == nil || m.m == nil {
		return nil, false
	}
	return m.m.udpHandlerForFlow(src, dst)
}

func (m *Manager) TCPHandlerForFlow(src, dst netip.AddrPort) (func(net.Conn) error, bool) {
	if m == nil || m.m == nil {
		return nil, false
	}
	return m.m.tcpHandlerForFlow(src, dst)
}

func (m *Manager) ForwardCaptured(proto Proto, payload []byte, queryKey string, capturedSrc *net.UDPAddr) {
	if m == nil || m.m == nil {
		return
	}
	m.m.forwardCaptured(proto, payload, queryKey, capturedSrc)
}

func (m *Manager) SnapshotHello() Hello {
	if m == nil || m.m == nil {
		return Hello{}
	}
	return m.m.snapshotHello()
}

func (m *Manager) SetSelfState(nodeID tailcfg.NodeID, segmentID string, segmentStrong bool, rank uint64) {
	if m == nil || m.m == nil {
		return
	}
	lockedAt := m.m.lockRelayMu("SetSelfState")
	m.m.selfNodeID = nodeID
	m.m.segmentID = segmentID
	m.m.segmentStrong = segmentStrong
	m.m.rank = rank
	m.m.unlockRelayMu("SetSelfState", lockedAt)
}

func (m *Manager) LeaderForSegment(segmentID string) (Leader, bool) {
	if m == nil || m.m == nil {
		return Leader{}, false
	}
	lockedAt := m.m.lockRelayMu("LeaderForSegment")
	leader, ok := m.m.leaderBySeg[segmentID]
	m.m.unlockRelayMu("LeaderForSegment", lockedAt)
	return leader, ok
}

func (m *Manager) SetSendEnvelopeHook(fn func(dst netip.Addr, env Envelope)) {
	if m == nil || m.m == nil {
		return
	}
	m.m.sendEnvelopeHook = fn
}

func (m *Manager) SetInjectPacketHook(fn func(proto Proto, payload []byte)) {
	if m == nil || m.m == nil {
		return
	}
	m.m.injectPacketHook = fn
}

func (m *Manager) HandleHello(from tailcfg.NodeView, msg Hello) {
	if m == nil || m.m == nil {
		return
	}
	handleHello(m.m, from, msg)
}

func (m *Manager) HandleLeader(from tailcfg.NodeView, msg Leader) error {
	if m == nil || m.m == nil {
		return nil
	}
	return handleLeader(m.m, from, msg)
}

func (m *Manager) HandleIncomingEnvelope(src netip.AddrPort, selfAddr netip.Addr, raw []byte) error {
	if m == nil || m.m == nil {
		return nil
	}
	return handleEnvelope(m.m, src, selfAddr, raw)
}

// TunOutboundCaptureFunc returns a tstun.FilterFunc to install as
// tstun.Wrapper.PreFilterPacketOutboundCapture. It intercepts locally-sourced
// multicast packets (mDNS, WSD) before the main filter can drop them, which
// is necessary on Windows where the OS does not loop multicast back to the
// physical-interface socket when the packet is routed through the tunnel.
func (m *Manager) TunOutboundCaptureFunc() tstun.FilterFunc {
	if m == nil || m.m == nil {
		return nil
	}
	return m.m.tunOutboundCaptureFunc()
}

// SetInjectInboundUDP sets a callback that injects a raw IPv4/UDP packet as
// an inbound packet on the TUN device. This is used on Windows to deliver
// WSD/mDNS responses to queries that were captured via the TUN outbound hook
// (where the querier source IP is the Tailscale CGNAT address).
// fn should call tstun.Wrapper.InjectInboundCopy with a packet built from
// src, dst, and payload.
func (m *Manager) ProxyTCP(from tailcfg.NodeView, target string, fromAddr, selfAddr netip.Addr, w http.ResponseWriter) error {
	if m == nil || m.m == nil {
		return errors.New("l2relay manager not initialized")
	}
	return proxyTCP(m.m, from, target, fromAddr, selfAddr, w)
}
