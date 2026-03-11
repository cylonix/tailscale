// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package l2relay_test

import (
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/l2relay"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
)

type l2TestNode struct {
	id tailcfg.NodeID
	ip netip.Addr

	b *ipnlocal.LocalBackend
	m *l2relay.Manager

	mu       sync.Mutex
	injected map[l2relay.Proto][][]byte
}

func (n *l2TestNode) NodeView() tailcfg.NodeView {
	return (&tailcfg.Node{
		ID:        tailcfg.NodeID(n.id),
		Addresses: []netip.Prefix{netip.PrefixFrom(n.ip, 32)},
	}).View()
}

func TestL2RelayMultiNodeIntegration(t *testing.T) {
	const (
		segA = "seg-a"
		segB = "seg-b"
	)
	peerIDs := []tailcfg.NodeID{100, 101, 102, 200}
	peerIPs := []string{"100.64.0.10", "100.64.0.11", "100.64.0.12", "100.64.0.20"}

	allowAOut := []tailcfg.L2DiscoveryRule{{
		SrcIPs:    []string{"100.64.0.10", "100.64.0.11"},
		DstIPs:    []string{"100.64.0.20"},
		Protocols: []string{"ssdp", "minecraft"},
	}}
	allowBIn := []tailcfg.L2DiscoveryRule{{
		SrcIPs:    []string{"100.64.0.10", "100.64.0.11"},
		DstIPs:    []string{"100.64.0.20"},
		Protocols: []string{"ssdp", "minecraft"},
	}}

	nodeA := newL2TestNode(100, "100.64.0.10", segA, 100, peerIDs, peerIPs, allowAOut)
	nodeAFollower := newL2TestNode(101, "100.64.0.11", segA, 50, peerIDs, peerIPs, allowAOut)
	nodeObserver := newL2TestNode(102, "100.64.0.12", segA, 10, peerIDs, peerIPs, nil)
	nodeB := newL2TestNode(200, "100.64.0.20", segB, 90, peerIDs, peerIPs, allowBIn)

	all := []*l2TestNode{nodeA, nodeAFollower, nodeObserver, nodeB}
	nodeByIP := map[netip.Addr]*l2TestNode{}
	for _, n := range all {
		nodeByIP[n.ip] = n
	}

	for _, n := range all {
		n := n
		n.m.SetSendEnvelopeHook(func(dst netip.Addr, env l2relay.Envelope) {
			target, ok := nodeByIP[dst]
			if !ok {
				return
			}
			b, err := json.Marshal(&env)
			if err != nil {
				t.Fatalf("marshal envelope: %v", err)
			}
			srcAP := netip.AddrPortFrom(n.ip, 41000)
			target.m.HandleIncomingEnvelope(srcAP, dst, b)
		})
		n.m.SetInjectPacketHook(func(proto l2relay.Proto, payload []byte) {
			n.mu.Lock()
			defer n.mu.Unlock()
			n.injected[proto] = append(n.injected[proto], append([]byte(nil), payload...))
		})
	}

	helloA := nodeA.m.SnapshotHello()
	helloAF := nodeAFollower.m.SnapshotHello()
	helloObs := nodeObserver.m.SnapshotHello()
	nodeA.m.HandleHello(nodeAFollower.NodeView(), helloAF)
	nodeA.m.HandleHello(nodeObserver.NodeView(), helloObs)
	nodeAFollower.m.HandleHello(nodeA.NodeView(), helloA)
	nodeAFollower.m.HandleHello(nodeObserver.NodeView(), helloObs)
	nodeObserver.m.HandleHello(nodeA.NodeView(), helloA)
	nodeObserver.m.HandleHello(nodeAFollower.NodeView(), helloAF)

	if leader, ok := nodeA.m.LeaderForSegment(segA); !ok || leader.LeaderID != nodeA.id {
		got := tailcfg.NodeID(0)
		if ok {
			got = leader.LeaderID
		}
		t.Fatalf("segment A leader=%v, want %v", got, nodeA.id)
	}
	if leader, ok := nodeAFollower.m.LeaderForSegment(segA); !ok || leader.LeaderID != nodeA.id {
		got := tailcfg.NodeID(0)
		if ok {
			got = leader.LeaderID
		}
		t.Fatalf("segment A follower view leader=%v, want %v", got, nodeA.id)
	}

	leaderB := l2relay.Leader{SegmentID: segB, LeaderID: nodeB.id, LeaseTill: time.Now().Add(30 * time.Second)}
	nodeA.m.HandleLeader(nodeB.NodeView(), leaderB)
	nodeAFollower.m.HandleLeader(nodeB.NodeView(), leaderB)
	nodeObserver.m.HandleLeader(nodeB.NodeView(), leaderB)
	leaderA := l2relay.Leader{SegmentID: segA, LeaderID: nodeA.id, LeaseTill: time.Now().Add(30 * time.Second)}
	nodeB.m.HandleLeader(nodeA.NodeView(), leaderA)

	ssdp := []byte("NOTIFY * HTTP/1.1\r\nLOCATION: http://192.168.0.2:631/ipp/print\r\n\r\n")
	nodeAFollower.m.ForwardCaptured(l2relay.ProtoSSDP, ssdp, "", nil)
	if got := nodeB.injectCount(l2relay.ProtoSSDP); got != 0 {
		t.Fatalf("follower forwarded unexpectedly; nodeB ssdp inject count=%d", got)
	}

	nodeA.m.ForwardCaptured(l2relay.ProtoSSDP, ssdp, "", nil)
	if got := nodeB.injectCount(l2relay.ProtoSSDP); got != 1 {
		t.Fatalf("leader forward failed; nodeB ssdp inject count=%d, want 1", got)
	}
	gotSSDP := string(nodeB.lastInjected(l2relay.ProtoSSDP))
	if !strings.Contains(gotSSDP, "LOCATION: http://100.64.0.20:631/ipp/print") {
		t.Fatalf("ssdp LOCATION not rewritten to relay endpoint, got: %q", gotSSDP)
	}
	if got := nodeObserver.injectCount(l2relay.ProtoSSDP); got != 0 {
		t.Fatalf("observer should not receive ssdp, got=%d", got)
	}

	mc := []byte("MC-LAN|192.168.0.2:25565")
	nodeA.m.ForwardCaptured(l2relay.ProtoMinecraft, mc, "", nil)
	if got := nodeB.injectCount(l2relay.ProtoMinecraft); got != 1 {
		t.Fatalf("minecraft forward failed; nodeB count=%d, want 1", got)
	}
	if got := string(nodeB.lastInjected(l2relay.ProtoMinecraft)); got != string(mc) {
		t.Fatalf("minecraft payload changed unexpectedly, got=%q", got)
	}
}

func TestL2RelaySameSegmentSingleLeaderForwards(t *testing.T) {
	peerIDs := []tailcfg.NodeID{100, 101, 200}
	peerIPs := []string{"100.64.0.10", "100.64.0.11", "100.64.0.20"}
	rules := []tailcfg.L2DiscoveryRule{{
		SrcIPs:    []string{"100.64.0.10", "100.64.0.11"},
		DstIPs:    []string{"100.64.0.20"},
		Protocols: []string{"ssdp"},
	}}

	leader := newL2TestNode(100, "100.64.0.10", "seg-a", 100, peerIDs, peerIPs, rules)
	follower := newL2TestNode(101, "100.64.0.11", "seg-a", 50, peerIDs, peerIPs, rules)
	remote := newL2TestNode(200, "100.64.0.20", "seg-b", 90, peerIDs, peerIPs, rules)

	all := []*l2TestNode{leader, follower, remote}
	nodeByIP := map[netip.Addr]*l2TestNode{}
	for _, n := range all {
		nodeByIP[n.ip] = n
	}
	for _, n := range all {
		n := n
		n.m.SetSendEnvelopeHook(func(dst netip.Addr, env l2relay.Envelope) {
			target, ok := nodeByIP[dst]
			if !ok {
				return
			}
			b, err := json.Marshal(&env)
			if err != nil {
				t.Fatalf("marshal envelope: %v", err)
			}
			target.m.HandleIncomingEnvelope(netip.AddrPortFrom(n.ip, 41000), dst, b)
		})
		n.m.SetInjectPacketHook(func(proto l2relay.Proto, payload []byte) {
			n.mu.Lock()
			defer n.mu.Unlock()
			n.injected[proto] = append(n.injected[proto], append([]byte(nil), payload...))
		})
	}

	helloLeader := leader.m.SnapshotHello()
	helloFollower := follower.m.SnapshotHello()
	leader.m.HandleHello(follower.NodeView(), helloFollower)
	follower.m.HandleHello(leader.NodeView(), helloLeader)

	leader.m.HandleLeader(remote.NodeView(), l2relay.Leader{SegmentID: "seg-b", LeaderID: remote.id, LeaseTill: time.Now().Add(30 * time.Second)})
	follower.m.HandleLeader(remote.NodeView(), l2relay.Leader{SegmentID: "seg-b", LeaderID: remote.id, LeaseTill: time.Now().Add(30 * time.Second)})
	remote.m.HandleLeader(remote.NodeView(), l2relay.Leader{SegmentID: "seg-a", LeaderID: leader.id, LeaseTill: time.Now().Add(30 * time.Second)})

	ssdp := []byte("NOTIFY * HTTP/1.1\r\nLOCATION: http://192.168.0.2:631/ipp/print\r\n\r\n")
	follower.m.ForwardCaptured(l2relay.ProtoSSDP, ssdp, "", nil)
	if got := remote.injectCount(l2relay.ProtoSSDP); got != 0 {
		t.Fatalf("follower should not relay; remote count=%d", got)
	}
	leader.m.ForwardCaptured(l2relay.ProtoSSDP, ssdp, "", nil)
	if got := remote.injectCount(l2relay.ProtoSSDP); got != 1 {
		t.Fatalf("leader should relay exactly once; remote count=%d", got)
	}
}

func newL2TestNode(id tailcfg.NodeID, ipStr, segment string, rank uint64, peerIDs []tailcfg.NodeID, peerIPs []string, rules []tailcfg.L2DiscoveryRule) *l2TestNode {
	ip := netip.MustParseAddr(ipStr)
	b := &ipnlocal.LocalBackend{}
	b.StoreTestFilter(filter.NewAllowAllForTest(logger.Discard))

	var peers []tailcfg.NodeView
	for i, pid := range peerIDs {
		if pid == id {
			continue
		}
		peers = append(peers, (&tailcfg.Node{
			ID:        pid,
			Cap:       tailcfg.L2RelaySupportCapabilityVersion,
			Online:    ptr.To(true),
			CapMap:    tailcfg.NodeCapMap{tailcfg.NodeCanInjectL2Discovery: []tailcfg.RawMessage{"can inject"}},
			Addresses: []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr(peerIPs[i]), 32)},
		}).View())
	}
	b.SetTestNetmap(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID: id,
			CapMap: tailcfg.NodeCapMap{
				tailcfg.NodeCanRelayL2Discovery:  []tailcfg.RawMessage{"can relay"},
				tailcfg.NodeCanInjectL2Discovery: []tailcfg.RawMessage{"can inject"},
			},
			Addresses: []netip.Prefix{netip.PrefixFrom(ip, 32)},
		}).View(),
		Peers:            peers,
		L2DiscoveryRules: views.SliceOf(rules),
	})

	m := l2relay.NewManager(b)
	m.SetSelfState(id, segment, true, rank)

	return &l2TestNode{
		id:       id,
		ip:       ip,
		b:        b,
		m:        m,
		injected: make(map[l2relay.Proto][][]byte),
	}
}

func (n *l2TestNode) injectCount(proto l2relay.Proto) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.injected[proto])
}

func (n *l2TestNode) lastInjected(proto l2relay.Proto) []byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	v := n.injected[proto]
	if len(v) == 0 {
		return nil
	}
	return append([]byte(nil), v[len(v)-1]...)
}
