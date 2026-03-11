// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package l2relay_test

import (
	"encoding/json"
	"net/netip"
	"testing"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/l2relay"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
)

func TestL2RelayIncomingEnvelopePolicyGate(t *testing.T) {
	b := &ipnlocal.LocalBackend{}
	b.StoreTestFilter(filter.NewAllowAllForTest(logger.Discard))

	selfAddr := netip.MustParsePrefix("100.64.0.10/32")
	b.SetTestNetmap(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID: 100,
			CapMap: tailcfg.NodeCapMap{
				tailcfg.NodeCanInjectL2Discovery: []tailcfg.RawMessage{"can inject"},
			},
			Addresses: []netip.Prefix{selfAddr},
		}).View(),
		L2DiscoveryRules: views.SliceOf([]tailcfg.L2DiscoveryRule{{
			SrcIPs:    []string{"100.64.0.0/10"},
			DstIPs:    []string{"100.64.0.10"},
			Protocols: []string{"ssdp"},
		}}),
	})
	m := l2relay.NewManager(b)
	var got int
	m.SetInjectPacketHook(func(proto l2relay.Proto, payload []byte) {
		got++
	})

	raw, _ := json.Marshal(l2relay.Envelope{
		OriginNodeID: 200,
		OriginBootID: "boot",
		Seq:          1,
		Proto:        l2relay.ProtoSSDP,
		Hops:         1,
		Payload:      []byte("NOTIFY * HTTP/1.1\r\nLOCATION: http://192.168.0.2:631/ipp/print\r\n\r\n"),
	})
	m.HandleIncomingEnvelope(netip.MustParseAddrPort("100.64.0.20:5000"), selfAddr.Addr(), raw)
	if got != 1 {
		t.Fatalf("inject count=%d, want 1", got)
	}

	raw, _ = json.Marshal(l2relay.Envelope{
		OriginNodeID: 200,
		OriginBootID: "boot2",
		Seq:          2,
		Proto:        l2relay.ProtoMDNS,
		Hops:         1,
		Payload:      []byte("hello"),
	})
	m.HandleIncomingEnvelope(netip.MustParseAddrPort("100.64.0.20:5000"), selfAddr.Addr(), raw)
	if got != 1 {
		t.Fatalf("inject count after denied proto=%d, want 1", got)
	}
}

func TestL2RelayForwardCapturedRewritesAndSends(t *testing.T) {
	b := &ipnlocal.LocalBackend{}
	b.StoreTestFilter(filter.NewAllowAllForTest(logger.Discard))
	selfAddr := netip.MustParsePrefix("100.64.0.10/32")
	b.SetTestNetmap(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID: 100,
			CapMap: tailcfg.NodeCapMap{
				tailcfg.NodeCanRelayL2Discovery: []tailcfg.RawMessage{"can relay"},
			},
			Addresses: []netip.Prefix{selfAddr},
		}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				ID:     200,
				Cap:    tailcfg.L2RelaySupportCapabilityVersion,
				Online: ptr.To(true),
				CapMap: tailcfg.NodeCapMap{
					tailcfg.NodeCanInjectL2Discovery: []tailcfg.RawMessage{"can inject"},
				},
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.20/32")},
			}).View(),
		},
		L2DiscoveryRules: views.SliceOf([]tailcfg.L2DiscoveryRule{{
			SrcIPs:    []string{"100.64.0.10"},
			DstIPs:    []string{"100.64.0.20"},
			Protocols: []string{"ssdp"},
		}}),
	})
	m := l2relay.NewManager(b)

	var sentTo netip.Addr
	var sentEnv l2relay.Envelope
	m.SetSendEnvelopeHook(func(dst netip.Addr, env l2relay.Envelope) {
		sentTo = dst
		sentEnv = env
	})

	ssdp := "NOTIFY * HTTP/1.1\r\nLOCATION: http://192.168.0.2:631/ipp/print\r\n\r\n"
	m.ForwardCaptured(l2relay.ProtoSSDP, []byte(ssdp), "", nil)

	if !sentTo.IsValid() || sentTo.String() != "100.64.0.20" {
		t.Fatalf("sentTo=%v, want 100.64.0.20", sentTo)
	}
	if sentEnv.Proto != l2relay.ProtoSSDP || sentEnv.Hops != 1 {
		t.Fatalf("unexpected env: %+v", sentEnv)
	}
	if string(sentEnv.Payload) == ssdp {
		t.Fatalf("expected rewritten payload, got unchanged")
	}
}
