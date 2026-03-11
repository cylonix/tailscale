// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package l2relay

import (
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
)

func TestL2SelectorMatches(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.20")
	tests := []struct {
		selector string
		want     bool
	}{
		{"*", true},
		{"192.168.1.20", true},
		{"192.168.1.0/24", true},
		{"192.168.2.0/24", false},
		{"192.168.1.21", false},
		{"bad", false},
	}
	for _, tt := range tests {
		if got := SelectorMatches(tt.selector, ip); got != tt.want {
			t.Fatalf("SelectorMatches(%q, %v)=%v, want %v", tt.selector, ip, got, tt.want)
		}
	}
}

func TestL2RuleMatches(t *testing.T) {
	src := netip.MustParseAddr("100.64.0.10")
	dst := netip.MustParseAddr("100.64.0.20")
	rule := tailcfg.L2DiscoveryRule{
		SrcIPs:    []string{"100.64.0.0/10"},
		DstIPs:    []string{"100.64.0.20"},
		Protocols: []string{"mdns", "ssdp"},
	}
	if !RuleMatches(rule, src, dst, "mDNS") {
		t.Fatal("expected protocol/cidr/ip match")
	}
	if RuleMatches(rule, src, dst, "minecraft") {
		t.Fatal("unexpected protocol match")
	}
	if RuleMatches(rule, netip.MustParseAddr("101.0.0.1"), dst, "mdns") {
		t.Fatal("unexpected source match")
	}
}
