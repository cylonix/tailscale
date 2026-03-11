// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package l2relay

import (
	"net"
	"net/netip"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

func nodeIP(n tailcfg.NodeView, pred func(netip.Addr) bool) netip.Addr {
	for _, pfx := range n.Addresses().All() {
		if pfx.IsSingleIP() && pred(pfx.Addr()) {
			return pfx.Addr()
		}
	}
	return netip.Addr{}
}

func udpAddrPort(ua *net.UDPAddr) (netip.AddrPort, bool) {
	ip, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(ua.Port)), true
}

// TODO: use a map for O(1) lookup instead of O(N) scan.
func peerNode(nm *netmap.NetworkMap, id tailcfg.NodeID) (peer tailcfg.NodeView, ok bool) {
	if nm == nil {
		return
	}
	for _, p := range nm.Peers {
		if p.ID() == id {
			return p, true
		}
	}
	return
}
