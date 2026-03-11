// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package l2relay

import (
	"net"
	"net/netip"
	"strings"

	"github.com/tailscale/netlink"
)

func DefaultGatewayMAC(gw netip.Addr) (string, bool) {
	if !gw.IsValid() {
		return "", false
	}
	family := netlink.FAMILY_V4
	if gw.Is6() {
		family = netlink.FAMILY_V6
	}
	filter := &netlink.Route{Gw: gw.AsSlice()}
	routes, err := netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_GW)
	if err != nil {
		return "", false
	}
	for _, route := range routes {
		if route.Dst != nil {
			continue
		}
		if route.Gw == nil {
			continue
		}
		if rGW, ok := netip.AddrFromSlice(route.Gw); !ok || rGW != gw {
			continue
		}
		if route.LinkIndex <= 0 {
			continue
		}
		neighs, err := netlink.NeighList(route.LinkIndex, family)
		if err != nil {
			continue
		}
		for _, neigh := range neighs {
			if neigh.IP == nil || neigh.HardwareAddr == nil {
				continue
			}
			nip, ok := netip.AddrFromSlice(neigh.IP)
			if !ok || nip != gw {
				continue
			}
			if len(neigh.HardwareAddr) == 0 {
				continue
			}
			return strings.ToLower(net.HardwareAddr(neigh.HardwareAddr).String()), true
		}
	}
	return "", false
}
