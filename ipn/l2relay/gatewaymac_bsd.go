// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || freebsd

package l2relay

import (
	"net/netip"
	"strings"

	"tailscale.com/net/routetable"
)

func DefaultGatewayMAC(gw netip.Addr) (string, bool) {
	if !gw.IsValid() {
		return "", false
	}
	routes, err := routetable.Get(1024)
	if err != nil {
		return "", false
	}
	defaultIface := ""
	for _, re := range routes {
		if !re.Dst.IsValid() {
			continue
		}
		dst := re.Dst.Prefix
		if dst.Bits() != 0 {
			continue
		}
		if dst.Addr().Is4() != gw.Is4() {
			continue
		}
		if re.Gateway == gw {
			if sys, ok := re.Sys.(routetable.RouteEntryBSD); ok && sys.GatewayAddr != "" {
				return strings.ToLower(sys.GatewayAddr), true
			}
			defaultIface = re.Interface
			break
		}
	}
	if defaultIface == "" {
		return "", false
	}
	for _, re := range routes {
		if re.Interface != defaultIface {
			continue
		}
		if !re.Dst.IsValid() {
			continue
		}
		dst := re.Dst.Prefix
		if dst.Bits() != dst.Addr().BitLen() {
			continue
		}
		if dst.Addr() != gw {
			continue
		}
		sys, ok := re.Sys.(routetable.RouteEntryBSD)
		if !ok || sys.GatewayAddr == "" {
			continue
		}
		return strings.ToLower(sys.GatewayAddr), true
	}
	return "", false
}
