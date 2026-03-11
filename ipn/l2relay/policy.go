// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package l2relay

import (
	"net/netip"
	"strings"

	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

var debugAllowL2RelayOpt = envknob.RegisterOptBool("TS_DEBUG_ALLOW_L2RELAY")

func debugAllowL2Relay() bool {
	if v, ok := debugAllowL2RelayOpt().Get(); ok {
		return v
	}
	return false
}

func allowed(src, dst netip.Addr, proto string, isInput bool, f *filter.Filter, rules []tailcfg.L2DiscoveryRule, logf func(format string, args ...any)) bool {
	if !src.IsValid() || !dst.IsValid() || proto == "" {
		if logf != nil {
			logf("l2relay: policy deny invalid input src=%v dst=%v proto=%q", src, dst, proto)
		}
		return false
	}
	if debugAllowL2Relay() {
		if logf != nil {
			logf("l2relay: policy allow via TS_DEBUG_ALLOW_L2RELAY src=%v dst=%v proto=%q", src, dst, proto)
		}
		return true
	}
	if f != nil {
		r := f.CheckTCPWithDir(src, dst, 53, isInput)
		if r != filter.Accept {
			if logf != nil {
				logf("l2relay: policy deny l3 gate src=%v dst=%v proto=%q filterNil=%v r=%v", src, dst, proto, f == nil, r)
			}
			return false
		}
	}
	// Treat no-rules as permit all for now. We may want to change this default in the future,
	// but it's easier to be permissive now while we're still iterating on the policy design
	// and testing it in the wild.
	if len(rules) == 0 {
		if logf != nil {
			logf("l2relay: policy allow no-rules src=%v dst=%v proto=%q", src, dst, proto)
		}
		return true
	}
	for i, r := range rules {
		if RuleMatches(r, src, dst, proto) {
			if logf != nil {
				logf("l2relay: policy allow src=%v dst=%v proto=%q rule_index=%d", src, dst, proto, i)
			}
			return true
		}
	}
	if logf != nil {
		logf("l2relay: policy deny no-match src=%v dst=%v proto=%q rules=%d", src, dst, proto, len(rules))
	}
	return false
}

func RuleMatches(r tailcfg.L2DiscoveryRule, src, dst netip.Addr, proto string) bool {
	if len(r.Protocols) > 0 {
		matchedProto := false
		for _, p := range r.Protocols {
			if strings.EqualFold(p, proto) {
				matchedProto = true
				break
			}
		}
		if !matchedProto {
			return false
		}
	}
	if len(r.SrcIPs) > 0 && !SelectorsMatchAny(r.SrcIPs, src) {
		return false
	}
	if len(r.DstIPs) > 0 && !SelectorsMatchAny(r.DstIPs, dst) {
		return false
	}
	return true
}

func SelectorsMatchAny(selectors []string, ip netip.Addr) bool {
	for _, s := range selectors {
		if SelectorMatches(s, ip) {
			return true
		}
	}
	return false
}

func SelectorMatches(selector string, ip netip.Addr) bool {
	selector = strings.TrimSpace(selector)
	switch selector {
	case "":
		return false
	case "*":
		return true
	}
	if pfx, err := netip.ParsePrefix(selector); err == nil {
		return pfx.Contains(ip)
	}
	if addr, err := netip.ParseAddr(selector); err == nil {
		return addr == ip
	}
	return false
}
