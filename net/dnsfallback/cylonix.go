// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Cylonix extensions to the dnsfallback package. When the system resolver is
// broken (e.g. DNS poisoning under the Great Firewall) and no cached DERP map
// is available yet, the generic DERP bootstrap path can still fail because
// upstream Tailscale DERPs will not resolve the Cylonix controller hostname.
//
// This file provides two extra resolution tiers scoped to Cylonix:
//
//  1. A hardcoded IP table for known controller hostnames, baked into the
//     binary. This serves as a last-resort, always-available answer similar
//     to what Roblox does for its client bootstrapping.
//
//  2. A separate embedded DERP list (cylonix-dns-fallback-servers.json) that
//     is merged into the static DERP map returned by GetDERPMap. Cylonix DERP
//     deployments must be started with
//     -bootstrap-dns-names=manage.cylonix.io so that /bootstrap-dns on those
//     DERPs can resolve the controller hostname for future refreshes.

package dnsfallback

import (
	_ "embed"
	"encoding/json"
	"net/netip"

	"tailscale.com/tailcfg"
)

// cylonixControllerIPs is the last-resort IP list for Cylonix controller
// hostnames, consulted before the DERP bootstrap path. The embedded values
// should be refreshed periodically via the release process. Control-plane
// responses update the DERP cache at runtime, which is a better source of
// truth once reachable, but this static list is what bootstraps a brand-new
// install when system DNS is poisoned.
var cylonixControllerIPs = map[string][]netip.Addr{
	"manage.cylonix.io": {
		// Cloudflare front for manage.cylonix.io. Cloudflare anycast
		// addresses are durable; any of these IPs will reach the origin
		// via CF's edge network.
		netip.MustParseAddr("104.21.30.15"),
		netip.MustParseAddr("172.67.150.51"),
		netip.MustParseAddr("2606:4700:3032::6815:1e0f"),
		netip.MustParseAddr("2606:4700:3037::ac43:9633"),
	},
}

// cylonixStaticLookup returns hardcoded fallback IPs for well-known Cylonix
// controller hostnames and ok=true if present. Callers should treat the
// returned slice as read-only.
func cylonixStaticLookup(host string) (addrs []netip.Addr, ok bool) {
	ips, ok := cylonixControllerIPs[host]
	return ips, ok
}

//go:embed cylonix-dns-fallback-servers.json
var cylonixDERPMapJSON []byte

// getCylonixDERPMap returns the Cylonix-specific static DERP map, or nil if
// the embedded JSON contains no regions. These DERPs are merged into the
// upstream static DERP map by mergeCylonixDERPs below.
func getCylonixDERPMap() *tailcfg.DERPMap {
	dm := new(tailcfg.DERPMap)
	if err := json.Unmarshal(cylonixDERPMapJSON, dm); err != nil {
		return nil
	}
	if len(dm.Regions) == 0 {
		return nil
	}
	return dm
}

// mergeCylonixDERPs merges the Cylonix-specific DERP regions into dm. Region
// IDs in the Cylonix JSON should not collide with upstream Tailscale region
// IDs; conflicts are resolved by appending Cylonix nodes into the existing
// region.
func mergeCylonixDERPs(dm *tailcfg.DERPMap) {
	cyl := getCylonixDERPMap()
	if cyl == nil || dm == nil {
		return
	}
	if dm.Regions == nil {
		dm.Regions = map[int]*tailcfg.DERPRegion{}
	}
	for id, region := range cyl.Regions {
		existing, ok := dm.Regions[id]
		if !ok {
			dm.Regions[id] = region
			continue
		}
		seen := make(map[string]bool, len(existing.Nodes))
		for _, n := range existing.Nodes {
			seen[n.HostName] = true
		}
		for _, n := range region.Nodes {
			if !seen[n.HostName] {
				existing.Nodes = append(existing.Nodes, n)
			}
		}
	}
}
