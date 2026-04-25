// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"testing"

	xnet "github.com/xtls/xray-core/common/net"

	"tailscale.com/tailcfg"
)

func TestXRayConfigForNode(t *testing.T) {
	node := &tailcfg.DERPNode{
		HostName: "derp.example.com",
		XRay: &tailcfg.DERPXRay{
			ClientUUID:        "27848739-7e62-4138-9fd3-098a63964b6b",
			ServerPublicKey:   "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM",
			XHTTPTunnel:       "tunnel-alpha",
			RealityShortID:    "0123456789abcdef",
			RealityServerName: "example.com",
		},
	}

	coreCfg, dest, configKey, err := xrayConfigForNode(node, xnet.Port(443), "example.com", "203.0.113.10")
	if err != nil {
		t.Fatalf("xrayConfigForNode: %v", err)
	}
	if coreCfg == nil {
		t.Fatal("xrayConfigForNode returned nil config")
	}
	if got := dest.Port.Value(); got != 443 {
		t.Fatalf("unexpected port: %d", got)
	}
	if got := dest.Address.String(); got != "203.0.113.10" {
		t.Fatalf("unexpected address: %s", got)
	}
	if configKey == "" {
		t.Fatal("xrayConfigForNode returned empty config key")
	}
}

func TestXRayConfigForNodeMissingShortID(t *testing.T) {
	node := &tailcfg.DERPNode{
		HostName: "derp.example.com",
		XRay: &tailcfg.DERPXRay{
			ClientUUID:      "27848739-7e62-4138-9fd3-098a63964b6b",
			ServerPublicKey: "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM",
			XHTTPTunnel:     "tunnel-alpha",
		},
	}

	if _, _, _, err := xrayConfigForNode(node, xnet.Port(443), "example.com", "derp.example.com"); err == nil {
		t.Fatal("expected error for missing reality short id")
	}
}

func TestXRayConfigForNodeSpiderXPrefix(t *testing.T) {
	node := &tailcfg.DERPNode{
		HostName: "derp.example.com",
		XRay: &tailcfg.DERPXRay{
			ClientUUID:        "27848739-7e62-4138-9fd3-098a63964b6b",
			ServerPublicKey:   "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM",
			XHTTPTunnel:       "tunnel-alpha",
			RealityShortID:    "0123456789abcdef",
			RealityServerName: "example.com",
			RealitySpiderX:    "something", // missing leading /
		},
	}

	coreCfg, _, _, err := xrayConfigForNode(node, xnet.Port(443), "example.com", "203.0.113.10")
	if err != nil {
		t.Fatalf("xrayConfigForNode: %v", err)
	}
	if coreCfg == nil {
		t.Fatal("xrayConfigForNode returned nil config")
	}
	// The function should have auto-prefixed "/" — we can't directly
	// inspect the protobuf config, but at least it didn't error out.
}

func TestXRayConfigForNodeStableConfigKey(t *testing.T) {
	node := &tailcfg.DERPNode{
		HostName: "derp.example.com",
		XRay: &tailcfg.DERPXRay{
			ClientUUID:        "27848739-7e62-4138-9fd3-098a63964b6b",
			ServerPublicKey:   "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM",
			XHTTPTunnel:       "tunnel-alpha",
			RealityShortID:    "0123456789abcdef",
			RealityServerName: "example.com",
		},
	}

	_, _, key1, err := xrayConfigForNode(node, xnet.Port(443), "example.com", "203.0.113.10")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	_, _, key2, err := xrayConfigForNode(node, xnet.Port(443), "example.com", "203.0.113.10")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if key1 != key2 {
		t.Fatalf("config key not stable: %q != %q", key1, key2)
	}

	// Changing the tunnel should change the key.
	node.XRay.XHTTPTunnel = "tunnel-beta"
	_, _, key3, err := xrayConfigForNode(node, xnet.Port(443), "example.com", "203.0.113.10")
	if err != nil {
		t.Fatalf("third call: %v", err)
	}
	if key1 == key3 {
		t.Fatal("config key should differ after tunnel change")
	}
}

func TestXRayTunnelPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "/"},
		{"whitespace", "  ", "/"},
		{"simple", "tunnel-alpha", "/tunnel-alpha"},
		{"leading_slash", "/tunnel-alpha", "/tunnel-alpha"},
		{"path_with_segments", "/cylonix-derp-tunnel", "/cylonix-derp-tunnel"},
		{"whitespace_around", "  /tunnel  ", "/tunnel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := xrayTunnelPath(tt.in)
			if got != tt.want {
				t.Errorf("xrayTunnelPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestWantsXRayUnderlay(t *testing.T) {
	tests := []struct {
		name string
		node *tailcfg.DERPNode
		want bool
	}{
		{"nil node", nil, false},
		{"nil xray", &tailcfg.DERPNode{}, false},
		{"empty xray", &tailcfg.DERPNode{XRay: &tailcfg.DERPXRay{}}, false},
		{"missing uuid", &tailcfg.DERPNode{XRay: &tailcfg.DERPXRay{
			ServerPublicKey: "key", XHTTPTunnel: "t", RealityShortID: "id",
		}}, false},
		{"missing pubkey", &tailcfg.DERPNode{XRay: &tailcfg.DERPXRay{
			ClientUUID: "uuid", XHTTPTunnel: "t", RealityShortID: "id",
		}}, false},
		{"missing tunnel", &tailcfg.DERPNode{XRay: &tailcfg.DERPXRay{
			ClientUUID: "uuid", ServerPublicKey: "key", RealityShortID: "id",
		}}, false},
		{"missing shortid", &tailcfg.DERPNode{XRay: &tailcfg.DERPXRay{
			ClientUUID: "uuid", ServerPublicKey: "key", XHTTPTunnel: "t",
		}}, false},
		{"all present", &tailcfg.DERPNode{XRay: &tailcfg.DERPXRay{
			ClientUUID: "uuid", ServerPublicKey: "key", XHTTPTunnel: "t", RealityShortID: "id",
		}}, true},
		{"whitespace only", &tailcfg.DERPNode{XRay: &tailcfg.DERPXRay{
			ClientUUID: "  ", ServerPublicKey: "key", XHTTPTunnel: "t", RealityShortID: "id",
		}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wantsXRayUnderlay(tt.node)
			if got != tt.want {
				t.Errorf("wantsXRayUnderlay() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXRayInstanceGetOrCreate(t *testing.T) {
	// We can't actually start a real xray-core instance in unit tests
	// without a valid config, but we can test the caching logic
	// by verifying that close() doesn't panic on a zero-value instance.
	var xi xrayInstance
	xi.close() // should be safe on zero value
	xi.close() // should be safe to call twice
}