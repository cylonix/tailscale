// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

// TestXrayProtoConfigEquivalence proves the direct-proto builder produces
// byte-identical configs to the infra/conf JSON path it replaced. The conf
// import here is test-only; shipping binaries no longer link it.
func TestXrayProtoConfigEquivalence(t *testing.T) {
	pub := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	cases := []struct {
		name string
		p    xrayProtoParams
	}{
		{"basic", xrayProtoParams{
			dialAddr: "203.0.113.5", port: 443,
			clientUUID:      "8ca92dd7-01f1-42a3-a687-8a1ab4327a2b",
			serverPublicKey: pub, realityShortID: "0123456789abcdef",
			fingerprint: "chrome", realityServerName: "derp.example.com",
			xhttpHost: "derp.example.com", tunnelPath: "/tunnel",
			xhttpMode: "stream-up",
		}},
		{"hostname-dial-auto-mode", xrayProtoParams{
			dialAddr: "derp.example.com", port: 8443,
			clientUUID:      "3effe009-d6c1-46ee-8529-e9de9d76bfaf",
			serverPublicKey: pub, realityShortID: "aabb",
			fingerprint: "safari", realityServerName: "www.apple.com",
			xhttpHost: "www.apple.com", tunnelPath: "/t",
			xhttpMode: "auto",
		}},
		{"spiderx-with-params", xrayProtoParams{
			dialAddr: "198.51.100.9", port: 443,
			clientUUID:      "8ca92dd7-01f1-42a3-a687-8a1ab4327a2b",
			serverPublicKey: pub, realityShortID: "00ff",
			fingerprint: "chrome", realityServerName: "cdn.example.org",
			spiderX:   "/seek?p=100-200&c=2",
			xhttpHost: "cdn.example.org", tunnelPath: "/tunnel",
			xhttpMode: "packet-up",
		}},
		{"stream-one-empty-spider", xrayProtoParams{
			dialAddr: "2001:db8::5", port: 443,
			clientUUID:      "8ca92dd7-01f1-42a3-a687-8a1ab4327a2b",
			serverPublicKey: pub, realityShortID: "0123456789abcdef",
			fingerprint: "firefox", realityServerName: "derp.example.com",
			xhttpHost: "derp.example.com", tunnelPath: "/tunnel",
			xhttpMode: "stream-one",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildXrayCoreProtoConfig(tc.p)
			if err != nil {
				t.Fatalf("proto builder: %v", err)
			}
			want, err := confBuild(t, tc.p)
			if err != nil {
				t.Fatalf("conf builder: %v", err)
			}
			if !proto.Equal(got, want) {
				t.Errorf("configs differ\n got: %v\nwant: %v", got, want)
			}
		})
	}
}

// confBuild reproduces the original infra/conf-based construction from
// xrayConfigForNode (as of the migration) for comparison.
func confBuild(t *testing.T, p xrayProtoParams) (got interface {
	proto.Message
}, err error) {
	t.Helper()
	vlessSettings := conf.VLessOutboundConfig{
		Address:    &conf.Address{Address: xnet.ParseAddress(p.dialAddr)},
		Port:       p.port,
		Id:         p.clientUUID,
		Flow:       "",
		Encryption: "none",
	}
	settingsBytes, err := json.Marshal(&vlessSettings)
	if err != nil {
		return nil, err
	}
	settings := json.RawMessage(settingsBytes)

	transport := conf.TransportProtocol("xhttp")
	mode := p.xhttpMode
	stream := &conf.StreamConfig{
		Network:  &transport,
		Security: "reality",
		REALITYSettings: &conf.REALITYConfig{
			ServerName:  p.realityServerName,
			PublicKey:   p.serverPublicKey,
			ShortId:     p.realityShortID,
			Fingerprint: p.fingerprint,
			SpiderX:     p.spiderX,
		},
		XHTTPSettings: &conf.SplitHTTPConfig{
			Host: p.xhttpHost,
			Path: p.tunnelPath,
			Mode: mode,
		},
	}
	cfg := &conf.Config{
		LogConfig: &conf.LogConfig{LogLevel: "warning"},
		OutboundConfigs: []conf.OutboundDetourConfig{{
			Protocol:      "vless",
			Settings:      &settings,
			StreamSetting: stream,
		}},
	}
	return cfg.Build()
}
