// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

// This file builds the xray-core configuration protobufs directly,
// replicating exactly what the infra/conf JSON layer produced for the
// VLESS+REALITY+XHTTP DERP underlay. The infra/conf package transitively
// imports the config types of every xray protocol (hysteria, kcp, vmess,
// trojan, ...), each of which registers protobuf descriptors at init and
// inflates the resident baseline of the iOS network extension, which runs
// under a ~50MB jetsam limit. Building the protos directly keeps only the
// components the underlay actually uses in the binary.
//
// Equivalence with the conf-based construction is enforced by
// TestXrayProtoConfigEquivalence, which compares this builder's output
// against conf.Build() for a matrix of inputs (the conf import there is
// test-only and does not ship).

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/app/dispatcher"
	xlog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	clog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	cserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/vless"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

// xrayProtoParams carries the already-defaulted values computed by
// xrayConfigForNode (fingerprint, server name, spiderX prefixing, etc.).
type xrayProtoParams struct {
	dialAddr          string
	port              uint16
	clientUUID        string
	serverPublicKey   string // base64.RawURLEncoding, 32 bytes
	realityShortID    string // hex, up to 16 chars
	fingerprint       string
	realityServerName string
	spiderX           string // empty or absolute path
	xhttpHost         string
	tunnelPath        string
	xhttpMode         string // "", auto, packet-up, stream-up, stream-one
}

// buildXrayCoreProtoConfig mirrors conf.Config.Build() for the fixed
// config shape used by the DERP underlay: LogConfig{warning} plus a
// single VLESS outbound with REALITY security over XHTTP transport.
func buildXrayCoreProtoConfig(p xrayProtoParams) (*core.Config, error) {
	vlessCfg, err := buildVlessOutbound(p)
	if err != nil {
		return nil, err
	}
	realityCfg, err := buildRealityConfig(p)
	if err != nil {
		return nil, err
	}
	shttpCfg, err := buildSplitHTTPConfig(p)
	if err != nil {
		return nil, err
	}

	realityTM := cserial.ToTypedMessage(realityCfg)
	stream := &internet.StreamConfig{
		ProtocolName: "splithttp",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "splithttp",
			Settings:     cserial.ToTypedMessage(shttpCfg),
		}},
		SecurityType:     realityTM.Type,
		SecuritySettings: []*cserial.TypedMessage{realityTM},
	}
	sender := &proxyman.SenderConfig{StreamSettings: stream}

	// App order matches conf.Config.Build: the logger goes first so other
	// modules can log during startup.
	logCfg := &xlog.Config{
		ErrorLogType:  xlog.LogType_Console,
		ErrorLogLevel: clog.Severity_Warning,
		AccessLogType: xlog.LogType_Console,
	}
	return &core.Config{
		App: []*cserial.TypedMessage{
			cserial.ToTypedMessage(logCfg),
			cserial.ToTypedMessage(&dispatcher.Config{}),
			cserial.ToTypedMessage(&proxyman.InboundConfig{}),
			cserial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{{
			SenderSettings: cserial.ToTypedMessage(sender),
			ProxySettings:  cserial.ToTypedMessage(vlessCfg),
		}},
	}, nil
}

// buildVlessOutbound mirrors conf.VLessOutboundConfig.Build for a single
// vnext endpoint with one user, empty flow, encryption "none".
func buildVlessOutbound(p xrayProtoParams) (*vlessout.Config, error) {
	u, err := uuid.ParseString(p.clientUUID)
	if err != nil {
		return nil, err
	}
	account := &vless.Account{
		Id:         u.String(),
		Encryption: "none",
	}
	return &vlessout.Config{
		Vnext: &protocol.ServerEndpoint{
			Address: xnet.NewIPOrDomain(xnet.ParseAddress(p.dialAddr)),
			Port:    uint32(p.port),
			User: &protocol.User{
				Account: cserial.ToTypedMessage(account),
			},
		},
	}, nil
}

// buildRealityConfig mirrors the client branch of conf.REALITYConfig.Build.
func buildRealityConfig(p xrayProtoParams) (*reality.Config, error) {
	cfg := new(reality.Config)
	cfg.Fingerprint = strings.ToLower(p.fingerprint)
	if cfg.Fingerprint == "unsafe" || cfg.Fingerprint == "hellogolang" {
		return nil, errors.New(`invalid "fingerprint": ` + cfg.Fingerprint)
	}
	if xtls.GetFingerprint(cfg.Fingerprint) == nil {
		return nil, errors.New(`unknown "fingerprint": ` + cfg.Fingerprint)
	}
	if p.serverPublicKey == "" {
		return nil, errors.New(`empty "password"`)
	}
	pub, err := base64.RawURLEncoding.DecodeString(p.serverPublicKey)
	if err != nil || len(pub) != 32 {
		return nil, errors.New(`invalid "password": ` + p.serverPublicKey)
	}
	cfg.PublicKey = pub
	if len(p.realityShortID) > 16 {
		return nil, errors.New(`too long "shortId": ` + p.realityShortID)
	}
	cfg.ShortId = make([]byte, 8)
	if _, err := hex.Decode(cfg.ShortId, []byte(p.realityShortID)); err != nil {
		return nil, errors.New(`invalid "shortId": ` + p.realityShortID)
	}
	spiderX := p.spiderX
	if spiderX == "" {
		spiderX = "/"
	}
	if spiderX[0] != '/' {
		return nil, errors.New(`invalid "spiderX": ` + spiderX)
	}
	cfg.SpiderY = make([]int64, 10)
	u, _ := url.Parse(spiderX)
	q := u.Query()
	parse := func(param string, index int) {
		if q.Get(param) != "" {
			s := strings.Split(q.Get(param), "-")
			if len(s) == 1 {
				cfg.SpiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
				cfg.SpiderY[index+1], _ = strconv.ParseInt(s[0], 10, 64)
			} else {
				cfg.SpiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
				cfg.SpiderY[index+1], _ = strconv.ParseInt(s[1], 10, 64)
			}
		}
		q.Del(param)
	}
	parse("p", 0) // padding
	parse("c", 2) // concurrency
	parse("t", 4) // times
	parse("i", 6) // interval
	parse("r", 8) // return
	u.RawQuery = q.Encode()
	cfg.SpiderX = u.String()
	cfg.ServerName = p.realityServerName
	return cfg, nil
}

// buildSplitHTTPConfig mirrors conf.SplitHTTPConfig.Build for a config
// that only sets Host, Path, and Mode; every other field takes the
// documented defaults for that shape.
func buildSplitHTTPConfig(p xrayProtoParams) (*splithttp.Config, error) {
	mode := p.xhttpMode
	switch mode {
	case "":
		mode = "auto"
	case "auto", "packet-up", "stream-up", "stream-one":
	default:
		return nil, errors.New("unsupported mode: " + mode)
	}
	return &splithttp.Config{
		Host:                 p.xhttpHost,
		Path:                 p.tunnelPath,
		Mode:                 mode,
		XPaddingBytes:        &splithttp.RangeConfig{},
		XPaddingKey:          "x_padding",
		XPaddingHeader:       "X-Padding",
		XPaddingPlacement:    "queryInHeader",
		XPaddingMethod:       "repeat-x",
		UplinkHTTPMethod:     "POST",
		SessionPlacement:     "path",
		SeqPlacement:         "path",
		UplinkDataPlacement:  "body",
		ScMaxEachPostBytes:   &splithttp.RangeConfig{},
		ScMinPostsIntervalMs: &splithttp.RangeConfig{},
		ScStreamUpServerSecs: &splithttp.RangeConfig{},
		Xmux: &splithttp.XmuxConfig{
			MaxConcurrency:   &splithttp.RangeConfig{From: 1, To: 1},
			MaxConnections:   &splithttp.RangeConfig{},
			CMaxReuseTimes:   &splithttp.RangeConfig{},
			HMaxRequestTimes: &splithttp.RangeConfig{From: 600, To: 900},
			HMaxReusableSecs: &splithttp.RangeConfig{From: 1800, To: 3000},
		},
	}, nil
}
