// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package l2relay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

var ErrInternalErr = errors.New("internal error")

func isAllowedRelayProxyPort(port int) bool {
	switch port {
	case 139, 443, 445, 5000, 5001, 515, 631, 9100:
		return true
	default:
		return false
	}
}

func isLikelyLANTarget(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	return false
}

func proxyTCP(m *l2RelayManager, from tailcfg.NodeView, target string, fromAddr, selfAddr netip.Addr, w http.ResponseWriter) error {
	logf := m.logf
	if target == "" {
		m.limitedLogf("l2relay: proxy deny missing-target from=%d", from.Name())
		return errors.New("missing proxy target")
	}
	logf("l2relay: proxy request from=%d target=%q", from.Name(), target)
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		logf("l2relay: proxy deny bad-target from=%d target=%q err=%v", from.Name(), target, err)
		return errors.New("invalid target host:port")
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		logf("l2relay: proxy deny bad-port from=%d target=%q", from.Name(), target)
		return errors.New("invalid target port")
	}
	if !isAllowedRelayProxyPort(port) {
		logf("l2relay: proxy deny blocked-port from=%d target=%q", from.Name(), target)
		return errors.New("target port denied")
	}
	targetIP, err := netip.ParseAddr(host)
	if err == nil {
		if !isLikelyLANTarget(targetIP) {
			logf("l2relay: proxy deny non-lan-ip from=%d ip=%q", from.Name(), targetIP.String())
			return errors.New("target IP denied")
		}
	} else if !strings.HasSuffix(strings.ToLower(strings.TrimSpace(host)), ".local") {
		logf("l2relay: proxy deny non-local-host from=%d host=%q", from.Name(), host)
		return errors.New("target host denied")
	}

	if m.l2DiscoveryAllowed(fromAddr, selfAddr, "ipp-proxy", true) {
		m.limitedLogf("l2relay: proxy deny policy from=%d src=%q self_dst=%q", from.Name(), fromAddr, selfAddr)
		return errors.New("policy denied")
	}

	upstreamHost := host
	if targetIP.IsValid() {
		upstreamHost = targetIP.String()
	}
	logf("l2relay: proxy dialing from=%d upstream=%q", from.Name(), target)
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(upstreamHost, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		logf("l2relay: proxy dial failed from=%d upstream=%q err=%v", from.Name(), target, err)
		return fmt.Errorf("%w: upstream dial failed", ErrInternalErr)
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		logf("l2relay: proxy hijack unsupported from=%d", from.Name())
		return fmt.Errorf("%w: hijack unsupported", ErrInternalErr)
	}
	downstream, _, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		logf("l2relay: proxy hijack failed from=%d err=%v", from.Name(), err)
		return fmt.Errorf("%w: hijack failed", ErrInternalErr)
	}
	logf("l2relay: proxy connected from=%d target=%q", from.Name(), target)
	_, _ = io.WriteString(downstream, "HTTP/1.1 101 Switching Protocols\r\n\r\n")

	go func() {
		defer downstream.Close()
		defer upstream.Close()
		n, err := io.Copy(upstream, downstream)
		logf("l2relay: proxy downstream->upstream done from=%d bytes=%d err=%v", from.Name(), n, err)
	}()
	go func() {
		defer downstream.Close()
		defer upstream.Close()
		n, err := io.Copy(downstream, upstream)
		logf("l2relay: proxy upstream->downstream done from=%d bytes=%d err=%v", from.Name(), n, err)
	}()
	return nil
}

func handleHello(m *l2RelayManager, from tailcfg.NodeView, msg Hello) {
	m.recordHello(from, msg)
}

func handleLeader(m *l2RelayManager, from tailcfg.NodeView, msg Leader) error {
	return m.recordLeader(from, msg)
}

func handleEnvelope(m *l2RelayManager, src netip.AddrPort, selfAddr netip.Addr, raw []byte) error {
	return m.handleIncomingEnvelope(src, selfAddr, raw)
}
