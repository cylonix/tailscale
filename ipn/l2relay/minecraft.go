// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package l2relay

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// parseMinecraftAD extracts the TCP port from [AD]port[/AD] in a Minecraft
// Java Edition LAN discovery announcement.
func parseMinecraftAD(payload []byte) (uint16, bool) {
	const open, close = "[AD]", "[/AD]"
	s := string(payload)
	i := strings.Index(s, open)
	if i < 0 {
		return 0, false
	}
	i += len(open)
	j := strings.Index(s[i:], close)
	if j < 0 {
		return 0, false
	}
	p, err := strconv.ParseUint(strings.TrimSpace(s[i:i+j]), 10, 16)
	if err != nil || p == 0 || p > 65535 {
		return 0, false
	}
	return uint16(p), true
}

// rewriteMinecraftAD rewrites [AD]port[/AD] in a Minecraft LAN discovery
// announcement to newPort. Returns the modified payload and whether a change
// was made.
func rewriteMinecraftAD(payload []byte, newPort uint16) ([]byte, bool) {
	const open, close = "[AD]", "[/AD]"
	s := string(payload)
	i := strings.Index(s, open)
	if i < 0 {
		return payload, false
	}
	start := i + len(open)
	j := strings.Index(s[start:], close)
	if j < 0 {
		return payload, false
	}
	end := start + j
	oldPort := strings.TrimSpace(s[start:end])
	newPortStr := strconv.Itoa(int(newPort))
	if oldPort == newPortStr {
		return payload, false
	}
	return []byte(s[:start] + newPortStr + s[end:]), true
}

// injectMinecraftWithProxy handles a Minecraft envelope whose origin node has
// Cylonix installed (MinecraftServerPort > 0). It ensures a TCP proxy exists
// forwarding to the origin's Tailscale IP:server_port, rewrites the [AD]port[/AD]
// in the announcement to the proxy port, and injects the multicast.
func (m *l2RelayManager) injectMinecraftWithProxy(_ netip.AddrPort, env *l2RelayEnvelope) {
	nm := m.b.NetMap()
	if nm == nil {
		m.logf("[v1] l2relay: minecraft proxy skip no netmap")
		return
	}
	peer, ok := peerNode(nm, env.OriginNodeID)
	if !ok || !peer.Valid() {
		m.logf("[v1] l2relay: minecraft proxy skip origin peer not found id=%d", env.OriginNodeID)
		return
	}
	originIP := nodeIP(peer, netip.Addr.Is4)
	if !originIP.IsValid() {
		m.logf("[v1] l2relay: minecraft proxy skip origin no tailscale IPv4 id=%d", env.OriginNodeID)
		return
	}

	serverPort := env.MinecraftServerPort
	targetAddr := net.JoinHostPort(originIP.String(), strconv.Itoa(int(serverPort)))
	proxyKey := fmt.Sprintf("%d:%d", env.OriginNodeID, serverPort)

	proxyPort, ok := m.getOrCreateMinecraftProxy(proxyKey, targetAddr)
	if !ok {
		m.logf("[v1] l2relay: minecraft proxy setup failed target=%s", targetAddr)
		// Fall back to injecting as-is.
		m.injectToLocalDiscovery(l2ProtoMinecraft, env.Payload)
		return
	}

	rewritten, changed := rewriteMinecraftAD(env.Payload, proxyPort)
	if !changed {
		m.logf("[v1] l2relay: minecraft proxy port rewrite failed proxy_port=%d", proxyPort)
		m.injectToLocalDiscovery(l2ProtoMinecraft, env.Payload)
		return
	}

	payloadSig := relayRawSig(env.Payload)
	m.limitedLogf("[v1] l2relay: minecraft proxy inject origin=%d target=%s proxy_port=%d sig=%s", env.OriginNodeID, targetAddr, proxyPort, payloadSig)
	m.injectToLocalDiscovery(l2ProtoMinecraft, rewritten)
}

// getOrCreateMinecraftProxy returns the local proxy port for proxyKey, creating
// a new proxy to targetAddr if none exists. It also expires proxies that have
// not seen an announcement in the last 60 seconds.
func (m *l2RelayManager) getOrCreateMinecraftProxy(proxyKey, targetAddr string) (uint16, bool) {
	lockedAt := m.lockRelayMu("getOrCreateMinecraftProxy")
	now := time.Now()
	// Expire stale proxies.
	for k, p := range m.mcProxies {
		if now.Sub(p.lastSeen) > 60*time.Second {
			p.cancel()
			delete(m.mcProxies, k)
		}
	}
	if p, ok := m.mcProxies[proxyKey]; ok {
		p.lastSeen = now
		port := p.localPort
		m.unlockRelayMu("getOrCreateMinecraftProxy", lockedAt)
		return port, true
	}
	m.unlockRelayMu("getOrCreateMinecraftProxy", lockedAt)

	// Create new proxy outside the lock.
	p, err := m.startMinecraftProxy(targetAddr)
	if err != nil {
		m.logf("[v1] l2relay: minecraft proxy start failed target=%s err=%v", targetAddr, err)
		return 0, false
	}
	p.lastSeen = now

	lockedAt = m.lockRelayMu("getOrCreateMinecraftProxy-store")
	m.mcProxies[proxyKey] = p
	m.unlockRelayMu("getOrCreateMinecraftProxy-store", lockedAt)
	return p.localPort, true
}

// startMinecraftProxy starts a TCP listener that forwards connections to
// targetAddr. The listener runs until the returned cancel func is called.
func (m *l2RelayManager) startMinecraftProxy(targetAddr string) (*minecraftProxy, error) {
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	done := make(chan struct{})
	cancel := func() {
		ln.Close()
		<-done
	}
	go func() {
		defer close(done)
		defer ln.Close()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.minecraftProxyConn(c, targetAddr)
		}
	}()
	return &minecraftProxy{localPort: port, cancel: cancel}, nil
}

// minecraftProxyConn bidirectionally copies between client and a fresh
// connection to targetAddr.
func (m *l2RelayManager) minecraftProxyConn(client net.Conn, targetAddr string) {
	defer client.Close()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	upstream, err := dialer.Dial("tcp4", targetAddr)
	if err != nil {
		m.logf("[v1] l2relay: minecraft proxy conn dial target=%q err=%v", targetAddr, err)
		return
	}
	defer upstream.Close()
	m.logf("[v2] l2relay: minecraft proxy conn client=%v target=%q", client.RemoteAddr(), targetAddr)
	errc := make(chan error, 2)
	go func() { _, err := io.Copy(upstream, client); errc <- err }()
	go func() { _, err := io.Copy(client, upstream); errc <- err }()
	<-errc
}
