package l2relay

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var relayInterestedWSDTokens = []string{
	"printer",
	"print",
	"smb",
	"pub:computer",
	"storage",
	"fileserver",
	"networkshare",
}

func isWSDQueryLike(lower []byte) bool {
	return bytes.Contains(lower, []byte("<d:probe")) ||
		bytes.Contains(lower, []byte("<probe")) ||
		bytes.Contains(lower, []byte(":probe")) ||
		bytes.Contains(lower, []byte("/probe\"")) ||
		bytes.Contains(lower, []byte("/discovery/probe")) ||
		bytes.Contains(lower, []byte("<d:resolve")) ||
		bytes.Contains(lower, []byte("<resolve")) ||
		bytes.Contains(lower, []byte(":resolve")) ||
		bytes.Contains(lower, []byte("/resolve\"")) ||
		bytes.Contains(lower, []byte("/discovery/resolve"))
}

func summarizeWSDPacket(payload []byte) (summary string, interested bool, ok bool) {
	if len(payload) == 0 {
		return "", false, false
	}
	lower := bytes.ToLower(payload)
	action := "unknown"
	queryLike := false
	responseLike := false
	switch {
	case bytes.Contains(lower, []byte("probematches")):
		action = "ProbeMatches"
		responseLike = true
	case bytes.Contains(lower, []byte("resolvematches")):
		action = "ResolveMatches"
		responseLike = true
	case bytes.Contains(lower, []byte("<d:probe")) || bytes.Contains(lower, []byte("<probe")) || bytes.Contains(lower, []byte(":probe")) || bytes.Contains(lower, []byte("/probe\"")) || bytes.Contains(lower, []byte("/discovery/probe")):
		action = "Probe"
		queryLike = true
	case bytes.Contains(lower, []byte("<d:resolve")) || bytes.Contains(lower, []byte("<resolve")) || bytes.Contains(lower, []byte(":resolve")) || bytes.Contains(lower, []byte("/resolve\"")) || bytes.Contains(lower, []byte("/discovery/resolve")):
		action = "Resolve"
		queryLike = true
	case bytes.Contains(lower, []byte("hello")):
		action = "Hello"
	case bytes.Contains(lower, []byte("bye")):
		action = "Bye"
	}
	interested = queryLike
	if !interested {
		interested = containsAnyBytesToken(lower, relayInterestedWSDTokens)
	}
	summary = fmt.Sprintf("action=%s query=%v response=%v contains_printer=%v contains_smb=%v contains_storage=%v", action, queryLike, responseLike, bytes.Contains(lower, []byte("printer")), bytes.Contains(lower, []byte("smb")) || bytes.Contains(lower, []byte("pub:computer")), bytes.Contains(lower, []byte("storage")) || bytes.Contains(lower, []byte("networkshare")))
	return summary, interested, true
}

func containsAnyBytesToken(b []byte, tokens []string) bool {
	for _, tok := range tokens {
		if bytes.Contains(b, []byte(strings.ToLower(tok))) {
			return true
		}
	}
	return false
}

func isWSDQueryShaped(payload []byte) bool {
	_, _, ok := summarizeWSDPacket(payload)
	if !ok {
		return false
	}
	lower := bytes.ToLower(payload)
	if bytes.Contains(lower, []byte("probematches")) || bytes.Contains(lower, []byte("resolvematches")) {
		return false
	}
	return isWSDQueryLike(lower)
}

func isWSDResponse(payload []byte) bool {
	lower := bytes.ToLower(payload)
	return bytes.Contains(lower, []byte("probematches")) || bytes.Contains(lower, []byte("resolvematches"))
}

func isWSDAnnounce(payload []byte) bool {
	lower := bytes.ToLower(payload)
	return bytes.Contains(lower, []byte("hello")) || bytes.Contains(lower, []byte("bye"))
}

func (m *l2RelayManager) injectIncomingWSDQueryWithPAT(src netip.AddrPort, env *l2RelayEnvelope) bool {
	if env == nil || env.OriginNodeID == 0 || len(env.Payload) == 0 || env.WSDQueryKey == "" {
		return false
	}
	ra, err := net.ResolveUDPAddr("udp4", "239.255.255.250:3702")
	if err != nil {
		m.logf("[v1] l2relay: wsd pat resolve error err=%v", err)
		return false
	}
	c, err := net.ListenPacket("udp4", "")
	if err != nil {
		m.logf("[v1] l2relay: wsd pat listen error origin=%d/%s seq=%d err=%v", env.OriginNodeID, env.OriginBootID, env.Seq, err)
		return false
	}
	defer c.Close()
	if _, err := c.WriteTo(env.Payload, ra); err != nil {
		m.logf("[v1] l2relay: wsd pat inject write error local=%v dst=%v origin=%d/%s seq=%d err=%v", c.LocalAddr(), ra, env.OriginNodeID, env.OriginBootID, env.Seq, err)
		return false
	}
	// Record (sig, local IP, local port) after the successful send so that
	// the capture loop can suppress the bounce-back by exact address match.
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if ap, ok := udpAddrPort(ua); ok {
			m.noteInjectedPayload(l2ProtoWSD, env.Payload, ap)
		}
	}
	querySig := relayRawSig(env.Payload)
	m.limitedLogf("[v1] l2relay: wsd pat inject query local=%v dst=%v origin=%d/%s seq=%d query_key=%s query_sig=%s", c.LocalAddr(), ra, env.OriginNodeID, env.OriginBootID, env.Seq, env.WSDQueryKey, querySig)
	m.readWSDPATReplies(c, src, env)
	return true
}

func (m *l2RelayManager) readWSDPATReplies(c net.PacketConn, src netip.AddrPort, req *l2RelayEnvelope) {
	if c == nil || req == nil {
		return
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	buf := make([]byte, l2RelayMaxSize)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			m.logf("[v1] l2relay: wsd pat read error origin=%d/%s req_seq=%d err=%v", req.OriginNodeID, req.OriginBootID, req.Seq, err)
			return
		}
		if n <= 0 {
			continue
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok || ua == nil {
			continue
		}
		if !m.allowCapturedSourceIP(ua.IP) {
			continue
		}
		raw := slices.Clone(buf[:n])
		if !isWSDResponse(raw) {
			continue
		}
		replySrc, ok := udpAddrPort(ua)
		if !ok {
			continue
		}
		if summary, interested := summarizeDiscoveryPayload(l2ProtoWSD, raw); summary != "" && interested && m.shouldLogSummarySig(relayRawSig(raw)) {
			m.limitedLogf("[v1] l2relay: wsd pat reply summary src=%v req_query_key=%s reply_sig=%s %s", replySrc, req.WSDQueryKey, relayRawSig(raw), summary)
		}
		m.forwardWSDPATReplyToOrigin(replySrc, req, raw)
	}
}

func (m *l2RelayManager) forwardWSDPATReplyToOrigin(src netip.AddrPort, req *l2RelayEnvelope, payload []byte) {
	if req == nil || req.OriginNodeID == 0 || len(payload) == 0 || req.WSDQueryKey == "" {
		return
	}
	nm := m.b.NetMap()
	if nm == nil || !nm.SelfNode.Valid() {
		return
	}
	replySrcIP := src.Addr().Unmap()
	if debugRewriteMDNSSelfAddress() && replySrcIP.Is4() {
		if selfLANIP, ok := m.selfLANIPv4ForRelay(); ok && selfLANIP == replySrcIP {
			if selfName := strings.TrimSuffix(nm.SelfNode.Name(), "."); selfName != "" {
				forcePort := uint16(0)
				if debugL2RelayWSDHTTPProxyRewrite() {
					forcePort = l2RelayWSDProxyPort
				}
				if rewritten, changed := rewriteWSDResponseXAddrs(payload, selfName, forcePort); changed {
					m.limitedLogf("[v1] l2relay: wsd pat reply xaddr rewrite src_peer=%v req_query_key=%s host=%q force_port=%d payload_sig=%s", src, req.WSDQueryKey, selfName, forcePort, relayRawSig(rewritten))
					payload = rewritten
				}
			}
			if selfTailIP, tailOK := m.selfTailscaleIP(); tailOK {
				selfTailIP = selfTailIP.Unmap()
				if selfTailIP.Is4() {
					if rewritten, changed := rewriteWSDResponseIPv4Address(payload, replySrcIP, selfTailIP); changed {
						m.limitedLogf("[v1] l2relay: wsd pat reply self-address rewrite src_peer=%v req_query_key=%s from=%v to=%v payload_sig=%s", src, req.WSDQueryKey, replySrcIP, selfTailIP, relayRawSig(rewritten))
						payload = rewritten
					}
				}
			}
		}
	}
	selfIP, ok := m.selfTailscaleIP()
	if !ok {
		return
	}
	peer, ok := peerNode(nm, req.OriginNodeID)
	if !ok || !peer.Valid() {
		m.logf("[v1] l2relay: wsd pat drop reply no origin peer=%d sig=%s", req.OriginNodeID, relayRawSig(payload))
		return
	}
	if !peer.Online().Get() {
		m.logf("[v2] l2relay: wsd pat drop reply origin peer offline=%d sig=%s", req.OriginNodeID, relayRawSig(payload))
		return
	}
	dstIP := nodeIP(peer, netip.Addr.Is4)
	if !dstIP.IsValid() {
		m.logf("[v1] l2relay: wsd pat drop reply origin peer no valid IP=%d sig=%s", req.OriginNodeID, relayRawSig(payload))
		return
	}
	if !m.l2DiscoveryAllowed(selfIP, dstIP, string(l2ProtoWSD), false) {
		m.limitedLogf("[v1] l2relay: wsd pat drop reply policy deny src=%v dst=%v", selfIP, dstIP)
		return
	}
	env := l2RelayEnvelope{
		OriginNodeID: nm.SelfNode.ID(),
		OriginBootID: m.bootID,
		Seq:          m.seq.Add(1),
		Proto:        l2ProtoWSD,
		Hops:         1,
		WSDQueryKey:  req.WSDQueryKey,
		Payload:      payload,
	}
	m.limitedLogf("[v1] l2relay: wsd pat forward reply origin_peer=%d dst=%v req_origin=%d/%s req_seq=%d req_query_key=%s src_peer=%v reply_sig=%s", req.OriginNodeID, dstIP, req.OriginNodeID, req.OriginBootID, req.Seq, env.WSDQueryKey, src, relayRawSig(payload))
	m.sendEnvelopeToPeer(dstIP, peer, env)
}

// injectToWSDPATDestination delivers a WSD response to the original querier
// recorded under queryKey.
func (m *l2RelayManager) injectToWSDPATDestination(queryKey string, payload []byte) (bool, []byte) {
	lockedAt := m.lockRelayMu("injectToWSDPATDestination")
	now := time.Now()
	for k, v := range m.wsdPATByQuery {
		if now.Sub(v.at) > 20*time.Second {
			delete(m.wsdPATByQuery, k)
		}
	}
	dst, ok := m.wsdPATByQuery[queryKey]
	if !ok || !dst.querier.IsValid() {
		m.unlockRelayMu("injectToWSDPATDestination", lockedAt)
		m.logf("[v1] l2relay: wsd pat destination missing query_key=%s", queryKey)
		return false, nil
	}
	if now.Sub(dst.at) > 20*time.Second {
		delete(m.wsdPATByQuery, queryKey)
		m.unlockRelayMu("injectToWSDPATDestination", lockedAt)
		m.logf("[v1] l2relay: wsd pat destination stale query_key=%s", queryKey)
		return false, nil
	}
	m.unlockRelayMu("injectToWSDPATDestination", lockedAt)

	// NOTE: Windows self-relay of WSD ProbeMatches does not work. The WSD
	// service (FDResPub) has internal filtering that rejects responses
	// regardless of delivery path: regular UDP (self-filter drops same-machine
	// source), TUN injection (interface/source mismatch), and loopback
	// (application-level rejection) have all been tried and fail.
	// Cross-relay via a second node on the same LAN (e.g. Linux/Android)
	// works because the response arrives from an external machine.
	// Windows nodes require a peer relay on the local LAN segment.

	c, err := m.listenWSDSourcePort()
	if err != nil {
		m.logf("[v1] l2relay: wsd pat destination 3702 bind failed query_key=%s dst=%v err=%v; falling back to ephemeral", queryKey, dst.querier, err)
		c, err = net.ListenPacket("udp4", "")
		if err != nil {
			m.logf("[v1] l2relay: wsd pat destination listen error query_key=%s dst=%v err=%v", queryKey, dst.querier, err)
			return false, nil
		}
	}
	defer c.Close()
	ua := net.UDPAddrFromAddrPort(dst.querier)
	if _, err := c.WriteTo(payload, ua); err != nil {
		m.logf("[v1] l2relay: wsd pat destination write error query_key=%s local=%v dst=%v err=%v", queryKey, c.LocalAddr(), dst.querier, err)
		return false, nil
	}
	m.limitedLogf("[v1] l2relay: wsd pat destination injected query_key=%s local=%v dst=%v bytes=%d payload_sig=%s", queryKey, c.LocalAddr(), dst.querier, len(payload), relayRawSig(payload))
	return true, payload
}

func (m *l2RelayManager) listenWSDSourcePort() (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(_ string, _ string, c syscall.RawConn) error {
			if err := c.Control(func(fd uintptr) {
				SetReuseAddr(fd)
			}); err != nil {
				return err
			}
			return nil
		},
	}
	return lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:3702")
}

func rewriteWSDResponseIPv4Address(payload []byte, fromIP, toIP netip.Addr) ([]byte, bool) {
	if len(payload) == 0 || !fromIP.Is4() || !toIP.Is4() {
		return payload, false
	}
	from := fromIP.String()
	to := toIP.String()
	if from == "" || to == "" || from == to {
		return payload, false
	}
	in := string(payload)
	if !strings.Contains(in, from) {
		return payload, false
	}
	out := strings.ReplaceAll(in, from, to)
	if out == in {
		return payload, false
	}
	return []byte(out), true
}

func rewriteWSDResponseXAddrs(payload []byte, host string, forcePort uint16) ([]byte, bool) {
	if len(payload) == 0 || host == "" {
		return payload, false
	}
	const openTag = "<wsd:XAddrs>"
	const closeTag = "</wsd:XAddrs>"
	in := string(payload)
	start := strings.Index(in, openTag)
	if start < 0 {
		return payload, false
	}
	start += len(openTag)
	end := strings.Index(in[start:], closeTag)
	if end < 0 {
		return payload, false
	}
	end += start
	rawXAddrs := strings.TrimSpace(in[start:end])
	if rawXAddrs == "" {
		return payload, false
	}
	parts := strings.Fields(rawXAddrs)
	changed := false
	for i, part := range parts {
		u, err := url.Parse(part)
		if err != nil || u.Host == "" {
			continue
		}
		port := u.Port()
		if forcePort > 0 {
			port = strconv.Itoa(int(forcePort))
		}
		if port != "" {
			u.Host = net.JoinHostPort(host, port)
		} else {
			u.Host = host
		}
		rewritten := u.String()
		if rewritten != part {
			parts[i] = rewritten
			changed = true
		}
	}
	if !changed {
		return payload, false
	}
	newXAddrs := strings.Join(parts, " ")
	out := in[:start] + newXAddrs + in[end:]
	return []byte(out), true
}

func rewriteWSDResponseXAddrsHost(payload []byte, host string) ([]byte, bool) {
	return rewriteWSDResponseXAddrs(payload, host, 0)
}
