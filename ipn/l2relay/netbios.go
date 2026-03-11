package l2relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"tailscale.com/version/distro"
)

func summarizeNetBIOSPacket(payload []byte) (summary string, interested bool, ok bool) {
	if len(payload) < 12 {
		return fmt.Sprintf("bytes=%d", len(payload)), false, true
	}
	txid := binary.BigEndian.Uint16(payload[0:2])
	flags := binary.BigEndian.Uint16(payload[2:4])
	qd := binary.BigEndian.Uint16(payload[4:6])
	an := binary.BigEndian.Uint16(payload[6:8])
	resp := (flags & 0x8000) != 0
	opcode := (flags >> 11) & 0xf
	rcode := flags & 0xf
	interested = !resp || an > 0 || qd > 0
	return fmt.Sprintf("txid=0x%04x resp=%v opcode=%d qd=%d an=%d rcode=%d", txid, resp, opcode, qd, an, rcode), interested, true
}

func detailedNetBIOSPacketLines(payload []byte) ([]string, bool) {
	if len(payload) < 12 {
		return nil, false
	}
	txid := binary.BigEndian.Uint16(payload[0:2])
	flags := binary.BigEndian.Uint16(payload[2:4])
	qd := int(binary.BigEndian.Uint16(payload[4:6]))
	an := int(binary.BigEndian.Uint16(payload[6:8]))
	ns := int(binary.BigEndian.Uint16(payload[8:10]))
	ar := int(binary.BigEndian.Uint16(payload[10:12]))
	resp := (flags & 0x8000) != 0
	lines := []string{
		fmt.Sprintf("nb_hdr={txid=0x%04x resp=%v flags=0x%04x qd=%d an=%d ns=%d ar=%d}", txid, resp, flags, qd, an, ns, ar),
	}

	off := 12
	for i := 0; i < qd; i++ {
		name, next, ok := parseNBNSName(payload, off)
		if !ok || next+4 > len(payload) {
			lines = append(lines, fmt.Sprintf("q[%d]=<parse_error off=%d>", i, off))
			return lines, true
		}
		qtype := binary.BigEndian.Uint16(payload[next : next+2])
		qclass := binary.BigEndian.Uint16(payload[next+2 : next+4])
		lines = append(lines, fmt.Sprintf("q[%d]=name=%s type=0x%04x class=0x%04x", i, name, qtype, qclass))
		off = next + 4
	}

	rrCount := an + ns + ar
	for i := 0; i < rrCount; i++ {
		name, next, ok := parseNBNSName(payload, off)
		if !ok || next+10 > len(payload) {
			lines = append(lines, fmt.Sprintf("rr[%d]=<parse_error off=%d>", i, off))
			return lines, true
		}
		rtype := binary.BigEndian.Uint16(payload[next : next+2])
		rclass := binary.BigEndian.Uint16(payload[next+2 : next+4])
		ttl := binary.BigEndian.Uint32(payload[next+4 : next+8])
		rdlen := int(binary.BigEndian.Uint16(payload[next+8 : next+10]))
		rstart := next + 10
		rend := rstart + rdlen
		if rend > len(payload) {
			lines = append(lines, fmt.Sprintf("rr[%d]=name=%s type=0x%04x class=0x%04x ttl=%d rdlen=%d <truncated>", i, name, rtype, rclass, ttl, rdlen))
			return lines, true
		}
		desc := fmt.Sprintf("rr[%d]=name=%s type=0x%04x class=0x%04x ttl=%d rdlen=%d", i, name, rtype, rclass, ttl, rdlen)
		switch rtype {
		case 0x0020: // NB
			if rdlen >= 6 {
				nbFlags := binary.BigEndian.Uint16(payload[rstart : rstart+2])
				ips := make([]string, 0, (rdlen-2)/4)
				for p := rstart + 2; p+4 <= rend; p += 4 {
					ip := net.IPv4(payload[p], payload[p+1], payload[p+2], payload[p+3])
					ips = append(ips, ip.String())
				}
				desc += fmt.Sprintf(" nb_flags=0x%04x addrs=%v", nbFlags, ips)
			}
		case 0x0021: // NBSTAT
			if rdlen > 0 {
				desc += fmt.Sprintf(" nbstat_names=%d", int(payload[rstart]))
			}
		}
		lines = append(lines, desc)
		off = rend
	}

	return lines, true
}

func parseNBNSName(payload []byte, off int) (string, int, bool) {
	if off < 0 || off >= len(payload) {
		return "", off, false
	}
	start := off
	var labels []string
	jumped := false
	seenPtrs := 0
	for {
		if off >= len(payload) {
			return "", start, false
		}
		n := int(payload[off])
		switch {
		case n == 0:
			off++
			if jumped {
				return strings.Join(labels, "."), start + 2, true
			}
			return strings.Join(labels, "."), off, true
		case n&0xC0 == 0xC0:
			if off+1 >= len(payload) || seenPtrs > 4 {
				return "", start, false
			}
			ptr := int(binary.BigEndian.Uint16(payload[off:off+2]) & 0x3fff)
			seenPtrs++
			if !jumped {
				start = off
			}
			off = ptr
			jumped = true
		default:
			off++
			if off+n > len(payload) {
				return "", start, false
			}
			label := string(payload[off : off+n])
			if decoded, ok := decodeNBNSLabel(label); ok {
				label = decoded
			}
			labels = append(labels, label)
			off += n
		}
	}
}

func decodeNBNSLabel(label string) (string, bool) {
	if len(label) != 32 {
		return "", false
	}
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hi := label[i*2]
		lo := label[i*2+1]
		if hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P' {
			return "", false
		}
		out[i] = ((hi - 'A') << 4) | (lo - 'A')
	}
	name := strings.TrimRight(string(out[:15]), " ")
	suffix := out[15]
	if name == "" {
		name = "<empty>"
	}
	return fmt.Sprintf("%s<0x%02x>", name, suffix), true
}

func isNBNSQuery(payload []byte) bool {
	if len(payload) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	qd := binary.BigEndian.Uint16(payload[4:6])
	resp := (flags & 0x8000) != 0
	return !resp && qd > 0
}

func isNBNSResponse(payload []byte) bool {
	if len(payload) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	return (flags & 0x8000) != 0
}

func (m *l2RelayManager) captureNetBIOSLoop(ctx context.Context, port int) {
	pc, err := m.listenNetBIOSPort(port)
	if err != nil {
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			m.logf("l2relay: netbios capture disabled port=%d reason=privileged_bind_denied", port)
			return
		}
		m.logf("l2relay: netbios capture listen port=%d failed: %v", port, err)
		return
	}
	defer pc.Close()
	m.logf("l2relay: netbios capture listen started on :%d", port)
	buf := make([]byte, l2RelayMaxSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			m.logf("l2relay: netbios capture read terminating port=%d err=%v", port, err)
			return
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok || ua == nil || n <= 0 {
			continue
		}
		if ua.Port != port {
			continue
		}
		if !m.allowCapturedSourceIP(ua.IP) {
			continue
		}
		raw := append([]byte(nil), buf[:n]...)
		if m.isRecentlyInjected(l2ProtoNetBIOS, raw, 1200*time.Millisecond) {
			continue
		}
		queryKey := m.observeLocalDiscoverySource(l2ProtoNetBIOS, ua, raw)
		m.forwardCaptured(l2ProtoNetBIOS, raw, queryKey, ua)
	}
}

func (m *l2RelayManager) listenNetBIOSPort(port int) (net.PacketConn, error) {
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
	return lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", port))
}

func (m *l2RelayManager) handleIncomingNetBIOSEnvelope(src netip.AddrPort, env *l2RelayEnvelope) {
	if env == nil || len(env.Payload) == 0 || env.NetBIOSPort == 0 {
		return
	}
	if env.NetBIOSPort == 137 && env.NetBIOSQueryKey != "" && isNBNSResponse(env.Payload) {
		m.logf("l2relay: netbios pat destination receive src=%v query_key=%s payload_sig=%s", src, env.NetBIOSQueryKey, relayRawSig(env.Payload))
		if delivered, _ := m.injectToNetBIOSPATDestination(env.NetBIOSQueryKey, env.Payload, env.NetBIOSPort); delivered {
			m.logf("l2relay: netbios pat destination delivered src=%v query_key=%s payload_sig=%s", src, env.NetBIOSQueryKey, relayRawSig(env.Payload))
		} else {
			m.logf("l2relay: netbios pat destination miss src=%v query_key=%s payload_sig=%s", src, env.NetBIOSQueryKey, relayRawSig(env.Payload))
		}
		return
	}
	if env.NetBIOSPort == 137 && env.NetBIOSQueryKey != "" && isNBNSQuery(env.Payload) {
		if injected := m.injectIncomingNetBIOSQueryWithPAT(src, env); injected {
			maybeLogSynthetic := false
			if m.shouldSynthesizeNetBIOSHostReply() {
				if m.forwardSyntheticNetBIOSHostReplyToOrigin(src, env, "nbns_query") {
					maybeLogSynthetic = true
				}
			}
			_ = maybeLogSynthetic
			return
		}
		if m.shouldSynthesizeNetBIOSHostReply() && m.forwardSyntheticNetBIOSHostReplyToOrigin(src, env, "nbns_query_after_inject_fail") {
			return
		}
		m.logf("l2relay: netbios query inject failed from=%v sig=%s", src, relayRawSig(env.Payload))
		return
	}
	if env.NetBIOSPort == 138 && env.NetBIOSQueryKey != "" && m.shouldSynthesizeNetBIOS138Reply() {
		m.injectToLocalNetBIOSBroadcast(env.NetBIOSPort, env.Payload)
		if isNetBIOS138DiscoveryLike(env.Payload) && m.forwardSyntheticNetBIOSHostReplyToOrigin(src, env, "netbios138_trigger") {
			return
		}
	}
	m.injectToLocalNetBIOSBroadcast(env.NetBIOSPort, env.Payload)
}

func (m *l2RelayManager) injectIncomingNetBIOSQueryWithPAT(src netip.AddrPort, env *l2RelayEnvelope) bool {
	if env == nil || env.OriginNodeID == 0 || len(env.Payload) == 0 || env.NetBIOSPort != 137 || env.NetBIOSQueryKey == "" {
		return false
	}
	c, err := m.listenNetBIOSPort(int(env.NetBIOSPort))
	fallbackEphemeral := false
	if err != nil {
		m.logf("l2relay: netbios pat listen error origin=%d/%s seq=%d err=%v; falling back to ephemeral", env.OriginNodeID, env.OriginBootID, env.Seq, err)
		c, err = net.ListenPacket("udp4", "")
		if err != nil {
			m.logf("l2relay: netbios pat ephemeral listen error origin=%d/%s seq=%d err=%v", env.OriginNodeID, env.OriginBootID, env.Seq, err)
			return false
		}
		fallbackEphemeral = true
	}
	defer c.Close()
	m.noteInjectedPayload(l2ProtoNetBIOS, env.Payload)
	dst := &net.UDPAddr{IP: m.localIPv4BroadcastAddr(), Port: int(env.NetBIOSPort)}
	if _, err := c.WriteTo(env.Payload, dst); err != nil {
		m.logf("l2relay: netbios pat inject write error local=%v dst=%v origin=%d/%s seq=%d err=%v", c.LocalAddr(), dst, env.OriginNodeID, env.OriginBootID, env.Seq, err)
		return false
	}
	m.logf("l2relay: netbios pat inject query local=%v dst=%v origin=%d/%s seq=%d query_key=%s query_sig=%s fallback_ephemeral=%v", c.LocalAddr(), dst, env.OriginNodeID, env.OriginBootID, env.Seq, env.NetBIOSQueryKey, relayRawSig(env.Payload), fallbackEphemeral)
	m.readNetBIOSPATReplies(c, src, env)
	return true
}

func (m *l2RelayManager) readNetBIOSPATReplies(c net.PacketConn, src netip.AddrPort, req *l2RelayEnvelope) {
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
			m.logf("l2relay: netbios pat read error origin=%d/%s req_seq=%d err=%v", req.OriginNodeID, req.OriginBootID, req.Seq, err)
			return
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok || ua == nil || n <= 0 {
			continue
		}
		if !m.allowCapturedSourceIP(ua.IP) {
			continue
		}
		raw := append([]byte(nil), buf[:n]...)
		if !isNBNSResponse(raw) {
			continue
		}
		replySrc, ok := udpAddrPort(ua)
		if !ok {
			continue
		}
		if summary, interested := summarizeDiscoveryPayload(l2ProtoNetBIOS, raw); summary != "" && interested && m.shouldLogSummarySig(relayRawSig(raw)) {
			m.logf("l2relay: netbios pat reply summary src=%v req_query_key=%s reply_sig=%s %s", replySrc, req.NetBIOSQueryKey, relayRawSig(raw), summary)
			if dumps, ok := detailedNetBIOSPacketLines(raw); ok {
				for i, dump := range dumps {
					m.logf("l2relay: netbios pat reply detail[%d] src=%v req_query_key=%s reply_sig=%s %s", i, replySrc, req.NetBIOSQueryKey, relayRawSig(raw), dump)
				}
			}
		}
		m.forwardNetBIOSPATReplyToOrigin(replySrc, req, raw)
	}
}

func (m *l2RelayManager) forwardNetBIOSPATReplyToOrigin(src netip.AddrPort, req *l2RelayEnvelope, payload []byte) {
	if req == nil || req.OriginNodeID == 0 || len(payload) == 0 || req.NetBIOSQueryKey == "" {
		return
	}
	replySrcIP := src.Addr().Unmap()
	if debugRewriteMDNSSelfAddress() && replySrcIP.Is4() {
		if selfLANIP, ok := m.selfLANIPv4ForRelay(); ok && selfLANIP == replySrcIP {
			if selfTailIP, tailOK := m.selfTailscaleIP(); tailOK {
				selfTailIP = selfTailIP.Unmap()
				if selfTailIP.Is4() {
					if rewritten, changed := rewriteNBNSResponseIPv4Address(payload, replySrcIP, selfTailIP); changed {
						m.logf("l2relay: netbios pat reply self-address rewrite src_peer=%v req_query_key=%s from=%v to=%v payload_sig=%s", src, req.NetBIOSQueryKey, replySrcIP, selfTailIP, relayRawSig(rewritten))
						payload = rewritten
					}
				}
			}
		}
	}
	nm := m.b.NetMap()
	if nm == nil || !nm.SelfNode.Valid() {
		return
	}
	selfIP, ok := m.selfTailscaleIP()
	if !ok {
		return
	}
	peer, ok := peerNode(nm, req.OriginNodeID)
	if !ok || !peer.Valid() {
		m.logf("[v1] l2relay: peer not found for id %v", req.OriginNodeID)
		return
	}
	if online, ok := peer.Online().GetOk(); !ok || !online {
		m.logf("[v1] l2relay: netbios pat drop reply peer offline peer=%d sig=%s", req.OriginNodeID, relayRawSig(payload))
		return
	}
	dstIP := nodeIP(peer, netip.Addr.Is4)
	if !dstIP.IsValid() {
		m.logf("[v1] l2relay: netbios pat drop reply no origin peer=%d sig=%s", req.OriginNodeID, relayRawSig(payload))
		return
	}
	if !m.l2DiscoveryAllowed(selfIP, dstIP, string(l2ProtoNetBIOS), false) {
		m.logf("[v1] l2relay: netbios pat drop reply policy deny src=%v dst=%v", selfIP, dstIP)
		return
	}
	env := l2RelayEnvelope{
		OriginNodeID:    nm.SelfNode.ID(),
		OriginBootID:    m.bootID,
		Seq:             m.seq.Add(1),
		Proto:           l2ProtoNetBIOS,
		Hops:            1,
		NetBIOSQueryKey: req.NetBIOSQueryKey,
		NetBIOSPort:     req.NetBIOSPort,
		Payload:         payload,
	}
	m.logf("[v2] l2relay: netbios pat forward reply origin_peer=%d dst=%v req_origin=%d/%s req_seq=%d req_query_key=%s src_peer=%v reply_sig=%s", req.OriginNodeID, dstIP, req.OriginNodeID, req.OriginBootID, req.Seq, env.NetBIOSQueryKey, src, relayRawSig(payload))
	m.sendEnvelopeToPeer(dstIP, peer, env)
}

func (m *l2RelayManager) injectToNetBIOSPATDestination(queryKey string, payload []byte, port uint16) (bool, []byte) {
	lockedAt := m.lockRelayMu("injectToNetBIOSPATDestination")
	now := time.Now()
	for k, v := range m.netbiosPATByQuery {
		if now.Sub(v.at) > 20*time.Second {
			delete(m.netbiosPATByQuery, k)
		}
	}
	dst, ok := m.netbiosPATByQuery[queryKey]
	if !ok || !dst.querier.IsValid() {
		m.unlockRelayMu("injectToNetBIOSPATDestination", lockedAt)
		m.logf("[v1] l2relay: netbios pat destination missing query_key=%s", queryKey)
		return false, nil
	}
	if now.Sub(dst.at) > 20*time.Second {
		delete(m.netbiosPATByQuery, queryKey)
		m.unlockRelayMu("injectToNetBIOSPATDestination", lockedAt)
		m.logf("[v1] l2relay: netbios pat destination stale query_key=%s", queryKey)
		return false, nil
	}
	m.unlockRelayMu("injectToNetBIOSPATDestination", lockedAt)
	c, err := m.listenNetBIOSPort(int(port))
	if err != nil {
		m.logf("[v1] l2relay: netbios pat destination %d bind failed query_key=%s dst=%v err=%v; falling back to ephemeral", port, queryKey, dst.querier, err)
		c, err = net.ListenPacket("udp4", "")
		if err != nil {
			m.logf("[v1] l2relay: netbios pat destination listen error query_key=%s dst=%v err=%v", queryKey, dst.querier, err)
			return false, nil
		}
	}
	defer c.Close()
	dstAddr := netip.AddrPortFrom(dst.querier.Addr(), port)
	ua := net.UDPAddrFromAddrPort(dstAddr)
	if _, err := c.WriteTo(payload, ua); err != nil {
		m.logf("[v1] l2relay: netbios pat destination write error query_key=%s local=%v dst=%v err=%v", queryKey, c.LocalAddr(), dstAddr, err)
		return false, nil
	}
	m.limitedLogf("[v1] l2relay: netbios pat destination injected query_key=%s local=%v dst=%v bytes=%d payload_sig=%s", queryKey, c.LocalAddr(), dstAddr, len(payload), relayRawSig(payload))
	return true, payload
}

func (m *l2RelayManager) injectToLocalNetBIOSBroadcast(port uint16, payload []byte) {
	if len(payload) == 0 || port == 0 {
		return
	}
	m.noteInjectedPayload(l2ProtoNetBIOS, payload)
	c, err := net.ListenPacket("udp4", "")
	if err != nil {
		m.logf("[v1] l2relay: netbios local inject listen error port=%d err=%v", port, err)
		return
	}
	defer c.Close()
	dst := &net.UDPAddr{IP: m.localIPv4BroadcastAddr(), Port: int(port)}
	if _, err := c.WriteTo(payload, dst); err != nil {
		m.logf("[v1] l2relay: netbios local inject write error port=%d local=%v dst=%v err=%v", port, c.LocalAddr(), dst, err)
		return
	}
	m.limitedLogf("[v1] l2relay: netbios local inject port=%d local=%v dst=%v bytes=%d payload_sig=%s", port, c.LocalAddr(), dst, len(payload), relayRawSig(payload))
}

func (m *l2RelayManager) localIPv4BroadcastAddr() net.IP {
	if selfIP, ok := m.selfLANIPv4ForRelay(); ok && selfIP.Is4() {
		b := selfIP.As4()
		b[3] = 255
		return net.IPv4(b[0], b[1], b[2], b[3])
	}
	return net.IPv4bcast
}

func rewriteNBNSResponseIPv4Address(payload []byte, fromIP, toIP netip.Addr) ([]byte, bool) {
	if len(payload) < 12 || !fromIP.Is4() || !toIP.Is4() {
		return payload, false
	}
	if !isNBNSResponse(payload) {
		return payload, false
	}
	from4 := fromIP.As4()
	to4 := toIP.As4()
	out := append([]byte(nil), payload...)
	changed := false
	for i := 0; i+4 <= len(out); i++ {
		if out[i] == from4[0] && out[i+1] == from4[1] && out[i+2] == from4[2] && out[i+3] == from4[3] {
			out[i] = to4[0]
			out[i+1] = to4[1]
			out[i+2] = to4[2]
			out[i+3] = to4[3]
			changed = true
		}
	}
	if !changed {
		return payload, false
	}
	return out, true
}

func (m *l2RelayManager) shouldSynthesizeNetBIOS138Reply() bool {
	if runtime.GOOS != "linux" || distro.Get() != distro.Synology {
		return false
	}
	_, err := m.listenNetBIOSPort(138)
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

func (m *l2RelayManager) shouldSynthesizeNetBIOSHostReply() bool {
	if runtime.GOOS != "linux" || distro.Get() != distro.Synology {
		return false
	}
	return true
}

func (m *l2RelayManager) forwardSyntheticNetBIOSHostReplyToOrigin(src netip.AddrPort, req *l2RelayEnvelope, reason string) bool {
	if req == nil || req.OriginNodeID == 0 || req.NetBIOSQueryKey == "" {
		return false
	}
	ident, ok := m.synologySMBIdentity()
	if !ok {
		return false
	}
	replyIP := ident.IP
	if !replyIP.IsValid() {
		return false
	}
	payload, ok := synthesizeNBNSHostReply(req.Payload, ident.Hostname, replyIP)
	if !ok {
		return false
	}
	nm := m.b.NetMap()
	if nm == nil || !nm.SelfNode.Valid() {
		return false
	}
	selfIP, ok := m.selfTailscaleIP()
	if !ok {
		return false
	}
	peer, ok := peerNode(nm, req.OriginNodeID)
	if !ok || !peer.Valid() {
		return false
	}
	dstIP := nodeIP(peer, netip.Addr.Is4)
	if !dstIP.IsValid() {
		return false
	}
	if !m.l2DiscoveryAllowed(selfIP, dstIP, string(l2ProtoNetBIOS), false) {
		return false
	}
	env := l2RelayEnvelope{
		OriginNodeID:    nm.SelfNode.ID(),
		OriginBootID:    m.bootID,
		Seq:             m.seq.Add(1),
		Proto:           l2ProtoNetBIOS,
		Hops:            1,
		NetBIOSQueryKey: req.NetBIOSQueryKey,
		NetBIOSPort:     137,
		Payload:         payload,
	}
	m.limitedLogf("[v1] l2relay: netbios synthetic host reply reason=%s origin_peer=%d dst=%v req_origin=%d/%s req_seq=%d req_query_key=%s hostname=%q reply_ip=%v payload_sig=%s", reason, req.OriginNodeID, dstIP, req.OriginNodeID, req.OriginBootID, req.Seq, req.NetBIOSQueryKey, ident.Hostname, replyIP, relayRawSig(payload))
	m.sendEnvelopeToPeer(dstIP, peer, env)
	return true
}

type synologySMBIdentityInfo struct {
	Hostname string
	IP       netip.Addr
}

func (m *l2RelayManager) synologySMBIdentity() (synologySMBIdentityInfo, bool) {
	host, _ := os.Hostname()
	info := synologySMBIdentityInfo{
		Hostname: strings.TrimSpace(host),
	}
	if info.Hostname == "" {
		return synologySMBIdentityInfo{}, false
	}
	if debugRewriteMDNSSelfAddress() {
		if tail, ok := m.selfTailscaleIP(); ok {
			tail = tail.Unmap()
			if tail.Is4() {
				info.IP = tail
			}
		}
	}
	if !info.IP.IsValid() {
		if selfLAN, ok := m.selfLANIPv4ForRelay(); ok && selfLAN.Is4() {
			info.IP = selfLAN
		}
	}
	if !info.IP.IsValid() {
		return synologySMBIdentityInfo{}, false
	}
	return info, true
}

func synthesizeNBNSHostReply(seed []byte, hostname string, ip netip.Addr) ([]byte, bool) {
	hostname = strings.TrimSpace(hostname)
	ip = ip.Unmap()
	if hostname == "" || !ip.Is4() {
		return nil, false
	}
	txid := uint16(0)
	if len(seed) >= 2 {
		txid = binary.BigEndian.Uint16(seed[:2])
	}
	name, ok := encodeNBNSQuestionName(hostname, 0x20)
	if !ok {
		return nil, false
	}
	out := make([]byte, 0, 12+len(name)+2+10+6)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], txid)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8500)
	binary.BigEndian.PutUint16(hdr[4:6], 0)
	binary.BigEndian.PutUint16(hdr[6:8], 1)
	out = append(out, hdr...)
	out = append(out, name...)
	rr := make([]byte, 2+2+4+2+2+4)
	binary.BigEndian.PutUint16(rr[0:2], 0x0020)
	binary.BigEndian.PutUint16(rr[2:4], 0x0001)
	binary.BigEndian.PutUint32(rr[4:8], 300)
	binary.BigEndian.PutUint16(rr[8:10], 6)
	binary.BigEndian.PutUint16(rr[10:12], 0x0000)
	ip4 := ip.As4()
	copy(rr[12:16], ip4[:])
	out = append(out, rr...)
	return out, true
}

func isNetBIOS138DiscoveryLike(payload []byte) bool {
	if len(payload) < 16 {
		return false
	}
	// NetBIOS datagram browser traffic commonly carries SMB mailslot browse
	// payloads. We only synthesize a reply when the incoming datagram appears to
	// be a browser discovery-style packet we can reasonably answer with local
	// share metadata.
	s := strings.ToUpper(string(payload))
	if strings.Contains(s, "\\MAILSLOT\\BROWSE") || strings.Contains(s, "MSBROWSE") {
		return true
	}
	// Some captures do not preserve a clean mailslot string but still carry the
	// browser datagram to port 138. Treat broadcast-ish datagrams with no NBNS
	// header shape as candidates.
	if !isNBNSQuery(payload) && !isNBNSResponse(payload) {
		return true
	}
	return false
}

func encodeNBNSQuestionName(hostname string, suffix byte) ([]byte, bool) {
	name := make([]byte, 16)
	host := strings.ToUpper(strings.TrimSpace(hostname))
	if len(host) > 15 {
		host = host[:15]
	}
	copy(name, []byte(host))
	for i := len(host); i < 15; i++ {
		name[i] = ' '
	}
	name[15] = suffix
	enc := make([]byte, 34)
	enc[0] = 32
	for i := 0; i < 16; i++ {
		b := name[i]
		enc[1+i*2] = 'A' + ((b >> 4) & 0x0f)
		enc[1+i*2+1] = 'A' + (b & 0x0f)
	}
	enc[33] = 0
	return enc, true
}
