// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package l2relay

import (
	"context"
	"io"
	"net"
	"net/netip"
	"time"

	"tailscale.com/net/netns"
	"tailscale.com/types/nettype"
)

func (m *l2RelayManager) listenRelayUDP(ctx context.Context, network, bindAddr string) {
	lc := netns.Listener(m.logf, m.b.NetMon())
	pc, err := lc.ListenPacket(ctx, network, bindAddr)
	if err != nil {
		m.logf("l2relay: udp listen failed network=%s addr=%s err=%v", network, bindAddr, err)
		return
	}
	m.logf("l2relay: udp listen started network=%s addr=%s", network, bindAddr)
	defer pc.Close()

	conn, ok := pc.(*net.UDPConn)
	if !ok {
		m.logf("l2relay: udp listen unexpected conn type network=%s addr=%s type=%T", network, bindAddr, pc)
		return
	}
	m.logf("l2relay: udp listen active network=%s requested=%s local=%v", network, bindAddr, conn.LocalAddr())

	buf := make([]byte, l2RelayMaxSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			m.logf("l2relay: udp listen stop network=%s addr=%s err=%v", network, bindAddr, err)
			return
		}
		if n <= 0 {
			continue
		}
		src, ok := udpAddrPort(from)
		if !ok {
			m.logf("l2relay: udp listen drop invalid src network=%s from=%v", network, from)
			continue
		}
		m.logf("l2relay: udp socket recv network=%s bytes=%d from=%v", network, n, src)
		dstAP := src
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			if ap, ok := udpAddrPort(ua); ok {
				dstAP = ap
			}
		}
		m.handleIncomingEnvelope(src, dstAP.Addr(), buf[:n])
	}
}

// Deprecated: kept for compatibility while migrating away from UDP flow intercept relay.
func (m *l2RelayManager) udpHandlerForFlow(src, dst netip.AddrPort) (handler func(nettype.ConnPacketConn), intercept bool) {
	if dst.Port() != l2RelayDataPort {
		return nil, false
	}
	lockedAt := m.lockRelayMu("udpHandlerForFlow.cap")
	selfCanRelay := m.selfCanRelayQuery
	m.unlockRelayMu("udpHandlerForFlow.cap", lockedAt)
	if !selfCanRelay {
		return nil, false
	}
	m.logf("l2relay: udp intercept flow src=%v dst=%v", src, dst)
	return func(c nettype.ConnPacketConn) {
		m.logf("l2relay: udp intercept handler start src=%v dst=%v", src, dst)
		defer c.Close()
		m.readIncomingRelayPackets(src, c)
		m.logf("l2relay: udp intercept handler stop src=%v dst=%v", src, dst)
	}, true
}

// Deprecated: kept for compatibility while migrating away from UDP flow intercept relay.
func (m *l2RelayManager) readIncomingRelayPackets(src netip.AddrPort, c nettype.ConnPacketConn) {
	m.logf("l2relay: udp read loop start src=%v", src)
	buf := make([]byte, 64<<10)
	for {
		_ = c.SetReadDeadline(time.Now().Add(l2RelayReadTTL))
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				m.logf("l2relay: udp read timeout src=%v", src)
				return
			}
			if err != io.EOF {
				m.logf("l2relay: read error: %v", err)
			}
			m.logf("l2relay: udp read loop stop src=%v err=%v", src, err)
			return
		}
		srcAP := src
		if ua, ok := from.(*net.UDPAddr); ok {
			if ap, ok := udpAddrPort(ua); ok {
				srcAP = ap
			}
		}
		m.logf("l2relay: udp recv packet bytes=%d from=%v flow_src=%v raw_sig=%s", n, srcAP, src, relayRawSig(buf[:n]))
		dstAP := src
		if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
			if ap, ok := udpAddrPort(ua); ok {
				dstAP = ap
			}
		}
		m.handleIncomingEnvelope(srcAP, dstAP.Addr(), buf[:n])
	}
}
