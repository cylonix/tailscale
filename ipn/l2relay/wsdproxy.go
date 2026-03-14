// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package l2relay

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"tailscale.com/envknob"
)

const l2RelayWSDProxyPort uint16 = 35357

var debugL2RelayWSDHTTPProxyRewriteOpt = envknob.RegisterOptBool("TS_DEBUG_L2RELAY_WSD_HTTP_PROXY_REWRITE")

func debugL2RelayWSDHTTPProxyRewrite() bool {
	if v, ok := debugL2RelayWSDHTTPProxyRewriteOpt().Get(); ok {
		return v
	}
	// Default to true so that NAS showing from a Node installed with Cylonix can
	// be properly identified with full domain name. Use the above option
	// to disable the rewrite if prefer to the original hostname.
	return true
}

func (m *l2RelayManager) tcpHandlerForFlow(src, dst netip.AddrPort) (handler func(net.Conn) error, intercept bool) {
	if !debugL2RelayWSDHTTPProxyRewrite() || dst.Port() != l2RelayWSDProxyPort {
		return nil, false
	}
	if !m.l2DiscoveryAllowed(src.Addr(), dst.Addr(), string(l2ProtoWSD), true) {
		m.logf("l2relay: wsd http proxy deny policy src=%v dst=%v", src, dst)
		return nil, false
	}
	return func(c net.Conn) error {
		return m.handleWSDHTTPProxyConn(src, dst, c)
	}, true
}

func (m *l2RelayManager) handleWSDHTTPProxyConn(src, dst netip.AddrPort, c net.Conn) error {
	defer c.Close()
	upstreamIP, ok := m.selfLANIPv4ForRelay()
	if !ok {
		m.logf("l2relay: wsd http proxy reject src=%v dst=%v reason=no_lan_ip", src, dst)
		return nil
	}
	upstreamHostPort := net.JoinHostPort(upstreamIP.String(), "5357")
	rewriteHost := ""
	if nm := m.b.NetMap(); nm != nil && nm.SelfNode.Valid() {
		rewriteHost = strings.TrimSuffix(nm.SelfNode.Name(), ".")
	}
	if rewriteHost == "" {
		rewriteHost = dst.Addr().String()
	}
	m.logf("l2relay: wsd http proxy accept src=%v dst=%v upstream=%q rewrite_host=%q", src, dst, upstreamHostPort, rewriteHost)

	tr := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		DisableCompression:    true,
		ResponseHeaderTimeout: 10 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if err != io.EOF {
				m.logf("l2relay: wsd http proxy read request err=%v src=%v dst=%v", err, src, dst)
			}
			return nil
		}
		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			m.logf("l2relay: wsd http proxy read body err=%v src=%v dst=%v", err, src, dst)
			return nil
		}

		targetURL := &url.URL{
			Scheme:   "http",
			Host:     upstreamHostPort,
			Path:     req.URL.Path,
			RawPath:  req.URL.RawPath,
			RawQuery: req.URL.RawQuery,
		}
		upReq, err := http.NewRequestWithContext(context.Background(), req.Method, targetURL.String(), bytes.NewReader(body))
		if err != nil {
			m.logf("l2relay: wsd http proxy build request err=%v src=%v dst=%v", err, src, dst)
			return nil
		}
		upReq.Header = req.Header.Clone()
		upReq.Host = upstreamHostPort
		upReq.ContentLength = int64(len(body))
		removeHopByHopHeaders(upReq.Header)

		resp, err := client.Do(upReq)
		if err != nil {
			m.logf("l2relay: wsd http proxy upstream err=%v src=%v dst=%v upstream=%q", err, src, dst, upstreamHostPort)
			io.WriteString(bw, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			_ = bw.Flush()
			return nil
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			m.logf("l2relay: wsd http proxy read upstream body err=%v src=%v dst=%v upstream=%q", err, src, dst, upstreamHostPort)
			return nil
		}
		if rewritten, changed := rewriteWSDHTTPPubComputerHost(respBody, rewriteHost); changed {
			m.logf("l2relay: wsd http proxy rewrite src=%v dst=%v upstream=%q host=%q sig_before=%s sig_after=%s", src, dst, upstreamHostPort, rewriteHost, relayRawSig(respBody), relayRawSig(rewritten))
			respBody = rewritten
		}

		resp.Body = io.NopCloser(bytes.NewReader(respBody))
		resp.ContentLength = int64(len(respBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(respBody)))
		resp.Header.Del("Transfer-Encoding")
		removeHopByHopHeaders(resp.Header)
		if err := resp.Write(bw); err != nil {
			m.logf("l2relay: wsd http proxy write response err=%v src=%v dst=%v", err, src, dst)
			return nil
		}
		if err := bw.Flush(); err != nil {
			m.logf("l2relay: wsd http proxy flush err=%v src=%v dst=%v", err, src, dst)
			return nil
		}
		if req.Close || resp.Close {
			return nil
		}
	}
}

func removeHopByHopHeaders(h http.Header) {
	if h == nil {
		return
	}
	for _, k := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
}

func rewriteWSDHTTPPubComputerHost(payload []byte, host string) ([]byte, bool) {
	if len(payload) == 0 || host == "" {
		return payload, false
	}
	const openTag = "<pub:Computer>"
	const closeTag = "</pub:Computer>"
	in := string(payload)
	start := strings.Index(in, openTag)
	if start < 0 {
		return payload, false
	}
	start += len(openTag)
	endRel := strings.Index(in[start:], closeTag)
	if endRel < 0 {
		return payload, false
	}
	end := start + endRel
	raw := in[start:end]
	if raw == "" {
		return payload, false
	}
	oldHost, suffix, found := strings.Cut(raw, "/")
	if !found || oldHost == "" {
		return payload, false
	}
	newVal := host + "/" + suffix
	if newVal == raw {
		return payload, false
	}
	out := in[:start] + newVal + in[end:]
	return []byte(out), true
}
