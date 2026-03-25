// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// derpbench measures DERP relay throughput between two clients on the same
// DERP server.  It is used to compare performance with and without an xray
// underlay (VLESS+REALITY+XHTTP).
//
// Usage:
//
//	# direct (no xray):
//	derpbench -server http://10.100.0.1:8080
//
//	# through built-in xray underlay (stream-up, the fixed mode):
//	derpbench -server http://10.100.0.1:8080 \
//	    -xray-uuid <UUID> -xray-pubkey <PUBKEY> \
//	    -xray-shortid <SHORTID> -xray-tunnel /cylonix-derp-tunnel
//
//	# through built-in xray underlay (packet-up, reproduces bottleneck):
//	derpbench -server http://10.100.0.1:8080 \
//	    -xray-uuid <UUID> -xray-pubkey <PUBKEY> \
//	    -xray-shortid <SHORTID> -xray-tunnel /cylonix-derp-tunnel \
//	    -xray-mode packet-up
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func main() {
	serverURL := flag.String("server", "http://localhost:8080/derp", "DERP server URL (include /derp path)")
	duration := flag.Duration("d", 15*time.Second, "test duration")
	msgSize := flag.Int("size", 1400, "message size in bytes (default matches WireGuard MTU)")

	// xray underlay flags (optional — omit all to use direct DERP)
	xrayUUID    := flag.String("xray-uuid", "", "xray VLESS client UUID (enables xray underlay)")
	xrayPubkey  := flag.String("xray-pubkey", "", "xray REALITY server public key")
	xrayShortID := flag.String("xray-shortid", "", "xray REALITY short ID")
	xrayTunnel  := flag.String("xray-tunnel", "/cylonix-derp-tunnel", "xray XHTTP tunnel path")
	xraySNI     := flag.String("xray-sni", "www.microsoft.com", "xray REALITY server name")
	xrayMode      := flag.String("xray-mode", "stream-up", "xhttp upload mode: stream-up or packet-up")
	xrayConnCount := flag.Int("xray-conn-count", 1, "number of parallel xray sender connections (requires -allow-parallel-clients on derper)")
	xrayRecvCount := flag.Int("xray-recv-count", 1, "number of parallel xray receiver connections (requires -allow-parallel-clients on derper)")
	check         := flag.Bool("check", false, "quick connectivity check: test latency-check + DERP ping, then exit")
	flag.Parse()

	log.SetFlags(0)

	// Ensure the server URL has the /derp path that derphttp.Client expects.
	{
		u, err := url.Parse(*serverURL)
		if err != nil {
			log.Fatalf("bad server URL %q: %v", *serverURL, err)
		}
		if u.Path == "" || u.Path == "/" {
			u.Path = "/derp"
			*serverURL = u.String()
		}
	}

	netMon, err := netmon.New(log.Printf)
	if err != nil {
		log.Fatalf("netmon.New: %v", err)
	}

	senderPriv := key.NewNode()
	recvPriv   := key.NewNode()
	recvPub    := recvPriv.Public()

	// Build an XRay-enabled DERPNode if xray flags are set.
	var xrayNode *tailcfg.DERPNode
	if *xrayUUID != "" {
		u, err := url.Parse(*serverURL)
		if err != nil {
			log.Fatalf("bad server URL %q: %v", *serverURL, err)
		}
		xrayNode = &tailcfg.DERPNode{
			HostName: u.Hostname(),
			// xray server always listens on 443; dialNodeXRay uses DERPPort
			// when non-zero, otherwise falls back to 443 (HTTPS) or 80 (HTTP)
			// based on the server URL scheme. Set it explicitly so HTTP server
			// URLs (-server http://...) still route xray to port 443.
			DERPPort: 443,
			XRay: &tailcfg.DERPXRay{
				ClientUUID:        *xrayUUID,
				ServerPublicKey:   *xrayPubkey,
				RealityShortID:    *xrayShortID,
				XHTTPTunnel:       *xrayTunnel,
				RealityServerName: *xraySNI,
				XHTTPMode:         *xrayMode,
			},
		}
		log.Printf("xray underlay: mode=%s tunnel=%s sni=%s", *xrayMode, *xrayTunnel, *xraySNI)
	}

	// -check: quick connectivity test then exit.
	if *check {
		runCheck(*serverURL, xrayNode)
		return
	}

	newClient := func(priv key.NodePrivate, label string) *derphttp.Client {
		c, err := derphttp.NewClient(priv, *serverURL, log.Printf, netMon)
		if err != nil {
			log.Fatalf("NewClient(%s): %v", label, err)
		}
		if xrayNode != nil {
			c.SetURLDialer(derphttp.XRayDialer(c, xrayNode))
		}
		if err := c.Connect(context.Background()); err != nil {
			log.Fatalf("Connect(%s): %v", label, err)
		}
		log.Printf("[%s] connected to %s", label, *serverURL)
		return c
	}

	// Create one or more receiver clients (all sharing the same key so the
	// server distributes incoming packets across all of them round-robin).
	nReceivers := *xrayRecvCount
	if nReceivers < 1 {
		nReceivers = 1
	}
	recvs := make([]*derphttp.Client, nReceivers)
	for i := range recvs {
		recvs[i] = newClient(recvPriv, fmt.Sprintf("receiver-%d", i))
	}

	// Create one or more sender clients (all sharing the same key so the
	// server sees them as parallel connections from the same node).
	nSenders := *xrayConnCount
	if nSenders < 1 {
		nSenders = 1
	}
	senders := make([]*derphttp.Client, nSenders)
	for i := range senders {
		senders[i] = newClient(senderPriv, fmt.Sprintf("sender-%d", i))
	}

	var rxBytes atomic.Int64

	// Receiver goroutines — one per receiver connection.
	for _, r := range recvs {
		r := r
		go func() {
			for {
				msg, err := r.Recv()
				if err != nil {
					return
				}
				if pkt, ok := msg.(derp.ReceivedPacket); ok {
					rxBytes.Add(int64(len(pkt.Data)))
				}
			}
		}()
	}

	// Give receiver goroutine a moment to start.
	time.Sleep(100 * time.Millisecond)

	payload := make([]byte, *msgSize)

	switch {
	case nSenders > 1 && nReceivers > 1:
		fmt.Printf("Sending %d-byte packets for %v via %d senders / %d receivers...\n", *msgSize, *duration, nSenders, nReceivers)
	case nSenders > 1:
		fmt.Printf("Sending %d-byte packets for %v via %d parallel sender connections...\n", *msgSize, *duration, nSenders)
	case nReceivers > 1:
		fmt.Printf("Sending %d-byte packets for %v via %d parallel receiver connections...\n", *msgSize, *duration, nReceivers)
	default:
		fmt.Printf("Sending %d-byte packets for %v...\n", *msgSize, *duration)
	}
	start    := time.Now()
	deadline := start.Add(*duration)

	var txBytes int64
	var sendErrs int
	var rrIdx int
	for time.Now().Before(deadline) {
		// Round-robin across senders.
		s := senders[rrIdx%nSenders]
		rrIdx++
		if err := s.Send(recvPub, payload); err != nil {
			sendErrs++
			if sendErrs > 10 {
				log.Printf("too many send errors: %v", err)
				break
			}
			continue
		}
		txBytes += int64(*msgSize)
	}
	elapsed := time.Since(start)

	// Wait briefly for in-flight packets to arrive.
	time.Sleep(500 * time.Millisecond)
	rxTotal := rxBytes.Load()

	txMbps := float64(txBytes) * 8 / elapsed.Seconds() / 1e6
	rxMbps := float64(rxTotal) * 8 / elapsed.Seconds() / 1e6

	fmt.Printf("── DERP throughput results ──────────────────────\n")
	fmt.Printf("  Duration : %.1fs\n", elapsed.Seconds())
	fmt.Printf("  Msg size : %d bytes\n", *msgSize)
	if nSenders > 1 || nReceivers > 1 {
		fmt.Printf("  Senders  : %d  Receivers: %d\n", nSenders, nReceivers)
	}
	fmt.Printf("  TX       : %.1f MB  →  %.1f Mbps\n", float64(txBytes)/1e6, txMbps)
	fmt.Printf("  RX       : %.1f MB  →  %.1f Mbps\n", float64(rxTotal)/1e6, rxMbps)
	if sendErrs > 0 {
		fmt.Printf("  SendErrs : %d\n", sendErrs)
	}
	fmt.Printf("─────────────────────────────────────────────────\n")

	for _, r := range recvs {
		r.Close()
	}
	for _, s := range senders {
		s.Close()
	}
}

// runCheck performs a quick connectivity test:
//  1. HTTP GET /derp/latency-check (via xray if configured)
//  2. Full DERP connect + ping-pong
//
// It exits 0 on success and 1 on any failure.
func runCheck(serverURL string, xrayNode *tailcfg.DERPNode) {
	baseURL := serverURL
	// Strip /derp suffix for the latency-check URL.
	if u, err := url.Parse(serverURL); err == nil {
		u.Path = ""
		baseURL = u.String()
	}

	// Step 1: latency-check over xray (if configured) or plain HTTP.
	latencyURL := baseURL + "/derp/latency-check"
	fmt.Printf("── check ────────────────────────────────────────\n")
	fmt.Printf("  Step 1: GET %s\n", latencyURL)
	var httpClient *http.Client
	if xrayNode != nil {
		netMon, err := netmon.New(log.Printf)
		if err != nil {
			log.Fatalf("netmon.New: %v", err)
		}
		// Use a temporary derphttp.Client just for xray dialing.
		tmpDC, _ := derphttp.NewClient(key.NewNode(), serverURL, log.Printf, netMon)
		dialer := derphttp.XRayDialer(tmpDC, xrayNode)
		httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: dialer,
			},
			Timeout: 10 * time.Second,
		}
	} else {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	t0 := time.Now()
	resp, err := httpClient.Get(latencyURL)
	if err != nil {
		fmt.Printf("  FAIL: %v\n", err)
		fmt.Printf("─────────────────────────────────────────────────\n")
		log.Fatal("check failed")
	}
	resp.Body.Close()
	lat1 := time.Since(t0)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("  FAIL: unexpected status %d\n", resp.StatusCode)
		fmt.Printf("─────────────────────────────────────────────────\n")
		log.Fatal("check failed")
	}
	fmt.Printf("  OK  : %d  latency=%v\n", resp.StatusCode, lat1.Round(time.Millisecond))

	// Step 2: full DERP connect + send/recv ping.
	fmt.Printf("  Step 2: DERP connect + ping to %s\n", serverURL)
	netMon, err := netmon.New(log.Printf)
	if err != nil {
		log.Fatalf("netmon.New: %v", err)
	}
	senderPriv := key.NewNode()
	recvPriv   := key.NewNode()
	recvPub    := recvPriv.Public()

	makeConn := func(priv key.NodePrivate, label string) *derphttp.Client {
		c, err := derphttp.NewClient(priv, serverURL, log.Printf, netMon)
		if err != nil {
			log.Fatalf("NewClient(%s): %v", label, err)
		}
		if xrayNode != nil {
			c.SetURLDialer(derphttp.XRayDialer(c, xrayNode))
		}
		t0 := time.Now()
		if err := c.Connect(context.Background()); err != nil {
			fmt.Printf("  FAIL: Connect(%s): %v\n", label, err)
			fmt.Printf("─────────────────────────────────────────────────\n")
			log.Fatal("check failed")
		}
		fmt.Printf("  OK  : %s connected  dial=%v\n", label, time.Since(t0).Round(time.Millisecond))
		return c
	}

	recv := makeConn(recvPriv, "receiver")
	send := makeConn(senderPriv, "sender")

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			msg, err := recv.Recv()
			if err != nil {
				fmt.Printf("  FAIL: receiver Recv: %v\n", err)
				return
			}
			if _, ok := msg.(derp.ReceivedPacket); ok {
				fmt.Printf("  OK  : ping received\n")
				return
			}
			// ServerInfoMessage and other control frames arrive first; skip them.
		}
	}()

	payload := []byte("ping")
	t0 = time.Now()
	if err := send.Send(recvPub, payload); err != nil {
		fmt.Printf("  FAIL: Send: %v\n", err)
		fmt.Printf("─────────────────────────────────────────────────\n")
		log.Fatal("check failed")
	}

	select {
	case <-done:
		fmt.Printf("  OK  : round-trip=%v\n", time.Since(t0).Round(time.Millisecond))
	case <-time.After(10 * time.Second):
		fmt.Printf("  FAIL: timeout waiting for ping\n")
		fmt.Printf("─────────────────────────────────────────────────\n")
		log.Fatal("check failed")
	}

	recv.Close()
	send.Close()
	fmt.Printf("── check PASSED ─────────────────────────────────\n")
}
