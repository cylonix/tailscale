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
	xrayMode    := flag.String("xray-mode", "stream-up", "xhttp upload mode: stream-up or packet-up")
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

	// Connect receiver first so it is registered before sender sends.
	recv   := newClient(recvPriv, "receiver")
	sender := newClient(senderPriv, "sender")

	var rxBytes atomic.Int64

	// Receiver goroutine.
	go func() {
		for {
			msg, err := recv.Recv()
			if err != nil {
				return
			}
			if pkt, ok := msg.(derp.ReceivedPacket); ok {
				rxBytes.Add(int64(len(pkt.Data)))
			}
		}
	}()

	// Give receiver goroutine a moment to start.
	time.Sleep(100 * time.Millisecond)

	payload := make([]byte, *msgSize)

	fmt.Printf("Sending %d-byte packets for %v...\n", *msgSize, *duration)
	start    := time.Now()
	deadline := start.Add(*duration)

	var txBytes int64
	var sendErrs int
	for time.Now().Before(deadline) {
		if err := sender.Send(recvPub, payload); err != nil {
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
	fmt.Printf("  TX       : %.1f MB  →  %.1f Mbps\n", float64(txBytes)/1e6, txMbps)
	fmt.Printf("  RX       : %.1f MB  →  %.1f Mbps\n", float64(rxTotal)/1e6, rxMbps)
	if sendErrs > 0 {
		fmt.Printf("  SendErrs : %d\n", sendErrs)
	}
	fmt.Printf("─────────────────────────────────────────────────\n")

	recv.Close()
	sender.Close()
}
