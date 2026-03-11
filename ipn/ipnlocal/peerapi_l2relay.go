// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"tailscale.com/ipn/l2relay"
)

func init() {
	RegisterPeerAPIHandler("/v0/l2relay/hello", handleHello)
	RegisterPeerAPIHandler("/v0/l2relay/leader", handleLeader)
	RegisterPeerAPIHandler("/v0/l2relay/envelope", handleEnvelope)
	RegisterPeerAPIHandler("/v0/l2relay/proxy/tcp", handleProxyTCP)
}

func handleHello(h PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var msg l2relay.Hello
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	relay := h.LocalBackend().l2Relay
	if relay != nil {
		relay.HandleHello(h.Peer(), msg)
	}
	w.WriteHeader(http.StatusNoContent)
}

func handleLeader(h PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var msg l2relay.Leader
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	relay := h.LocalBackend().l2Relay
	if relay != nil {
		if err := relay.HandleLeader(h.Peer(), msg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func handleEnvelope(h PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(l2relay.MaxSize*2)))
	if err != nil || len(raw) == 0 {
		http.Error(w, "bad envelope", http.StatusBadRequest)
		return
	}
	relay := h.LocalBackend().l2Relay
	if relay != nil {
		if err := relay.HandleIncomingEnvelope(h.RemoteAddr(), selfAddr(h), raw); err != nil {
			if errors.Is(err, l2relay.ErrInternalErr) {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			} else {
				http.Error(w, "bad envelope: "+err.Error(), http.StatusBadRequest)
			}
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func handleProxyTCP(h PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	target := strings.TrimSpace(r.Header.Get("Tailscale-L2Relay-Target"))
	relay := h.LocalBackend().l2Relay
	if relay != nil {
		if err := relay.ProxyTCP(h.Peer(), target, h.RemoteAddr().Addr(), selfAddr(h), w); err != nil {
			if errors.Is(err, l2relay.ErrInternalErr) {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			} else {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
			return
		}
	}
}

func selfAddr(h PeerAPIHandler) (self netip.Addr) {
	peer := h.RemoteAddr()
	if !peer.IsValid() {
		return
	}
	selfPfx := h.Self().Addresses()
	for i := 0; i < selfPfx.Len(); i++ {
		p := selfPfx.At(i)
		if p.IsSingleIP() && p.Addr().BitLen() == peer.Addr().BitLen() {
			self = p.Addr()
			break
		}
	}
	return
}
