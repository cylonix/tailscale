// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package localapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/util/httpm"
)

func init() {
	Register("peer-message/send", (*Handler).servePeerMessageSend)
	Register("peer-message/active-peers-stream", (*Handler).servePeerMessageActivePeersStream)
	Register("peer-message/active-peers", (*Handler).servePeerMessageActivePeers)
}

// peerMessageActivePeersStreamReadDeadline is the per-frame read deadline for
// the long-lived active-peers stream. Backup against zombie sockets that don't
// deliver a FIN promptly. The Flutter client sends a heartbeat every 60s.
const peerMessageActivePeersStreamReadDeadline = 90 * time.Second

func (h *Handler) servePeerMessageSend(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "want POST", http.StatusMethodNotAllowed)
		return
	}

	var payload ipnlocal.PeerMessageTransportPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	peerRef := payload.PeerID
	if peerRef == "" {
		peerRef = payload.PeerName
	}
	if peerRef == "" {
		peerRef = payload.ConversationID
	}
	peerRef = strings.TrimSpace(peerRef)
	if peerRef == "" {
		http.Error(w, "missing peer_id, peer_name, or conversation_id", http.StatusBadRequest)
		return
	}

	result, err := h.b.SendPeerMessage(r.Context(), peerRef, payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// servePeerMessageActivePeersStream is a long-lived chunked POST. The client
// streams NDJSON updates of which peers should be kept warm. When the client
// disconnects (graceful close, app crash, network drop, etc.), Decode returns
// an error and the deferred session.Close releases the daemon's claim on those
// peers — so warm goroutines stop within milliseconds of the client going away.
//
// Frame format:
//
//	{"peer_ids": ["<ref>", "<ref>"]}   # replace claimed set
//	{"heartbeat": true}                # no-op; refreshes the read deadline
func (h *Handler) servePeerMessageActivePeersStream(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "want POST", http.StatusMethodNotAllowed)
		return
	}

	session := h.b.NewActivePeerSession()
	defer session.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	rc := http.NewResponseController(w)
	dec := json.NewDecoder(r.Body)
	for {
		// Backup deadline: if the OS doesn't deliver a prompt FIN (rare on
		// Unix sockets, more common over named pipes / network blips), the
		// next Decode will return an error and we'll exit + clean up.
		_ = rc.SetReadDeadline(time.Now().Add(peerMessageActivePeersStreamReadDeadline))

		var msg struct {
			PeerIDs   []string `json:"peer_ids,omitempty"`
			Heartbeat bool     `json:"heartbeat,omitempty"`
		}
		if err := dec.Decode(&msg); err != nil {
			return
		}
		if !msg.Heartbeat {
			session.Set(msg.PeerIDs)
		}
	}
}

// servePeerMessageActivePeers is the one-shot variant for callers that can't
// hold a streaming connection (e.g. in-process libtailscale on Android/Apple
// using JSON-over-method-channel). The backend stores a single "global"
// session that auto-clears after a few minutes if no further calls arrive,
// so the caller is responsible for periodic heartbeat POSTs to keep peers warm.
//
//	POST   body {"peer_ids": ["..."]}   replace global set, refresh deadline
//	DELETE                              clear global set immediately
func (h *Handler) servePeerMessageActivePeers(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	switch r.Method {
	case httpm.POST:
		var msg struct {
			PeerIDs []string `json:"peer_ids,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
		h.b.SetGlobalActivePeers(msg.PeerIDs)
		w.WriteHeader(http.StatusOK)
	case httpm.DELETE:
		h.b.ClearGlobalActivePeers()
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "want POST or DELETE", http.StatusMethodNotAllowed)
	}
}
