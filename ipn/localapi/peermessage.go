// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package localapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"tailscale.com/ipn/ipnlocal"
)

func init() {
	Register("peer-message/send", (*Handler).servePeerMessageSend)
}

func (h *Handler) servePeerMessageSend(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
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

	if err := h.b.SendPeerMessage(r.Context(), peerRef, payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}\n"))
}
