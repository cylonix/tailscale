// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package localapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/util/httpm"
)

func init() {
	Register("peer-message/inbox", (*Handler).servePeerMessageInbox)
}

// servePeerMessageInbox lets the app catch up on peer-message events the
// daemon broadcast while no app was watching the bus (see
// ipnlocal.PeerMessageInboxEntry). GET returns the stored events, oldest
// first, as {"entries": [...]}; POST ?upto=<seq> acknowledges them so they
// are dropped.
func (h *Handler) servePeerMessageInbox(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case httpm.GET:
		if !h.PermitRead {
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}
		entries, err := h.b.PeerMessageInbox()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if entries == nil {
			entries = []ipnlocal.PeerMessageInboxEntry{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"entries": entries})
	case httpm.POST:
		if !h.PermitWrite {
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}
		upto, err := strconv.ParseUint(r.URL.Query().Get("upto"), 10, 64)
		if err != nil {
			http.Error(w, "invalid upto", http.StatusBadRequest)
			return
		}
		if err := h.b.AckPeerMessageInbox(upto); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}\n"))
	default:
		http.Error(w, "want GET or POST", http.StatusMethodNotAllowed)
	}
}
