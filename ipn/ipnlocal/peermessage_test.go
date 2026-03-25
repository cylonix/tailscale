// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/json"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

func TestResolvePeerByRefMatchesSelfNode(t *testing.T) {
	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			StableID:             "self-stable",
			Name:                 "m1.vital-skylark.cylonix.org.",
			ComputedName:         "m1",
			ComputedNameWithHost: "m1.vital-skylark.cylonix.org",
		}).View(),
	}

	tests := []string{
		"self-stable",
		"m1.vital-skylark.cylonix.org",
		"m1.vital-skylark.cylonix.org.",
		"m1",
	}

	for _, ref := range tests {
		t.Run(ref, func(t *testing.T) {
			got, err := resolvePeerByRef(nm, ref)
			if err != nil {
				t.Fatalf("resolvePeerByRef(%q): %v", ref, err)
			}
			if got.StableID() != nm.SelfNode.StableID() {
				t.Fatalf("resolvePeerByRef(%q) got %q, want %q", ref, got.StableID(), nm.SelfNode.StableID())
			}
		})
	}
}

func TestPeerMessageMenuOptionsJSONRoundTrip(t *testing.T) {
	msg := PeerMessage{
		ID:             "msg-1",
		ConversationID: "peer.example.ts.net",
		Role:           "user",
		Kind:           "menu_request",
		Text:           "Choose one",
		CreatedAt:      "2026-03-24T12:00:00Z",
		MenuOptions: []any{
			map[string]any{
				"id":     "approve",
				"title":  "Approve",
				"action": "approve",
			},
			map[string]any{
				"id":     "reject",
				"title":  "Reject",
				"action": "reject",
			},
		},
	}

	wire, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	options, ok := decoded["menu_options"].([]any)
	if !ok {
		t.Fatalf("menu_options missing or wrong type: %#v", decoded["menu_options"])
	}
	if len(options) != 2 {
		t.Fatalf("got %d menu options, want 2", len(options))
	}
}
