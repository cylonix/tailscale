// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

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

func TestNextPeerMessageRetryDelay(t *testing.T) {
	tests := []struct {
		attempts int
		want     time.Duration
	}{
		{0, 30 * time.Second},
		{1, 30 * time.Second},
		{2, time.Minute},
		{3, 2 * time.Minute},
		{4, 4 * time.Minute},
		{5, 5 * time.Minute},
		{20, 5 * time.Minute},
	}
	for _, tt := range tests {
		if got := nextPeerMessageRetryDelay(tt.attempts); got != tt.want {
			t.Errorf("nextPeerMessageRetryDelay(%d) = %v, want %v", tt.attempts, got, tt.want)
		}
	}
}

func TestMarkPeerMessageAttempt(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	entry := peerMessageQueueEntry{AttemptCount: 1}
	markPeerMessageAttempt(&entry, now, errors.New("peer unreachable"))

	if entry.AttemptCount != 2 {
		t.Errorf("AttemptCount = %d, want 2", entry.AttemptCount)
	}
	if entry.LastError != "peer unreachable" {
		t.Errorf("LastError = %q", entry.LastError)
	}
	if entry.LastAttemptAt != now.Format(time.RFC3339Nano) {
		t.Errorf("LastAttemptAt = %q", entry.LastAttemptAt)
	}
	next, err := time.Parse(time.RFC3339Nano, entry.NextAttemptAt)
	if err != nil {
		t.Fatalf("NextAttemptAt unparseable: %v", err)
	}
	if want := now.Add(time.Minute); !next.Equal(want) {
		t.Errorf("NextAttemptAt = %v, want %v", next, want)
	}
}

func TestPeerMessageQueueEntryJSONRoundTrip(t *testing.T) {
	entry := peerMessageQueueEntry{
		PeerRef: "peer-stable-id",
		Payload: PeerMessageTransportPayload{
			ConversationID: "peer-stable-id",
			DeliveryPolicy: "queue",
			Message:        PeerMessage{ID: "msg-1", Kind: "file"},
			OutgoingAttachments: []PeerMessageOutgoingAttachment{{
				TransferID:   "xfer-1",
				Name:         "photo.jpg",
				Path:         "/shared/peer-messaging/attachments/photo_xfer-1.jpg",
				DeclaredSize: 1234,
			}},
		},
		QueuedAt:        "2026-07-09T12:00:00Z",
		SentAttachments: []string{"xfer-1"},
	}
	wire, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var got peerMessageQueueEntry
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(got.Payload.OutgoingAttachments) != 1 ||
		got.Payload.OutgoingAttachments[0].Path != entry.Payload.OutgoingAttachments[0].Path {
		t.Errorf("OutgoingAttachments did not round-trip: %+v", got.Payload.OutgoingAttachments)
	}
	if len(got.SentAttachments) != 1 || got.SentAttachments[0] != "xfer-1" {
		t.Errorf("SentAttachments did not round-trip: %+v", got.SentAttachments)
	}
}
