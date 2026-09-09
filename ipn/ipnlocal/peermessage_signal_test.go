// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

func TestNextSignalRetryDelay(t *testing.T) {
	tests := []struct {
		attempts int
		want     time.Duration
	}{
		{0, 15 * time.Second},
		{1, 15 * time.Second},
		{2, 30 * time.Second},
		{3, time.Minute},
		{4, 2 * time.Minute},
		{5, 4 * time.Minute},
		{6, 5 * time.Minute},
		{60, 5 * time.Minute}, // capped, never overflows
	}
	for _, tt := range tests {
		if got := nextSignalRetryDelay(tt.attempts); got != tt.want {
			t.Errorf("nextSignalRetryDelay(%d) = %v, want %v", tt.attempts, got, tt.want)
		}
	}
}

func TestPeerMessageReadEvent(t *testing.T) {
	reader := (&tailcfg.Node{
		StableID:     "reader-stable",
		Name:         "iphone.example.ts.net.",
		ComputedName: "iphone",
	}).View()
	signal := PeerMessageSignal{
		Type:           PeerMessageSignalTypeRead,
		ConversationID: "laptop-stable", // the reader's id for us; not ours for them
		UpToMessageID:  "msg-42",
		At:             "2026-09-05T10:00:00Z",
	}
	ev := peerMessageReadEvent("profile-1", reader, signal)

	if ev.Type != "messages_read" {
		t.Errorf("Type = %q, want messages_read", ev.Type)
	}
	// The conversation must be keyed by the reader, not by the id the
	// reader used to address us.
	if ev.ConversationID != "reader-stable" {
		t.Errorf("ConversationID = %q, want reader-stable", ev.ConversationID)
	}
	if ev.MessageID != "msg-42" {
		t.Errorf("MessageID = %q, want msg-42", ev.MessageID)
	}
	if got := ev.Payload["up_to_message_id"]; got != "msg-42" {
		t.Errorf("up_to_message_id = %v, want msg-42", got)
	}
	if got := ev.Payload["read_at"]; got != "2026-09-05T10:00:00Z" {
		t.Errorf("read_at = %v, want the signal's timestamp", got)
	}
	if got := ev.Payload["from_peer_name"]; got != "iphone" {
		t.Errorf("from_peer_name = %v, want iphone", got)
	}

	// Without a timestamp the daemon stamps the receipt itself.
	signal.At = ""
	if got := peerMessageReadEvent("profile-1", reader, signal).Payload["read_at"]; got == "" {
		t.Error("read_at empty when the signal carried no timestamp")
	}
}
