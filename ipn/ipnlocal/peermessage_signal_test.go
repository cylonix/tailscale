// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"

	"tailscale.com/tailcfg"
)

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
