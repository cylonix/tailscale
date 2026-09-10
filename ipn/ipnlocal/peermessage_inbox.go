// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/atomicfile"
	"tailscale.com/ipn"
)

// Peer-message events on daemon-mode platforms (macOS direct PKG, Linux,
// Windows) are only broadcast on the watch-ipn-bus; nothing keeps them if
// no app is watching, so a message that arrives while the app is closed
// is lost even though the sender sees it delivered. The Apple NE build
// avoids this with an event queue in the app group that the app replays
// on launch. This inbox is the daemon-mode equivalent: every event the
// daemon broadcasts is also appended here, per profile, and the app
// drains it through LocalAPI peer-message/inbox (GET, then POST
// ?upto=<seq> to acknowledge) at start and on resume. The app
// de-duplicates by message id, so events it already saw live are
// harmless.

const (
	peerMessageInboxFile       = "inbox.json"
	peerMessageInboxMaxEntries = 500
	peerMessageInboxTTL        = 7 * 24 * time.Hour
)

// PeerMessageInboxEntry is one stored event. Seq is monotonic per profile
// so the app can acknowledge everything up to what it has processed.
type PeerMessageInboxEntry struct {
	Seq   uint64           `json:"seq"`
	At    string           `json:"at"`
	Event PeerMessageEvent `json:"event"`
}

type peerMessageInbox struct {
	NextSeq uint64                  `json:"next_seq"`
	Entries []PeerMessageInboxEntry `json:"entries"`
}

// broadcastPeerMessageEvent records the event in the inbox and sends it on
// the bus. Daemon mode only (PeerMessageEventSink == nil); callers must not
// hold b.mu.
func (b *LocalBackend) broadcastPeerMessageEvent(event PeerMessageEvent) {
	b.recordPeerMessageInbox(event)
	b.send(ipn.Notify{PeerMessageEvent: event})
}

// b.mu must be held.
func (b *LocalBackend) peerMessageInboxPathLocked() string {
	id := b.pm.CurrentProfile().ID()
	if id == "" {
		return ""
	}
	dir := b.profileDataPathLocked(id, "peer-message-queue")
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, peerMessageInboxFile)
}

// b.mu must be held.
func (b *LocalBackend) readPeerMessageInboxLocked() (peerMessageInbox, error) {
	var inbox peerMessageInbox
	path := b.peerMessageInboxPathLocked()
	if path == "" {
		return inbox, nil
	}
	bs, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return inbox, nil
	} else if err != nil {
		return inbox, err
	}
	if len(bs) == 0 {
		return inbox, nil
	}
	if err := json.Unmarshal(bs, &inbox); err != nil {
		return peerMessageInbox{}, err
	}
	return inbox, nil
}

// b.mu must be held.
func (b *LocalBackend) writePeerMessageInboxLocked(inbox peerMessageInbox) error {
	id := b.pm.CurrentProfile().ID()
	if id == "" {
		return nil
	}
	path := b.peerMessageInboxPathLocked()
	if path == "" {
		return nil
	}
	if inbox.Entries == nil {
		inbox.Entries = []PeerMessageInboxEntry{}
	}
	bs, err := json.Marshal(inbox)
	if err != nil {
		return err
	}
	if _, err := b.profileMkdirAllLocked(id, "peer-message-queue"); err != nil {
		return err
	}
	return atomicfile.WriteFile(path, bs, 0600)
}

// recordPeerMessageInbox appends an event the daemon is broadcasting.
// Callers must not hold b.mu. Failures are logged, never fatal: the live
// broadcast still happens.
func (b *LocalBackend) recordPeerMessageInbox(event PeerMessageEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inbox, err := b.readPeerMessageInboxLocked()
	if err != nil {
		b.logf("peermessage: inbox read failed, starting over: %v", err)
		inbox = peerMessageInbox{}
	}
	if inbox.NextSeq == 0 {
		inbox.NextSeq = 1
	}
	now := time.Now()
	inbox.Entries = append(inbox.Entries, PeerMessageInboxEntry{
		Seq:   inbox.NextSeq,
		At:    now.UTC().Format(time.RFC3339Nano),
		Event: event,
	})
	inbox.NextSeq++
	inbox.Entries = prunePeerMessageInbox(inbox.Entries, now)
	if err := b.writePeerMessageInboxLocked(inbox); err != nil {
		b.logf("peermessage: inbox write failed: %v", err)
	}
}

// prunePeerMessageInbox drops entries older than the TTL and keeps the
// newest peerMessageInboxMaxEntries, so an app that never acknowledges
// (a platform without the replay path) cannot grow the file unbounded.
func prunePeerMessageInbox(entries []PeerMessageInboxEntry, now time.Time) []PeerMessageInboxEntry {
	cutoff := now.Add(-peerMessageInboxTTL)
	kept := entries[:0]
	for _, e := range entries {
		if at, err := time.Parse(time.RFC3339Nano, e.At); err == nil && at.Before(cutoff) {
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) > peerMessageInboxMaxEntries {
		kept = kept[len(kept)-peerMessageInboxMaxEntries:]
	}
	return kept
}

// PeerMessageInbox returns the stored events not yet acknowledged, oldest
// first.
func (b *LocalBackend) PeerMessageInbox() ([]PeerMessageInboxEntry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	inbox, err := b.readPeerMessageInboxLocked()
	if err != nil {
		return nil, err
	}
	return inbox.Entries, nil
}

// AckPeerMessageInbox drops every stored event with Seq <= upto.
func (b *LocalBackend) AckPeerMessageInbox(upto uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	inbox, err := b.readPeerMessageInboxLocked()
	if err != nil {
		return err
	}
	kept := make([]PeerMessageInboxEntry, 0, len(inbox.Entries))
	for _, e := range inbox.Entries {
		if e.Seq > upto {
			kept = append(kept, e)
		}
	}
	if len(kept) == len(inbox.Entries) {
		return nil
	}
	inbox.Entries = kept
	return b.writePeerMessageInboxLocked(inbox)
}
