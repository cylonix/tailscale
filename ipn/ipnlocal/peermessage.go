// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/atomicfile"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/util/httpm"
)

type PeerMessage struct {
	ID              string         `json:"id"`
	ConversationID  string         `json:"conversation_id"`
	Role            string         `json:"role"`
	Kind            string         `json:"kind"`
	DeliveryStatus  string         `json:"delivery_status"`
	Text            string         `json:"text"`
	CreatedAt       string         `json:"created_at"`
	ApprovalID      string         `json:"approval_id,omitempty"`
	ApprovalActions []any          `json:"approval_actions,omitempty"`
	MenuOptions     []any          `json:"menu_options,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

// PeerMessageOutgoingAttachment describes one staged local file that must be
// pushed to the peer over Taildrop before the message itself is delivered.
// The Path must remain readable by this process until delivery succeeds (the
// app stages attachments into a daemon-readable location before sending).
type PeerMessageOutgoingAttachment struct {
	TransferID   string `json:"transfer_id"`
	Name         string `json:"name"`
	Path         string `json:"path"`
	DeclaredSize int64  `json:"declared_size,omitempty"`
}

type PeerMessageTransportPayload struct {
	PeerID            string      `json:"peer_id,omitempty"`
	PeerName          string      `json:"peer_name,omitempty"`
	ConversationID    string      `json:"conversation_id"`
	ConversationTitle string      `json:"conversation_title,omitempty"`
	Subtitle          string      `json:"subtitle,omitempty"`
	DeliveryPolicy    string      `json:"delivery_policy,omitempty"`
	Message           PeerMessage `json:"message"`
	// OutgoingAttachments is local-only state for the sender's outbound
	// queue; it is stripped from the payload before the wire send.
	OutgoingAttachments []PeerMessageOutgoingAttachment `json:"outgoing_attachments,omitempty"`
}

type PeerMessageSendResult struct {
	Accepted       bool   `json:"accepted"`
	Queued         bool   `json:"queued,omitempty"`
	DeliveryStatus string `json:"delivery_status"`
	MessageID      string `json:"message_id,omitempty"`
}

// Signals are small, latest-wins notifications exchanged between daemons
// outside the persisted message queue: never stored on disk, never retried
// behind messages. Today only read receipts use them.
const (
	peerMessageSignalPath    = "/v0/peer-message/signal"
	peerMessageSignalTimeout = 5 * time.Second

	PeerMessageSignalTypeRead = "read"
)

// PeerMessageSignal is the wire form of a signal posted to a peer's
// peerMessageSignalPath.
type PeerMessageSignal struct {
	Type string `json:"type"`
	// ConversationID is the sender's conversation id for the peer. The
	// receiver keys the conversation by the sending peer instead, so this is
	// informational.
	ConversationID string `json:"conversation_id,omitempty"`
	// UpToMessageID is the newest message the reader has seen; everything
	// the sender wrote before it in the conversation counts as read.
	UpToMessageID string `json:"up_to_message_id,omitempty"`
	At            string `json:"at,omitempty"`
}

// PeerMessageReadReceipt is the LocalAPI request asking the daemon to tell
// PeerRef that we have read its messages up to UpToMessageID.
type PeerMessageReadReceipt struct {
	PeerRef        string `json:"peer_ref"`
	ConversationID string `json:"conversation_id,omitempty"`
	UpToMessageID  string `json:"up_to_message_id"`
}

var errPeerMessageSignalUnsupported = fmt.Errorf("peer does not support peer-message signals")

type PeerMessageEvent struct {
	Version        string         `json:"version"`
	Type           string         `json:"type"`
	ConversationID string         `json:"conversation_id"`
	MessageID      string         `json:"message_id,omitempty"`
	Timestamp      string         `json:"timestamp"`
	Payload        map[string]any `json:"payload"`
}

var PeerMessageEventSink func(PeerMessageEvent) error

// PeerMessageFileSender is set by feature/taildrop to push one staged
// peer-message attachment to a peer over Taildrop (with outgoing-file
// progress reporting). It stays nil when the taildrop feature is not linked
// in, in which case attachment sends fail with an explicit error.
var PeerMessageFileSender func(ctx context.Context, lb *LocalBackend, peer tailcfg.NodeView, file PeerMessageOutgoingAttachment) error

const (
	peerMessageDeliveryPolicyDrop  = "drop"
	peerMessageDeliveryPolicyQueue = "queue"

	peerMessageQueueStateStoreKey ipn.StateKey = "_peerMessageOutboundQueue"
	peerMessageQueueTick                       = 30 * time.Second

	// peerMessageQueueMaxBackoff caps the per-entry retry backoff.
	peerMessageQueueMaxBackoff = 5 * time.Minute
	// peerMessageQueueEntryTTL is how long an entry may wait for delivery
	// before the queue gives up and emits a "failed" delivery update.
	peerMessageQueueEntryTTL = 24 * time.Hour
	// peerMessageQueueMaxEntries bounds the per-profile queue; sends beyond
	// it are rejected so the caller can surface an immediate failure.
	peerMessageQueueMaxEntries = 200
	// peerMessageQueueEntryTimeout bounds a single delivery attempt,
	// including any attachment uploads.
	peerMessageQueueEntryTimeout = 10 * time.Minute
)

type peerMessageQueueEntry struct {
	PeerRef       string                      `json:"peer_ref"`
	Payload       PeerMessageTransportPayload `json:"payload"`
	QueuedAt      string                      `json:"queued_at"`
	LastAttemptAt string                      `json:"last_attempt_at,omitempty"`
	NextAttemptAt string                      `json:"next_attempt_at,omitempty"`
	LastError     string                      `json:"last_error,omitempty"`
	AttemptCount  int                         `json:"attempt_count"`
	// SentAttachments lists Payload.OutgoingAttachments transfer IDs that
	// were already delivered, so retries only resend what's missing.
	SentAttachments []string `json:"sent_attachments,omitempty"`
}

type peerMessageQueueWorker struct {
	signal chan struct{}
	// urgent, when set before a signal, makes the next flush ignore
	// per-entry retry backoff — used when network conditions changed
	// (link change, warm-ping recovery) rather than time passing.
	urgent atomic.Bool
}

var peerMessageQueueWorkers sync.Map

func init() {
	RegisterPeerAPIHandler("/v0/peer-message/message", handlePeerMessage)
	RegisterPeerAPIHandler(peerMessageSignalPath, handlePeerMessageSignal)
}

func (b *LocalBackend) SendPeerMessage(ctx context.Context, peerRef string, payload PeerMessageTransportPayload) (*PeerMessageSendResult, error) {
	b.ensurePeerMessageQueueWorker()
	policy := normalizePeerMessageDeliveryPolicy(payload.DeliveryPolicy)

	if policy == peerMessageDeliveryPolicyQueue {
		// Queue policy always enqueues, even when the peer looks reachable:
		// it preserves per-peer FIFO ordering (a new message must never
		// overtake an older queued one), and it keeps large attachment
		// uploads off the caller's request timeout. The worker is signaled
		// immediately, so an online peer still sees near-instant delivery;
		// the sender's UI is flipped to "delivered" by the
		// message_delivery_update event the flush emits.
		if err := b.enqueuePeerMessage(peerRef, payload, nil); err != nil {
			return nil, err
		}
		return &PeerMessageSendResult{
			Accepted:       true,
			Queued:         true,
			DeliveryStatus: "pending",
			MessageID:      payload.Message.ID,
		}, nil
	}

	// Drop policy: one immediate attempt, no retry.
	if len(payload.OutgoingAttachments) > 0 {
		return nil, fmt.Errorf("outgoing attachments require the queue delivery policy")
	}
	nm := b.NetMap()
	if nm == nil {
		return nil, fmt.Errorf("no network map available")
	}
	peer, err := resolvePeerByRef(nm, peerRef)
	if err != nil {
		return nil, err
	}
	if err := b.sendPeerMessageNow(ctx, nm, peer, peerRef, payload); err != nil {
		return nil, err
	}
	return &PeerMessageSendResult{
		Accepted:       true,
		DeliveryStatus: "delivered",
		MessageID:      payload.Message.ID,
	}, nil
}

func (b *LocalBackend) sendPeerMessageNow(ctx context.Context, nm *netmap.NetworkMap, peer tailcfg.NodeView, peerRef string, payload PeerMessageTransportPayload) error {
	base := peerAPIBase(nm, peer)
	if base == "" {
		return fmt.Errorf("peer %q does not expose peerapi", peerRef)
	}

	// OutgoingAttachments carries sender-local file paths for the outbound
	// queue; the receiver learns about attachments from the message metadata
	// and the Taildrop transfers themselves.
	payload.OutgoingAttachments = nil
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal peerMessage payload: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		httpm.POST,
		base+"/v0/peer-message/message",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("create peerapi request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: b.Dialer().PeerAPITransport(),
		Timeout:   15 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send peerMessage peerapi request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("peerapi send failed: status=%d body=%s", resp.StatusCode, string(msg))
	}
	return nil
}

func normalizePeerMessageDeliveryPolicy(policy string) string {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "", peerMessageDeliveryPolicyDrop:
		return peerMessageDeliveryPolicyDrop
	case peerMessageDeliveryPolicyQueue:
		return peerMessageDeliveryPolicyQueue
	default:
		return peerMessageDeliveryPolicyDrop
	}
}

func (b *LocalBackend) ensurePeerMessageQueueWorker() {
	worker := &peerMessageQueueWorker{
		signal: make(chan struct{}, 1),
	}
	actual, loaded := peerMessageQueueWorkers.LoadOrStore(b, worker)
	if loaded {
		return
	}
	b.goTracker.Go(func() {
		b.runPeerMessageQueueWorker(actual.(*peerMessageQueueWorker))
	})
}

func (b *LocalBackend) runPeerMessageQueueWorker(worker *peerMessageQueueWorker) {
	ticker := time.NewTicker(peerMessageQueueTick)
	defer ticker.Stop()
	defer peerMessageQueueWorkers.Delete(b)

	_ = b.flushPeerMessageQueue(b.ctx, false)

	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			_ = b.flushPeerMessageQueue(b.ctx, false)
		case <-worker.signal:
			_ = b.flushPeerMessageQueue(b.ctx, worker.urgent.Swap(false))
		}
	}
}

// PeerMessageLogf exposes the backend logger to Cylonix feature hooks such
// as feature/taildrop's peer-message attachment sender.
func (b *LocalBackend) PeerMessageLogf(format string, args ...any) {
	b.logf(format, args...)
}

// signalPeerMessageQueueFlush nudges the queue worker (if running) to attempt
// a flush now. urgent additionally overrides per-entry retry backoff and is
// meant for "conditions changed" triggers (link change, warm-ping recovery)
// as opposed to a new message being enqueued.
func (b *LocalBackend) signalPeerMessageQueueFlush(urgent bool) {
	if w, ok := peerMessageQueueWorkers.Load(b); ok {
		worker := w.(*peerMessageQueueWorker)
		if urgent {
			worker.urgent.Store(true)
		}
		select {
		case worker.signal <- struct{}{}:
		default:
		}
	}
}

func (b *LocalBackend) enqueuePeerMessage(peerRef string, payload PeerMessageTransportPayload, cause error) error {
	err := func() error {
		b.mu.Lock()
		defer b.mu.Unlock()
		entries, err := b.readPeerMessageQueueLocked()
		if err != nil {
			return fmt.Errorf("read peerMessage queue: %w", err)
		}
		if len(entries) >= peerMessageQueueMaxEntries {
			return fmt.Errorf("peer-message queue is full (%d messages waiting to be sent)", len(entries))
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		entry := peerMessageQueueEntry{
			PeerRef:  peerRef,
			Payload:  payload,
			QueuedAt: now,
		}
		if cause != nil {
			entry.LastAttemptAt = now
			entry.LastError = cause.Error()
			entry.AttemptCount = 1
		}
		entries = append(entries, entry)
		if err := b.writePeerMessageQueueLocked(entries); err != nil {
			return fmt.Errorf("write peerMessage queue: %w", err)
		}
		return nil
	}()
	if err != nil {
		return err
	}
	b.signalPeerMessageQueueFlush(false)
	return nil
}

// nextPeerMessageRetryDelay returns the backoff before the next retry after
// attempts failed delivery attempts: 30s, 1m, 2m, 4m, then capped at 5m.
func nextPeerMessageRetryDelay(attempts int) time.Duration {
	d := peerMessageQueueTick
	for i := 1; i < attempts && d < peerMessageQueueMaxBackoff; i++ {
		d *= 2
	}
	return min(d, peerMessageQueueMaxBackoff)
}

func markPeerMessageAttempt(entry *peerMessageQueueEntry, now time.Time, cause error) {
	entry.AttemptCount++
	entry.LastAttemptAt = now.UTC().Format(time.RFC3339Nano)
	entry.NextAttemptAt = now.Add(nextPeerMessageRetryDelay(entry.AttemptCount)).UTC().Format(time.RFC3339Nano)
	entry.LastError = cause.Error()
}

func (b *LocalBackend) flushPeerMessageQueue(ctx context.Context, ignoreBackoff bool) error {
	entries, profileID, err := b.readPeerMessageQueue()
	if err != nil || len(entries) == 0 {
		return err
	}
	processed := len(entries)
	now := time.Now()
	nm := b.NetMap()

	remaining := make([]peerMessageQueueEntry, 0, len(entries))
	// Peers whose oldest pending entry couldn't be delivered this round.
	// Their newer entries are carried over untouched so per-peer FIFO
	// ordering is preserved.
	blocked := make(map[string]bool)
	dirty := false

	for _, entry := range entries {
		ref := normalizePeerRef(entry.PeerRef)

		// Expire first so a permanently unreachable peer can't grow the
		// queue without bound.
		queuedAt, timeErr := time.Parse(time.RFC3339Nano, entry.QueuedAt)
		if timeErr == nil && now.Sub(queuedAt) > peerMessageQueueEntryTTL {
			reason := "message expired before it could be delivered"
			if entry.LastError != "" {
				reason += ": " + entry.LastError
			}
			b.logf("peermessage: giving up on message %q to %q after %d attempts",
				entry.Payload.Message.ID, entry.PeerRef, entry.AttemptCount)
			_ = b.emitPeerMessageDeliveryUpdate(entry.Payload, "failed", reason)
			dirty = true
			continue
		}

		if blocked[ref] {
			remaining = append(remaining, entry)
			continue
		}
		if !ignoreBackoff {
			if next, err := time.Parse(time.RFC3339Nano, entry.NextAttemptAt); err == nil && now.Before(next) {
				blocked[ref] = true
				remaining = append(remaining, entry)
				continue
			}
		}
		if nm == nil {
			// Nothing is sendable without a netmap; don't burn attempts.
			remaining = append(remaining, entry)
			continue
		}

		peer, resolveErr := resolvePeerByRef(nm, entry.PeerRef)
		if resolveErr != nil {
			markPeerMessageAttempt(&entry, now, resolveErr)
			blocked[ref] = true
			remaining = append(remaining, entry)
			dirty = true
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, peerMessageQueueEntryTimeout)
		sendErr := b.sendQueuedPeerMessage(attemptCtx, nm, peer, &entry)
		cancel()
		if sendErr != nil {
			b.logf("peermessage: send of %q to %q failed (attempt %d): %v",
				entry.Payload.Message.ID, entry.PeerRef, entry.AttemptCount+1, sendErr)
			markPeerMessageAttempt(&entry, now, sendErr)
			blocked[ref] = true
			remaining = append(remaining, entry)
			dirty = true
			continue
		}
		dirty = true
		_ = b.emitPeerMessageDeliveryUpdate(entry.Payload, "delivered", "")
	}

	if !dirty {
		// Every entry was merely waiting (backoff or no netmap); skip the
		// rewrite so idle ticks don't churn the file.
		return nil
	}
	return b.commitPeerMessageQueue(profileID, processed, remaining)
}

// sendQueuedPeerMessage delivers one queue entry: outstanding attachments
// first (recording per-file progress in entry.SentAttachments), then the
// message itself.
func (b *LocalBackend) sendQueuedPeerMessage(ctx context.Context, nm *netmap.NetworkMap, peer tailcfg.NodeView, entry *peerMessageQueueEntry) error {
	if len(entry.Payload.OutgoingAttachments) > 0 {
		if PeerMessageFileSender == nil {
			return fmt.Errorf("peer-message attachments unsupported: taildrop unavailable")
		}
		sent := make(map[string]bool, len(entry.SentAttachments))
		for _, id := range entry.SentAttachments {
			sent[id] = true
		}
		for _, file := range entry.Payload.OutgoingAttachments {
			if sent[file.TransferID] {
				continue
			}
			if err := PeerMessageFileSender(ctx, b, peer, file); err != nil {
				return fmt.Errorf("send attachment %q: %w", file.Name, err)
			}
			entry.SentAttachments = append(entry.SentAttachments, file.TransferID)
		}
	}
	return b.sendPeerMessageNow(ctx, nm, peer, entry.PeerRef, entry.Payload)
}

// commitPeerMessageQueue atomically replaces the first processed entries of
// the stored queue with remaining, preserving entries appended by concurrent
// enqueues while the flush was sending. If the active profile changed
// mid-flush the write is skipped: the entries still belong to the old
// profile's file, and re-delivery is deduplicated by message ID on the
// receiving side.
func (b *LocalBackend) commitPeerMessageQueue(profileID string, processed int, remaining []peerMessageQueueEntry) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if string(b.pm.CurrentProfile().ID()) != profileID {
		b.logf("peermessage: profile changed during queue flush; skipping commit")
		return nil
	}
	current, err := b.readPeerMessageQueueLocked()
	if err != nil {
		return fmt.Errorf("re-read peerMessage queue: %w", err)
	}
	processed = min(processed, len(current))
	merged := append(remaining, current[processed:]...)
	if err := b.writePeerMessageQueueLocked(merged); err != nil {
		return fmt.Errorf("write peerMessage queue: %w", err)
	}
	return nil
}

// peerMessageProfileID returns the active login profile's ID so emitted
// PeerMessageEvents can be filed under the right profile on the app side. The
// app keys peer-message history by profile; without this stamp it falls back
// to a by-conversation-id lookup that mis-files events under a stale profile
// after the same account is re-added (new profile, same conversations).
func (b *LocalBackend) peerMessageProfileID() string {
	return string(b.CurrentProfile().ID())
}

func (b *LocalBackend) emitPeerMessageDeliveryUpdate(payload PeerMessageTransportPayload, deliveryStatus, failureMessage string) error {
	message := map[string]any{
		"id":              payload.Message.ID,
		"conversation_id": payload.Message.ConversationID,
		"delivery_status": deliveryStatus,
	}
	eventPayload := map[string]any{
		"profile_id":      b.peerMessageProfileID(),
		"conversation_id": payload.ConversationID,
		"delivery_status": deliveryStatus,
		"message_id":      payload.Message.ID,
		"message":         message,
	}
	if failureMessage != "" {
		message["failure_message"] = failureMessage
		eventPayload["failure_message"] = failureMessage
	}
	event := PeerMessageEvent{
		Version:        "v1",
		Type:           "message_delivery_update",
		ConversationID: payload.ConversationID,
		MessageID:      payload.Message.ID,
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		Payload:        eventPayload,
	}
	if PeerMessageEventSink != nil {
		return PeerMessageEventSink(event)
	}
	// No event sink registered (daemon mode) — broadcast via watch-ipn-bus
	b.send(ipn.Notify{PeerMessageEvent: event})
	return nil
}

// peerMessageQueuePathLocked returns the current profile's queue file path,
// or "" when file storage is unavailable (no active profile, or no writable
// var root) and the StateStore fallback must be used instead. The file lives
// outside the StateStore because on Apple platforms the store is backed by
// the data-protection keychain, which is a poor fit for a growing queue of
// message payloads.
// b.mu must be held.
func (b *LocalBackend) peerMessageQueuePathLocked() string {
	id := b.pm.CurrentProfile().ID()
	if id == "" {
		return ""
	}
	dir := b.profileDataPathLocked(id, "peer-message-queue")
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "outbound.json")
}

func (b *LocalBackend) readPeerMessageQueue() ([]peerMessageQueueEntry, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entries, err := b.readPeerMessageQueueLocked()
	return entries, string(b.pm.CurrentProfile().ID()), err
}

func (b *LocalBackend) readPeerMessageQueueLocked() ([]peerMessageQueueEntry, error) {
	if b.pm.CurrentProfile().ID() == "" {
		return nil, nil
	}
	path := b.peerMessageQueuePathLocked()
	if path == "" {
		return b.readPeerMessageQueueFromStoreLocked()
	}
	bs, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// One-time migration from the legacy StateStore location.
		entries, storeErr := b.readPeerMessageQueueFromStoreLocked()
		if storeErr != nil {
			return nil, storeErr
		}
		// Write the file (an empty queue becomes "[]") even when the store
		// had nothing, so idle reads stop consulting the StateStore — on
		// Apple platforms that's a keychain hit per flush tick.
		if writeErr := b.writePeerMessageQueueLocked(entries); writeErr != nil {
			b.logf("peermessage: queue migration to %q failed: %v", path, writeErr)
			return entries, nil
		}
		if len(entries) > 0 {
			key := namespaceKeyForCurrentProfile(b.pm, peerMessageQueueStateStoreKey)
			if err := b.pm.WriteState(key, nil); err != nil {
				b.logf("peermessage: clearing legacy queue state failed: %v", err)
			}
		}
		return entries, nil
	} else if err != nil {
		return nil, err
	}
	if len(bs) == 0 {
		return nil, nil
	}
	var entries []peerMessageQueueEntry
	if err := json.Unmarshal(bs, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (b *LocalBackend) readPeerMessageQueueFromStoreLocked() ([]peerMessageQueueEntry, error) {
	key := namespaceKeyForCurrentProfile(b.pm, peerMessageQueueStateStoreKey)
	bs, err := b.pm.Store().ReadState(key)
	if err != nil {
		if errors.Is(err, ipn.ErrStateNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if len(bs) == 0 {
		return nil, nil
	}
	var entries []peerMessageQueueEntry
	if err := json.Unmarshal(bs, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (b *LocalBackend) writePeerMessageQueueLocked(entries []peerMessageQueueEntry) error {
	id := b.pm.CurrentProfile().ID()
	if id == "" {
		return nil
	}
	path := b.peerMessageQueuePathLocked()
	if path == "" {
		key := namespaceKeyForCurrentProfile(b.pm, peerMessageQueueStateStoreKey)
		if len(entries) == 0 {
			return b.pm.WriteState(key, nil)
		}
		bs, err := json.Marshal(entries)
		if err != nil {
			return err
		}
		return b.pm.WriteState(key, bs)
	}
	// An empty queue is written as "[]" rather than removing the file: a
	// missing file routes reads through the legacy StateStore migration
	// path, which on Apple platforms means a keychain read on every idle
	// flush tick.
	if entries == nil {
		entries = []peerMessageQueueEntry{}
	}
	bs, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if _, err := b.profileMkdirAllLocked(id, "peer-message-queue"); err != nil {
		return err
	}
	return atomicfile.WriteFile(path, bs, 0600)
}

func resolvePeerByRef(nm *netmap.NetworkMap, peerRef string) (tailcfg.NodeView, error) {
	ref := normalizePeerRef(peerRef)
	if ref == "" {
		return tailcfg.NodeView{}, fmt.Errorf("missing peer reference")
	}

	var exactMatches []tailcfg.NodeView
	if self := nm.SelfNode; self.Valid() && matchesPeerRef(self, ref) {
		exactMatches = append(exactMatches, self)
	}
	for _, candidate := range nm.Peers {
		if matchesPeerRef(candidate, ref) {
			exactMatches = append(exactMatches, candidate)
		}
	}
	switch len(exactMatches) {
	case 1:
		return exactMatches[0], nil
	case 0:
		return tailcfg.NodeView{}, fmt.Errorf("peer %q not found", peerRef)
	default:
		return tailcfg.NodeView{}, fmt.Errorf("peer %q is ambiguous; use a full device name or StableNodeID", peerRef)
	}
}

func matchesPeerRef(peer tailcfg.NodeView, ref string) bool {
	return normalizePeerRef(string(peer.StableID())) == ref ||
		normalizePeerRef(peer.Name()) == ref ||
		normalizePeerRef(peer.ComputedName()) == ref ||
		normalizePeerRef(peer.ComputedNameWithHost()) == ref
}

func normalizePeerRef(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func handlePeerMessage(ph PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.POST {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !ph.IsSelfUntagged() {
		http.Error(w, "peerMessage is only allowed for same-user peers", http.StatusForbidden)
		return
	}

	var payload PeerMessageTransportPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid peerMessage payload", http.StatusBadRequest)
		return
	}

	if payload.ConversationID == "" {
		payload.ConversationID = string(ph.Peer().StableID())
	}
	if payload.Message.ConversationID == "" {
		payload.Message.ConversationID = payload.ConversationID
	}
	if payload.Message.CreatedAt == "" {
		payload.Message.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if payload.Message.DeliveryStatus == "" || payload.Message.DeliveryStatus == "pending" {
		// Once the peerapi handler receives the message, it has been accepted for
		// delivery on the recipient side. Keeping "pending" here causes self-sends
		// to overwrite the sender's later "sent" state back to pending.
		payload.Message.DeliveryStatus = "delivered"
	}

	eventType := "message_received"
	switch payload.Message.Kind {
	case "approval_request":
		eventType = "approval_requested"
	case "approval_response":
		eventType = "approval_submitted"
	case "menu_request":
		eventType = "menu_requested"
	case "menu_response":
		eventType = "menu_submitted"
	}

	event := PeerMessageEvent{
		Version:        "v1",
		Type:           eventType,
		ConversationID: payload.ConversationID,
		MessageID:      payload.Message.ID,
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		Payload: map[string]any{
			"profile_id":         ph.LocalBackend().peerMessageProfileID(),
			"conversation_title": payload.ConversationTitle,
			"subtitle":           payload.Subtitle,
			"from_peer_id":       ph.Peer().StableID(),
			"from_peer_name":     ph.Peer().ComputedName(),
			"message":            payload.Message,
		},
	}
	if PeerMessageEventSink != nil {
		if err := PeerMessageEventSink(event); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		// No event sink registered (daemon mode) — broadcast via watch-ipn-bus
		ph.LocalBackend().send(ipn.Notify{PeerMessageEvent: event})
	}

	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, "{}\n")
}

// handlePeerMessageSignal receives a signal from a same-user peer. A read
// receipt becomes a "messages_read" event for the app, which owns the message
// history and flips its own outbound messages to "read".
func handlePeerMessageSignal(ph PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.POST {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !ph.IsSelfUntagged() {
		http.Error(w, "peerMessage signals are only allowed for same-user peers", http.StatusForbidden)
		return
	}
	var signal PeerMessageSignal
	if err := json.NewDecoder(r.Body).Decode(&signal); err != nil {
		http.Error(w, "invalid peerMessage signal", http.StatusBadRequest)
		return
	}
	switch signal.Type {
	case PeerMessageSignalTypeRead:
		if signal.UpToMessageID == "" {
			http.Error(w, "missing up_to_message_id", http.StatusBadRequest)
			return
		}
		b := ph.LocalBackend()
		event := peerMessageReadEvent(b.peerMessageProfileID(), ph.Peer(), signal)
		if PeerMessageEventSink != nil {
			if err := PeerMessageEventSink(event); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			// No event sink registered (daemon mode) — broadcast via watch-ipn-bus
			b.send(ipn.Notify{PeerMessageEvent: event})
		}
	default:
		http.Error(w, "unknown signal type", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, "{}\n")
}

// peerMessageReadEvent builds the app-facing event for a read receipt from
// peer. ConversationID is the reader's stable id: on this side the
// conversation with the reader is keyed by the reader, not by the id the
// reader used for us.
func peerMessageReadEvent(profileID string, peer tailcfg.NodeView, signal PeerMessageSignal) PeerMessageEvent {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	readAt := signal.At
	if readAt == "" {
		readAt = now
	}
	return PeerMessageEvent{
		Version:        "v1",
		Type:           "messages_read",
		ConversationID: string(peer.StableID()),
		MessageID:      signal.UpToMessageID,
		Timestamp:      now,
		Payload: map[string]any{
			"profile_id":       profileID,
			"from_peer_id":     peer.StableID(),
			"from_peer_name":   peer.ComputedName(),
			"up_to_message_id": signal.UpToMessageID,
			"read_at":          readAt,
		},
	}
}

// SendPeerMessageReadReceipt tells receipt.PeerRef that we have read its
// messages up to receipt.UpToMessageID. It returns once the receipt is
// accepted: the send runs in the background with a short timeout and is never
// queued behind messages. An unreachable peer parks the receipt (latest wins,
// one per peer) until the warm loop next reaches it; a peer that answers 404
// predates signals and is skipped for the rest of the session.
func (b *LocalBackend) SendPeerMessageReadReceipt(receipt PeerMessageReadReceipt) error {
	peerRef := strings.TrimSpace(receipt.PeerRef)
	if peerRef == "" {
		return fmt.Errorf("missing peer_ref")
	}
	if receipt.UpToMessageID == "" {
		return fmt.Errorf("missing up_to_message_id")
	}
	signal := PeerMessageSignal{
		Type:           PeerMessageSignalTypeRead,
		ConversationID: receipt.ConversationID,
		UpToMessageID:  receipt.UpToMessageID,
		At:             time.Now().UTC().Format(time.RFC3339Nano),
	}
	m := b.activePeerManager()
	b.goTracker.Go(func() { m.deliverSignal(peerRef, signal) })
	return nil
}

// sendPeerMessageSignal posts one signal to the peer. It reports
// errPeerMessageSignalUnsupported when the peer's daemon predates signals.
func (b *LocalBackend) sendPeerMessageSignal(ctx context.Context, peerRef string, signal PeerMessageSignal) error {
	nm := b.NetMap()
	if nm == nil {
		return fmt.Errorf("no netmap")
	}
	peer, err := resolvePeerByRef(nm, peerRef)
	if err != nil {
		return err
	}
	base := peerAPIBase(nm, peer)
	if base == "" {
		return fmt.Errorf("peer %q does not expose peerapi", peerRef)
	}
	body, err := json.Marshal(signal)
	if err != nil {
		return fmt.Errorf("marshal peerMessage signal: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, peerMessageSignalTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, httpm.POST, base+peerMessageSignalPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create peerapi signal request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Transport: b.Dialer().PeerAPITransport(),
		Timeout:   peerMessageSignalTimeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send peerMessage signal: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return errPeerMessageSignalUnsupported
	default:
		return fmt.Errorf("peerapi signal failed: status=%d", resp.StatusCode)
	}
}
