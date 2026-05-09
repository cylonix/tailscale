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
	"strings"
	"sync"
	"time"

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

type PeerMessageTransportPayload struct {
	PeerID            string      `json:"peer_id,omitempty"`
	PeerName          string      `json:"peer_name,omitempty"`
	ConversationID    string      `json:"conversation_id"`
	ConversationTitle string      `json:"conversation_title,omitempty"`
	Subtitle          string      `json:"subtitle,omitempty"`
	DeliveryPolicy    string      `json:"delivery_policy,omitempty"`
	Message           PeerMessage `json:"message"`
}

type PeerMessageSendResult struct {
	Accepted       bool   `json:"accepted"`
	Queued         bool   `json:"queued,omitempty"`
	DeliveryStatus string `json:"delivery_status"`
	MessageID      string `json:"message_id,omitempty"`
}

type PeerMessageEvent struct {
	Version        string         `json:"version"`
	Type           string         `json:"type"`
	ConversationID string         `json:"conversation_id"`
	MessageID      string         `json:"message_id,omitempty"`
	Timestamp      string         `json:"timestamp"`
	Payload        map[string]any `json:"payload"`
}

var PeerMessageEventSink func(PeerMessageEvent) error

const (
	peerMessageDeliveryPolicyDrop  = "drop"
	peerMessageDeliveryPolicyQueue = "queue"

	peerMessageQueueStateStoreKey ipn.StateKey = "_peerMessageOutboundQueue"
	peerMessageQueueTick                       = 30 * time.Second
)

type peerMessageQueueEntry struct {
	PeerRef       string                      `json:"peer_ref"`
	Payload       PeerMessageTransportPayload `json:"payload"`
	QueuedAt      string                      `json:"queued_at"`
	LastAttemptAt string                      `json:"last_attempt_at,omitempty"`
	LastError     string                      `json:"last_error,omitempty"`
	AttemptCount  int                         `json:"attempt_count"`
}

type peerMessageQueueWorker struct {
	signal chan struct{}
}

var peerMessageQueueWorkers sync.Map

func init() {
	RegisterPeerAPIHandler("/v0/peer-message/message", handlePeerMessage)
}

func (b *LocalBackend) SendPeerMessage(ctx context.Context, peerRef string, payload PeerMessageTransportPayload) (*PeerMessageSendResult, error) {
	b.ensurePeerMessageQueueWorker()
	policy := normalizePeerMessageDeliveryPolicy(payload.DeliveryPolicy)
	nm := b.NetMap()
	if nm == nil {
		err := fmt.Errorf("no network map available")
		if policy == peerMessageDeliveryPolicyQueue {
			if enqueueErr := b.enqueuePeerMessage(peerRef, payload, err); enqueueErr != nil {
				return nil, enqueueErr
			}
			return &PeerMessageSendResult{
				Accepted:       true,
				Queued:         true,
				DeliveryStatus: "pending",
				MessageID:      payload.Message.ID,
			}, nil
		}
		return nil, err
	}

	peer, err := resolvePeerByRef(nm, peerRef)
	if err != nil {
		if policy == peerMessageDeliveryPolicyQueue {
			if enqueueErr := b.enqueuePeerMessage(peerRef, payload, err); enqueueErr != nil {
				return nil, enqueueErr
			}
			return &PeerMessageSendResult{
				Accepted:       true,
				Queued:         true,
				DeliveryStatus: "pending",
				MessageID:      payload.Message.ID,
			}, nil
		}
		return nil, err
	}

	if err := b.sendPeerMessageNow(ctx, nm, peer, peerRef, payload); err != nil {
		if policy == peerMessageDeliveryPolicyQueue {
			if enqueueErr := b.enqueuePeerMessage(peerRef, payload, err); enqueueErr != nil {
				return nil, enqueueErr
			}
			return &PeerMessageSendResult{
				Accepted:       true,
				Queued:         true,
				DeliveryStatus: "pending",
				MessageID:      payload.Message.ID,
			}, nil
		}
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

	_ = b.flushPeerMessageQueue(b.ctx)

	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			_ = b.flushPeerMessageQueue(b.ctx)
		case <-worker.signal:
			_ = b.flushPeerMessageQueue(b.ctx)
		}
	}
}

func (b *LocalBackend) enqueuePeerMessage(peerRef string, payload PeerMessageTransportPayload, cause error) error {
	entries, err := b.readPeerMessageQueue()
	if err != nil {
		return fmt.Errorf("read peerMessage queue: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	entries = append(entries, peerMessageQueueEntry{
		PeerRef:       peerRef,
		Payload:       payload,
		QueuedAt:      now,
		LastAttemptAt: now,
		LastError:     cause.Error(),
		AttemptCount:  1,
	})
	if err := b.writePeerMessageQueue(entries); err != nil {
		return fmt.Errorf("write peerMessage queue: %w", err)
	}
	if worker, ok := peerMessageQueueWorkers.Load(b); ok {
		select {
		case worker.(*peerMessageQueueWorker).signal <- struct{}{}:
		default:
		}
	}
	return nil
}

func (b *LocalBackend) flushPeerMessageQueue(ctx context.Context) error {
	entries, err := b.readPeerMessageQueue()
	if err != nil || len(entries) == 0 {
		return err
	}

	nm := b.NetMap()
	if nm == nil {
		return nil
	}

	remaining := make([]peerMessageQueueEntry, 0, len(entries))
	for _, entry := range entries {
		peer, err := resolvePeerByRef(nm, entry.PeerRef)
		if err != nil {
			entry.LastAttemptAt = time.Now().UTC().Format(time.RFC3339Nano)
			entry.LastError = err.Error()
			entry.AttemptCount++
			remaining = append(remaining, entry)
			continue
		}
		if err := b.sendPeerMessageNow(ctx, nm, peer, entry.PeerRef, entry.Payload); err != nil {
			entry.LastAttemptAt = time.Now().UTC().Format(time.RFC3339Nano)
			entry.LastError = err.Error()
			entry.AttemptCount++
			remaining = append(remaining, entry)
			continue
		}
		_ = b.emitPeerMessageDeliveryUpdate(entry.Payload, "delivered")
	}

	if err := b.writePeerMessageQueue(remaining); err != nil {
		return fmt.Errorf("write peerMessage queue: %w", err)
	}
	return nil
}

func (b *LocalBackend) emitPeerMessageDeliveryUpdate(payload PeerMessageTransportPayload, deliveryStatus string) error {
	event := PeerMessageEvent{
		Version:        "v1",
		Type:           "message_delivery_update",
		ConversationID: payload.ConversationID,
		MessageID:      payload.Message.ID,
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		Payload: map[string]any{
			"conversation_id": payload.ConversationID,
			"delivery_status": deliveryStatus,
			"message_id":      payload.Message.ID,
			"message": map[string]any{
				"id":              payload.Message.ID,
				"conversation_id": payload.Message.ConversationID,
				"delivery_status": deliveryStatus,
			},
		},
	}
	if PeerMessageEventSink != nil {
		return PeerMessageEventSink(event)
	}
	// No event sink registered (daemon mode) — broadcast via watch-ipn-bus
	b.send(ipn.Notify{PeerMessageEvent: event})
	return nil
}

func (b *LocalBackend) readPeerMessageQueue() ([]peerMessageQueueEntry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pm.CurrentProfile().ID() == "" {
		return nil, nil
	}
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

func (b *LocalBackend) writePeerMessageQueue(entries []peerMessageQueueEntry) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pm.CurrentProfile().ID() == "" {
		return nil
	}
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

