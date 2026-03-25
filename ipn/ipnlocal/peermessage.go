// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
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
	Message           PeerMessage `json:"message"`
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

func init() {
	RegisterPeerAPIHandler("/v0/peer-message/message", handlePeerMessage)
}

func (b *LocalBackend) SendPeerMessage(ctx context.Context, peerRef string, payload PeerMessageTransportPayload) error {
	nm := b.NetMap()
	if nm == nil {
		return fmt.Errorf("no network map available")
	}

	peer, err := resolvePeerByRef(nm, peerRef)
	if err != nil {
		return err
	}

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
		http.MethodPost,
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
	if r.Method != http.MethodPost {
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
	}

	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, "{}\n")
}
