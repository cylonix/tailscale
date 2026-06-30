// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Active-peer warm/keepalive: while the UI has a peer-message thread open,
// the daemon periodically pings the peer's PeerAPI so the XRay+DERP+WireGuard+
// TCP+HTTP path stays hot. Eliminates the cold-start timeout on the user's
// next outbound message.

package ipnlocal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/util/httpm"
)

const (
	peerMessageWarmInterval    = 25 * time.Second
	peerMessageWarmTimeout     = 30 * time.Second
	peerMessageWarmMaxBackoff  = 5 * time.Minute
	peerMessageWarmFailWarnCap = 3 // log full failure detail this many times, then stay at debug
)

// PeerMessageWarmStatus values surfaced to clients via PeerMessageEvent.
const (
	PeerMessageWarmStatusCold    = "cold"
	PeerMessageWarmStatusWarming = "warming"
	PeerMessageWarmStatusWarm    = "warm"
	PeerMessageWarmStatusError   = "error"
)

type activePeerEntry struct {
	refs   int
	cancel context.CancelFunc

	// status / failures are updated only by the warm loop goroutine for this
	// peer (one goroutine per ref), but read under m.mu by snapshot helpers.
	status     string // last published status; see PeerMessageWarmStatus*
	failures   int    // consecutive warm failures; reset on success
}

// activePeerManager tracks peer references that should be kept warm and runs
// a single warm-loop goroutine per distinct peer, refcounted across sessions.
type activePeerManager struct {
	b     *LocalBackend
	mu    sync.Mutex
	peers map[string]*activePeerEntry // key: normalized peer ref

	// global is the long-lived session used by method-channel callers
	// (Android/Apple) that can't hold a streaming HTTP connection. Its
	// lifecycle is governed by globalDeadline, refreshed on every Set call.
	global         *ActivePeerSession
	globalDeadline time.Time
	globalTimer    *time.Timer
}

// peerMessageWarmGlobalSessionTTL is the auto-clear deadline for the global
// session: if no update arrives within this window, drop all peers. Bound to
// app/lifetime where the caller can't observe a socket close.
const peerMessageWarmGlobalSessionTTL = 180 * time.Second

var activePeerManagers sync.Map // *LocalBackend -> *activePeerManager

func (b *LocalBackend) activePeerManager() *activePeerManager {
	if v, ok := activePeerManagers.Load(b); ok {
		return v.(*activePeerManager)
	}
	m := &activePeerManager{
		b:     b,
		peers: map[string]*activePeerEntry{},
	}
	actual, _ := activePeerManagers.LoadOrStore(b, m)
	return actual.(*activePeerManager)
}

// ActivePeerSession is a per-LocalAPI-connection claim on a set of peers to
// keep warm. Closing it (e.g. when the client disconnects) releases all of
// the session's claims; if no other session still claims a peer, its warm
// goroutine stops.
type ActivePeerSession struct {
	m      *activePeerManager
	mu     sync.Mutex
	peers  map[string]struct{}
	closed bool
}

// NewActivePeerSession returns a new session bound to b. Callers should call
// Close exactly once when their connection ends.
func (b *LocalBackend) NewActivePeerSession() *ActivePeerSession {
	return &ActivePeerSession{
		m:     b.activePeerManager(),
		peers: map[string]struct{}{},
	}
}

// Set replaces the session's set of claimed peer refs. Each ref is normalized
// (case + trailing dot) so callers can pass user-facing names interchangeably.
// Empty refs are ignored.
func (s *ActivePeerSession) Set(refs []string) {
	want := make(map[string]struct{}, len(refs))
	for _, r := range refs {
		if nr := normalizePeerRef(r); nr != "" {
			want[nr] = struct{}{}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	for ref := range want {
		if _, ok := s.peers[ref]; ok {
			continue
		}
		s.peers[ref] = struct{}{}
		s.m.acquire(ref)
	}
	for ref := range s.peers {
		if _, ok := want[ref]; ok {
			continue
		}
		delete(s.peers, ref)
		s.m.release(ref)
	}
}

// Close releases all peer claims held by this session.
func (s *ActivePeerSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for ref := range s.peers {
		s.m.release(ref)
	}
	s.peers = nil
}

// SetGlobalActivePeers updates the manager's long-lived "global" session for
// callers that can't hold a streaming HTTP connection (e.g. method-channel
// callers on Android / Apple, where the daemon runs in-process). The session
// auto-clears after peerMessageWarmGlobalSessionTTL with no further calls.
//
// Pass an empty slice to clear immediately.
func (b *LocalBackend) SetGlobalActivePeers(refs []string) {
	b.activePeerManager().setGlobal(refs)
}

// ClearGlobalActivePeers releases the global session immediately.
func (b *LocalBackend) ClearGlobalActivePeers() {
	b.activePeerManager().clearGlobal()
}

func (m *activePeerManager) setGlobal(refs []string) {
	m.mu.Lock()
	if m.global == nil {
		m.global = &ActivePeerSession{
			m:     m,
			peers: map[string]struct{}{},
		}
	}
	session := m.global
	m.globalDeadline = time.Now().Add(peerMessageWarmGlobalSessionTTL)
	m.armGlobalWatchdogLocked()
	m.mu.Unlock()

	session.Set(refs)
}

func (m *activePeerManager) clearGlobal() {
	m.mu.Lock()
	session := m.global
	m.global = nil
	if m.globalTimer != nil {
		m.globalTimer.Stop()
		m.globalTimer = nil
	}
	m.mu.Unlock()

	if session != nil {
		session.Close()
	}
}

func (m *activePeerManager) armGlobalWatchdogLocked() {
	// Caller must hold m.mu. Schedule (or reschedule) a one-shot fire that
	// closes the global session if no further updates come in by globalDeadline.
	if m.globalTimer != nil {
		m.globalTimer.Stop()
	}
	d := time.Until(m.globalDeadline)
	if d <= 0 {
		d = peerMessageWarmGlobalSessionTTL
	}
	m.globalTimer = time.AfterFunc(d, func() {
		m.mu.Lock()
		// Only fire if the deadline hasn't been pushed out by another setGlobal
		// since this timer was scheduled.
		if !time.Now().Before(m.globalDeadline) {
			session := m.global
			m.global = nil
			m.globalTimer = nil
			m.mu.Unlock()
			if session != nil {
				m.b.logf("peermessage_warm: global session expired (no heartbeat)")
				session.Close()
			}
			return
		}
		// Re-arm against the (newer) deadline.
		m.armGlobalWatchdogLocked()
		m.mu.Unlock()
	})
}

func (m *activePeerManager) acquire(ref string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.peers[ref]; ok {
		e.refs++
		return
	}
	ctx, cancel := context.WithCancel(m.b.ctx)
	m.peers[ref] = &activePeerEntry{
		refs:   1,
		cancel: cancel,
		status: PeerMessageWarmStatusCold,
	}
	// Surface initial cold state so the UI can render a placeholder
	// indicator immediately.
	m.b.emitWarmStatusLocked(ref, PeerMessageWarmStatusCold)
	m.b.goTracker.Go(func() { m.runWarmLoop(ctx, ref) })
}

func (m *activePeerManager) release(ref string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.peers[ref]
	if !ok {
		return
	}
	e.refs--
	if e.refs <= 0 {
		if e.cancel != nil {
			e.cancel()
		}
		delete(m.peers, ref)
	}
}

// runWarmLoop runs the per-peer warm pinger. The interval expands when the
// remote peer can't be reached (network outage, peer offline, peer on an old
// build that returns errors instead of a quick HTTP response) so we don't
// burn cycles or fill logs.
func (m *activePeerManager) runWarmLoop(ctx context.Context, ref string) {
	for {
		m.warmOnce(ctx, ref)

		m.mu.Lock()
		e, ok := m.peers[ref]
		if !ok {
			m.mu.Unlock()
			return // released
		}
		fails := e.failures
		m.mu.Unlock()

		next := nextWarmInterval(fails)
		t := time.NewTimer(next)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// nextWarmInterval picks the next sleep duration based on consecutive failure
// count. Healthy peers stay at the base 25s interval. Failures double the
// interval, capped at peerMessageWarmMaxBackoff.
func nextWarmInterval(failures int) time.Duration {
	if failures <= 0 {
		return peerMessageWarmInterval
	}
	d := peerMessageWarmInterval << uint(failures) // 25s, 50s, 100s, 200s, ...
	if d > peerMessageWarmMaxBackoff || d < 0 {
		return peerMessageWarmMaxBackoff
	}
	return d
}

// warmOnce performs a single warm GET to the peer's PeerAPI root. The root is
// universally supported by every tailscale-derived PeerAPI (it always returns
// 200 with an HTML hello page), so warming works regardless of the remote
// peer's build version. The HTTP body is small and the request is dropped
// immediately on the receiver — the only purpose is to keep the
// XRay+DERP+WireGuard+TCP path warm.
func (m *activePeerManager) warmOnce(ctx context.Context, ref string) {
	nm := m.b.NetMap()
	if nm == nil {
		return
	}
	peer, err := resolvePeerByRef(nm, ref)
	if err != nil {
		m.recordWarmFailure(ref, err)
		return
	}
	base := peerAPIBase(nm, peer)
	if base == "" {
		m.recordWarmFailure(ref, errors.New("peerapi base unavailable"))
		return
	}

	m.transitionStatus(ref, PeerMessageWarmStatusWarming)

	cctx, cancel := context.WithTimeout(ctx, peerMessageWarmTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, httpm.GET, base+"/", nil)
	if err != nil {
		m.recordWarmFailure(ref, err)
		return
	}
	client := &http.Client{
		Transport: m.b.Dialer().PeerAPITransport(),
		Timeout:   peerMessageWarmTimeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		m.recordWarmFailure(ref, err)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// Any HTTP response (including 4xx) means the path is warm — the request
	// completed an HTTP round-trip end-to-end. Treat as success.
	m.recordWarmSuccess(ref)
}

func (m *activePeerManager) recordWarmFailure(ref string, cause error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.peers[ref]
	if !ok {
		return
	}
	e.failures++
	if e.failures <= peerMessageWarmFailWarnCap {
		m.b.logf("peermessage_warm: ref=%q failed (attempt %d): %v", ref, e.failures, cause)
	} else {
		m.b.logf("[v1] peermessage_warm: ref=%q still failing (attempt %d): %v", ref, e.failures, cause)
	}
	if e.status != PeerMessageWarmStatusError {
		e.status = PeerMessageWarmStatusError
		m.b.emitWarmStatusLocked(ref, PeerMessageWarmStatusError)
	}
}

func (m *activePeerManager) recordWarmSuccess(ref string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.peers[ref]
	if !ok {
		return
	}
	if e.failures > 0 {
		m.b.logf("peermessage_warm: ref=%q recovered after %d failures", ref, e.failures)
	}
	e.failures = 0
	if e.status != PeerMessageWarmStatusWarm {
		e.status = PeerMessageWarmStatusWarm
		m.b.emitWarmStatusLocked(ref, PeerMessageWarmStatusWarm)
	}
}

// transitionStatus pushes an intermediate status (e.g. "warming") only if it
// differs from the current published value, so we don't spam events.
func (m *activePeerManager) transitionStatus(ref, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.peers[ref]
	if !ok || e.status == status {
		return
	}
	e.status = status
	m.b.emitWarmStatusLocked(ref, status)
}

// emitWarmStatusLocked is a thin wrapper that doesn't actually require any
// lock — the name reflects the calling pattern (always called while holding
// m.mu so the snapshot is consistent). It pushes a PeerMessageEvent so the
// app's existing peer-message event stream delivers it without a new channel.
func (b *LocalBackend) emitWarmStatusLocked(ref, status string) {
	event := PeerMessageEvent{
		Version:   "v1",
		Type:      "warm_status",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Payload: map[string]any{
			"profile_id": b.peerMessageProfileID(),
			"peer_ref":   ref,
			"status":     status,
		},
	}
	if PeerMessageEventSink != nil {
		_ = PeerMessageEventSink(event)
		return
	}
	b.send(ipn.Notify{PeerMessageEvent: event})
}
