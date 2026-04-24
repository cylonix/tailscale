// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Cylonix-only: a bounded ring buffer of recent IPN state notification sends,
// each annotated with a goroutine stack trace. The frontend sees stale or
// surprising state=0 notifications and the realtime log is often truncated
// by the time the problem is investigated, so we keep a short forensic log
// in memory that can be fetched on demand.

package ipnlocal

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"tailscale.com/ipn"
)

const cylonixStateTraceCapacity = 64

// CylonixStateTrace is one recorded state notification send. Exported for JSON
// rendering via the LocalAPI.
type CylonixStateTrace struct {
	At       time.Time `json:"at"`
	OldState string    `json:"oldState,omitempty"`
	NewState string    `json:"newState"`
	Stack    string    `json:"stack"`
}

type cylonixStateTraceRing struct {
	mu     sync.Mutex
	buf    []CylonixStateTrace
	head   int // index of the oldest entry; valid when buf is full
	filled bool
}

var globalCylonixStateTraces = &cylonixStateTraceRing{
	buf: make([]CylonixStateTrace, 0, cylonixStateTraceCapacity),
}

// recordCylonixStateSend captures a single state-send event with the current
// goroutine's stack trace. oldState may be empty when the caller does not
// know the prior state (e.g. forced resets).
func recordCylonixStateSend(oldState, newState ipn.State) {
	buf := make([]byte, 8192)
	n := runtime.Stack(buf, false)
	stack := string(buf[:n])

	entry := CylonixStateTrace{
		At:       time.Now(),
		NewState: newState.String(),
		Stack:    stack,
	}
	if oldState != 0 || oldState.String() != "" {
		entry.OldState = oldState.String()
	}

	r := globalCylonixStateTraces
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) < cap(r.buf) {
		r.buf = append(r.buf, entry)
		return
	}
	r.buf[r.head] = entry
	r.head = (r.head + 1) % cap(r.buf)
	r.filled = true
}

// CylonixGetStateTraces returns a snapshot of the recorded state traces in
// oldest-to-newest order.
func CylonixGetStateTraces() []CylonixStateTrace {
	r := globalCylonixStateTraces
	r.mu.Lock()
	defer r.mu.Unlock()

	n := len(r.buf)
	out := make([]CylonixStateTrace, 0, n)
	if !r.filled {
		out = append(out, r.buf...)
		return out
	}
	for i := 0; i < n; i++ {
		out = append(out, r.buf[(r.head+i)%n])
	}
	return out
}

// CylonixFormatStateTraces returns a human-readable rendering of the trace
// ring, suitable for shipping back over a debug method channel.
func CylonixFormatStateTraces() string {
	traces := CylonixGetStateTraces()
	if len(traces) == 0 {
		return "no IPN state-send traces recorded\n"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "IPN state-send trace (%d entries, newest last)\n", len(traces))
	for i, t := range traces {
		fmt.Fprintf(&sb, "\n--- [%d] %s %s -> %s ---\n%s",
			i, t.At.Format(time.RFC3339Nano), t.OldState, t.NewState, t.Stack)
	}
	return sb.String()
}
