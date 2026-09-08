// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"
	"time"
)

func TestNextWarmInterval(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{0, 25 * time.Second},
		{1, 10 * time.Second}, // quick re-probe before publishing an error
		{2, 50 * time.Second},
		{3, 100 * time.Second},
		{4, 200 * time.Second},
		{5, 5 * time.Minute},
		{40, 5 * time.Minute}, // large counts must cap, not overflow
	}
	for _, tt := range tests {
		if got := nextWarmInterval(tt.failures); got != tt.want {
			t.Errorf("nextWarmInterval(%d) = %v, want %v", tt.failures, got, tt.want)
		}
	}
}

func TestStatusAfterFailure(t *testing.T) {
	if got := statusAfterFailure(1); got != PeerMessageWarmStatusWarming {
		t.Errorf("one failure published as %q, want %q", got, PeerMessageWarmStatusWarming)
	}
	if got := statusAfterFailure(2); got != PeerMessageWarmStatusError {
		t.Errorf("two failures published as %q, want %q", got, PeerMessageWarmStatusError)
	}
}
