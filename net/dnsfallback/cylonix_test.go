// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dnsfallback

import (
	"context"
	"testing"

	"tailscale.com/types/logger"
)

func TestCylonixStaticLookupHit(t *testing.T) {
	ips, ok := cylonixStaticLookup("manage.cylonix.io")
	if !ok {
		t.Fatal("expected hit for manage.cylonix.io")
	}
	if len(ips) == 0 {
		t.Fatal("expected non-empty IP list for manage.cylonix.io")
	}
	var haveV4, haveV6 bool
	for _, ip := range ips {
		if ip.Is4() {
			haveV4 = true
		}
		if ip.Is6() {
			haveV6 = true
		}
	}
	if !haveV4 {
		t.Error("expected at least one IPv4 fallback")
	}
	if !haveV6 {
		t.Error("expected at least one IPv6 fallback")
	}
}

func TestCylonixStaticLookupMiss(t *testing.T) {
	if _, ok := cylonixStaticLookup("example.com"); ok {
		t.Fatal("unexpected hit for example.com")
	}
}

func TestLookupUsesCylonixStaticFallback(t *testing.T) {
	logf := logger.Discard
	got, err := lookup(context.Background(), "manage.cylonix.io", logf, nil, nil)
	if err != nil {
		t.Fatalf("lookup error: %v", err)
	}
	want, _ := cylonixStaticLookup("manage.cylonix.io")
	if len(got) != len(want) {
		t.Fatalf("lookup returned %d addrs, want %d (%v vs %v)", len(got), len(want), got, want)
	}
	// Order may be shuffled; check set membership.
	seen := map[string]bool{}
	for _, a := range got {
		seen[a.String()] = true
	}
	for _, a := range want {
		if !seen[a.String()] {
			t.Errorf("missing expected addr %v in %v", a, got)
		}
	}
}
