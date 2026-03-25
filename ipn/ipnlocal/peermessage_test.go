// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

func TestResolvePeerByRefMatchesSelfNode(t *testing.T) {
	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			StableID:             "self-stable",
			Name:                 "m1.vital-skylark.cylonix.org.",
			ComputedName:         "m1",
			ComputedNameWithHost: "m1.vital-skylark.cylonix.org",
		}).View(),
	}

	tests := []string{
		"self-stable",
		"m1.vital-skylark.cylonix.org",
		"m1.vital-skylark.cylonix.org.",
		"m1",
	}

	for _, ref := range tests {
		t.Run(ref, func(t *testing.T) {
			got, err := resolvePeerByRef(nm, ref)
			if err != nil {
				t.Fatalf("resolvePeerByRef(%q): %v", ref, err)
			}
			if got.StableID() != nm.SelfNode.StableID() {
				t.Fatalf("resolvePeerByRef(%q) got %q, want %q", ref, got.StableID(), nm.SelfNode.StableID())
			}
		})
	}
}
