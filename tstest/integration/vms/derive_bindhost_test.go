// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vms

import (
	"net/netip"
	"runtime"
	"testing"

	"tailscale.com/net/netmon"
)

func deriveBindhost(t *testing.T) string {
	t.Helper()

	// __BEGIN_CYLONIX_ADD__
	if *bindHost != "" {
		return *bindHost
	}
	// __END_CYLONIX_ADD__

	ifName, err := netmon.DefaultRouteInterface()
	if err != nil {
		// __BEGIN_CYLONIX_ADD__
		return "127.0.0.1"
		// __END_CYLONIX_ADD__
	}

	var ret string
	err = netmon.ForeachInterfaceAddress(func(i netmon.Interface, prefix netip.Prefix) {
		if ret != "" || i.Name != ifName {
			return
		}
		// __BEGIN_CYLONIX_ADD__
		addr := prefix.Addr()
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			return
		}
		ret = addr.String()
		// __END_CYLONIX_ADD__
	})
	if ret != "" {
		return ret
	}
	// __BEGIN_CYLONIX_ADD__
	if err == nil {
		return "127.0.0.1"
	}
	t.Fatal(err)
	return "127.0.0.1"
	// __END_CYLONIX_ADD__
}

func TestDeriveBindhost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires GOOS=linux")
	}
	t.Log(deriveBindhost(t))
}
