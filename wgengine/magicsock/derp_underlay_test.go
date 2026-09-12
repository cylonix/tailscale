// Copyright (c) EZBLOCK Inc. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"os"
	"syscall"
	"testing"
)

func TestUnderlayStillCurrent(t *testing.T) {
	p := func(s ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, x := range s {
			out = append(out, netip.MustParsePrefix(x))
		}
		return out
	}
	tests := []struct {
		name       string
		dialedOver []netip.Prefix
		okay       []netip.Prefix
		want       bool
	}{
		{"same interface", p("192.168.68.50/22", "fe80::1/64"), p("192.168.68.50/22", "fe80::1/64"), true},
		{"moved to cellular", p("192.168.68.50/22"), p("10.20.30.40/32"), false},
		{"renumbered", p("192.168.68.50/22"), p("192.168.68.51/22"), false},
		{"v6 dropped", p("192.168.68.50/22", "fe80::1/64"), p("192.168.68.50/22"), false},
		{"extra address on same interface", p("192.168.68.50/22"), p("192.168.68.50/22", "fe80::1/64"), true},
		{"nothing recorded", nil, p("192.168.68.50/22"), true},
	}
	for _, tt := range tests {
		if got := underlayStillCurrent(tt.dialedOver, tt.okay); got != tt.want {
			t.Errorf("%s: underlayStillCurrent = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestShouldRebindMobileErrors(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want string
	}{
		{&os.SyscallError{Syscall: "sendto", Err: syscall.ENETDOWN}, "network-down"},
		{&os.SyscallError{Syscall: "sendto", Err: syscall.EADDRNOTAVAIL}, "address-not-available"},
		{&os.SyscallError{Syscall: "sendto", Err: syscall.EHOSTUNREACH}, ""},
		{&os.SyscallError{Syscall: "sendto", Err: syscall.ENETUNREACH}, ""},
	} {
		ok, reason := shouldRebind(tt.err)
		if ok != (tt.want != "") || reason != tt.want {
			t.Errorf("shouldRebind(%v) = %v, %q; want %q", tt.err, ok, reason, tt.want)
		}
	}
}
