// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package magicsock

import (
	"errors"
	"syscall"

	"tailscale.com/net/neterror"
)

// shouldRebind returns if the error is one that is known to be healed by a
// rebind, and if so also returns a resason string for the rebind.
func shouldRebind(err error) (ok bool, reason string) {
	switch {
	// EPIPE/ENOTCONN are common errors when a send fails due to a closed
	// socket. There is some platform and version inconsistency in which
	// error is returned, but the meaning is the same.
	case neterror.IsClosedPipeError(err):
		return true, "broken-pipe"

	// EPERM is typically caused by EDR software, and has been observed to be
	// transient, it seems that some versions of some EDR lose track of sockets
	// at times, and return EPERM, but reconnects will establish appropriate
	// rights associated with a new socket.
	case errors.Is(err, syscall.EPERM):
		return true, "operation-not-permitted"

	// __BEGIN_CYLONIX_ADD__
	// On mobile the socket is bound to an interface index; when that
	// interface goes down or loses the address the socket was using, sends
	// fail with ENETDOWN / EADDRNOTAVAIL even though the path may already
	// look healthy again. Only a rebind fixes it.
	case errors.Is(err, syscall.ENETDOWN):
		return true, "network-down"
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return true, "address-not-available"
		// __END_CYLONIX_ADD__
	}
	return false, ""
}
