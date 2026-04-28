// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// __CYLONIX_MOD__ Also include for the ts_tcp_safesocket Windows
// build, where sessions_windows.go is excluded (it depends on the
// named-pipe-only ipnauth.WindowsActor).
//go:build !windows || ts_tcp_safesocket

package desktop

import "tailscale.com/types/logger"

// NewSessionManager returns a new [SessionManager] for the current platform,
// [ErrNotImplemented] if the platform is not supported, or an error if the
// session manager could not be created.
func NewSessionManager(logger.Logf) (SessionManager, error) {
	return nil, ErrNotImplemented
}
