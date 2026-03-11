// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !darwin && !freebsd

package l2relay

import "net/netip"

func DefaultGatewayMAC(gw netip.Addr) (string, bool) {
	return "", false
}
