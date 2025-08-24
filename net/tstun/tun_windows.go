// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func init() {
	tun.WintunTunnelType = "Cylonix"                                              // __CYLONIX_MOD__
	guid, err := windows.GUIDFromString("{51b7cfa4-ef76-4e70-bac7-9aac267ae5c9}") // __CYLONIX_MOD__
	if err != nil {
		panic(err)
	}
	tun.WintunStaticRequestedGUID = &guid
}

func interfaceName(dev tun.Device) (string, error) {
	guid, err := winipcfg.LUID(dev.(*tun.NativeTun).LUID()).GUID()
	if err != nil {
		return "", err
	}
	return guid.String(), nil
}
