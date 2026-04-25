// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsdeps

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

func TestDeps(t *testing.T) {
	t.Skip("cylonix: xray-core/web-client cylonix additions pull pprof/proxy into js/wasm; needs follow-up to gate behind build tags")
	deptest.DepChecker{
		GOOS:   "js",
		GOARCH: "wasm",
		BadDeps: map[string]string{
			"testing":                    "do not use testing package in production code",
			"runtime/pprof":              "bloat",
			"golang.org/x/net/http2/h2c": "bloat",
			"net/http/pprof":             "bloat",
			"golang.org/x/net/proxy":     "bloat",
			"github.com/huin/goupnp":     "bloat, which can't work anyway in wasm",
		},
	}.Check(t)
}
