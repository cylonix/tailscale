// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"runtime/pprof"
	"strconv"
	"tailscale.com/util/clientmetric"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/util/httpm"
)

// PeerDebugFootprint, when set by the platform, returns the process's
// resident footprint as the OS accounts it and its lifetime peak. The iOS
// extension sets it (memwatch.go); it is what the extension's memory limit
// is measured against, which Go's own statistics do not cover.
var PeerDebugFootprint func() (cur, peak uint64, ok bool)

// PeerDebugTaskMemory, when set, also returns the resident set and its
// peak: the basis of the rpages figure in jetsam snapshots, which counts
// clean file-backed pages the footprint excludes.
var PeerDebugTaskMemory func() (footprint, footprintPeak, resident, residentPeak uint64, ok bool)

// peerDebugPprofPath serves Go runtime profiles of this node to the user's
// own other devices. Upstream's /v0/goroutines needs the control plane to
// grant CapabilityDebug, which this control plane does not, and on iOS the
// extension's in-process pprof server is unreachable from outside the
// device (its network stack does not deliver tunnel traffic to process
// listeners). This is the one path that reaches a phone's extension from a
// laptop over the tailnet. Same-user peers only, like peer messaging.
const peerDebugPprofPath = "/v0/cylonix/pprof"

func init() {
	RegisterPeerAPIHandler(peerDebugPprofPath, handlePeerDebugPprof)
}

// handlePeerDebugPprof writes the named runtime/pprof profile (default heap,
// after a GC so the numbers are live bytes). ?debug=1 selects the text form.
func handlePeerDebugPprof(ph PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.GET {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !ph.IsSelfUntagged() {
		http.Error(w, "profiles are only served to same-user peers", http.StatusForbidden)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "heap"
	}
	if name == "footprint" {
		// footprint/footprint_peak (and resident) come from a platform hook
		// set only on iOS/macOS. On platforms without it (e.g. Android) still
		// return the Go memstats, xray purge counters, and all client metrics,
		// so DERP/xray/netcheck churn can be watched over the tunnel there too.
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		out := map[string]any{
			"go_sys":        ms.Sys,
			"go_heap_inuse": ms.HeapInuse,
			"go_released":   ms.HeapReleased,
			"num_gc":        uint64(ms.NumGC),
		}
		if PeerDebugFootprint != nil {
			if cur, peak, ok := PeerDebugFootprint(); ok {
				out["footprint"] = cur
				out["footprint_peak"] = peak
			}
		}
		if PeerDebugTaskMemory != nil {
			if _, _, res, resPeak, ok := PeerDebugTaskMemory(); ok {
				out["resident"] = res
				out["resident_peak"] = resPeak
			}
		}
		out["xray_purges"], out["xray_entries_purged"] = derphttp.XRayDialerCachePurges()
		// Every client metric, so rebind/DERP/netcheck churn can be watched
		// over the tunnel without a device log pull.
		metrics := make(map[string]int64)
		for _, m := range clientmetric.Metrics() {
			metrics[m.Name()] = m.Value()
		}
		out["metrics"] = metrics
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	}
	profile := pprof.Lookup(name)
	if profile == nil {
		http.Error(w, "unknown profile", http.StatusNotFound)
		return
	}
	debug, _ := strconv.Atoi(r.URL.Query().Get("debug"))
	if name == "heap" && r.URL.Query().Get("gc") != "0" {
		runtime.GC()
	}
	if debug > 0 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.pprof"`)
	}
	if err := profile.WriteTo(w, debug); err != nil {
		ph.LocalBackend().logf("peerdebug: writing %s profile: %v", name, err)
	}
}

// FetchPeerDebugPprof requests the named profile from peerRef's daemon over
// this daemon's PeerAPI transport. The caller owns the response body.
func (b *LocalBackend) FetchPeerDebugPprof(ctx context.Context, peerRef, name, debug string) (*http.Response, error) {
	nm := b.NetMap()
	if nm == nil {
		return nil, fmt.Errorf("no netmap")
	}
	peer, err := resolvePeerByRef(nm, peerRef)
	if err != nil {
		return nil, err
	}
	base := peerAPIBase(nm, peer)
	if base == "" {
		return nil, fmt.Errorf("peer %q does not expose peerapi", peerRef)
	}
	q := url.Values{"name": {name}, "debug": {debug}}
	req, err := http.NewRequestWithContext(ctx, httpm.GET, base+peerDebugPprofPath+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: b.Dialer().PeerAPITransport(),
		Timeout:   60 * time.Second,
	}
	return client.Do(req)
}
