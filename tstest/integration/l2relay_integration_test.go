// Copyright (c) EZBLOCK Inc
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
)

func TestL2DiscoveryRulesUserspaceMultiNode(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)

	env := newTestEnv(t, configureControl(func(cs *testcontrol.Server) {
		cs.L2DiscoveryRules = []tailcfg.L2DiscoveryRule{
			{
				Protocols: []string{"ssdp"},
				SrcIPs:    []string{"*"},
				DstIPs:    []string{"*"},
			},
		}
	}))

	n1 := newTestNode(t, env)
	d1 := n1.StartDaemon()
	defer d1.MustCleanShutdown(t)
	n1.AwaitResponding()
	n1.MustUp()
	n1.AwaitRunning()

	n2 := newTestNode(t, env)
	d2 := n2.StartDaemon()
	defer d2.MustCleanShutdown(t)
	n2.AwaitResponding()
	n2.MustUp()
	n2.AwaitRunning()

	n3 := newTestNode(t, env)
	d3 := n3.StartDaemon()
	defer d3.MustCleanShutdown(t)
	n3.AwaitResponding()
	n3.MustUp()
	n3.AwaitRunning()

	pingAll := func() error {
		if err := n1.Ping(n2); err != nil {
			return err
		}
		if err := n2.Ping(n3); err != nil {
			return err
		}
		if err := n3.Ping(n1); err != nil {
			return err
		}
		return nil
	}
	if err := tstest.WaitFor(20*time.Second, pingAll); err != nil {
		t.Fatalf("initial multi-node ping failed: %v", err)
	}

	// Change rules while nodes are running to verify map update plumbing.
	env.Control.SetL2DiscoveryRules([]tailcfg.L2DiscoveryRule{
		{
			Protocols: []string{"mdns"},
			SrcIPs:    []string{"*"},
			DstIPs:    []string{"*"},
		},
		{
			Protocols: []string{"minecraft"},
			SrcIPs:    []string{"*"},
			DstIPs:    []string{"*"},
		},
	})
	if err := tstest.WaitFor(20*time.Second, pingAll); err != nil {
		t.Fatalf("connectivity check after l2 rule update failed: %v", err)
	}
}
