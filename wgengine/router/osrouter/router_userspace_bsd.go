// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || freebsd

package osrouter

import (
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"runtime"
	"strings" // __CYLONIX_ADD__

	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak" // __CYLONIX_ADD__
	"tailscale.com/version"
	"tailscale.com/wgengine/router"
)

func init() {
	router.HookNewUserspaceRouter.Set(func(opts router.NewOpts) (router.Router, error) {
		return newUserspaceBSDRouter(opts.Logf, opts.Tun, opts.NetMon, opts.Health)
	})
}

type userspaceBSDRouter struct {
	logf    logger.Logf
	netMon  *netmon.Monitor
	health  *health.Tracker
	tunname string
	local   []netip.Prefix
	routes  map[netip.Prefix]bool

	// __BEGIN_CYLONIX_ADD__
	// scopedMirrors records, per address family ("inet"/"inet6"), the ifscoped
	// physical-default mirror route this router installed alongside the darwin
	// split-/1 default (see ensureScopedMirror), so teardown removes exactly
	// what was added.
	scopedMirrors map[string]scopedMirror
	// __END_CYLONIX_ADD__
}

// __BEGIN_CYLONIX_ADD__
// scopedMirror is an ifscoped copy of the physical interface's default route,
// e.g. `route add -inet default 192.168.1.254 -ifscope en1`.
type scopedMirror struct {
	gw    string // gateway address as printed by `route get`
	iface string // physical interface the mirror is scoped to
}

// __END_CYLONIX_ADD__

func newUserspaceBSDRouter(logf logger.Logf, tundev tun.Device, netMon *netmon.Monitor, health *health.Tracker) (router.Router, error) {
	tunname, err := tundev.Name()
	if err != nil {
		return nil, err
	}

	return &userspaceBSDRouter{
		logf:    logf,
		netMon:  netMon,
		health:  health,
		tunname: tunname,
	}, nil
}

func (r *userspaceBSDRouter) addrsToRemove(newLocalAddrs []netip.Prefix) (remove []netip.Prefix) {
	for _, cur := range r.local {
		found := false
		for _, v := range newLocalAddrs {
			found = (v == cur)
			if found {
				break
			}
		}
		if !found {
			remove = append(remove, cur)
		}
	}
	return
}

func (r *userspaceBSDRouter) addrsToAdd(newLocalAddrs []netip.Prefix) (add []netip.Prefix) {
	for _, cur := range newLocalAddrs {
		found := false
		for _, v := range r.local {
			found = (v == cur)
			if found {
				break
			}
		}
		if !found {
			add = append(add, cur)
		}
	}
	return
}

func cmd(args ...string) *exec.Cmd {
	if len(args) == 0 {
		log.Fatalf("exec.Cmd(%#v) invalid; need argv[0]", args)
	}
	return exec.Command(args[0], args[1:]...)
}

func (r *userspaceBSDRouter) Up() error {
	ifup := []string{"ifconfig", r.tunname, "up"}
	if out, err := cmd(ifup...).CombinedOutput(); err != nil {
		r.logf("running ifconfig failed: %v\n%s", err, out)
		return err
	}
	return nil
}

func inet(p netip.Prefix) string {
	if p.Addr().Is6() {
		return "inet6"
	}
	return "inet"
}

// __BEGIN_CYLONIX_ADD__
// isDefaultRoute reports whether p is a default route (0.0.0.0/0 or ::/0).
func isDefaultRoute(p netip.Prefix) bool {
	return p == tsaddr.AllIPv4() || p == tsaddr.AllIPv6()
}

// darwinV4Split and darwinV6Split are the two /1 subnets that together cover a
// default route without being a literal /0.
var (
	darwinV4Split = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
	darwinV6Split = []netip.Prefix{
		netip.MustParsePrefix("::/1"),
		netip.MustParsePrefix("8000::/1"),
	}
)

// routePrefixesToProgram maps a logical route to the prefixes actually installed
// in the OS routing table. On darwin a default route (0.0.0.0/0 or ::/0) is
// installed as its two covering /1 subnets instead of a literal /0. cylonixd
// runs this BSD router on macOS alongside the physical interface's own /0
// default, and macOS permits only one unscoped /0 per family:
//   - a literal /0 add collides with the physical default (silently refused for
//     v4, so the exit-node v4 default was never programmed), and
//   - a literal /0 delete matches by destination and removes the *physical*
//     default when the tunnel has no /0 of its own.
//
// Two /1s avoid both: they are distinct, more-specific destinations, so they add
// without collision, win by longest-prefix, and delete without ever touching the
// physical /0. They are also invisible to net/netmon.isDefaultGateway (netmask
// != 0, and -iface routes carry no RTF_GATEWAY), so netns/DERP keeps binding the
// underlay to the physical interface.
func routePrefixesToProgram(p netip.Prefix) []netip.Prefix {
	if runtime.GOOS != "darwin" || !isDefaultRoute(p) {
		return []netip.Prefix{p}
	}
	if p.Addr().Is4() {
		return darwinV4Split
	}
	return darwinV6Split
}

// physicalDefault returns the gateway and interface of the current unscoped
// default route for the given family ("inet"/"inet6"), if it points at a
// physical (non-utun) interface. The split /1s never remove the physical /0,
// and `route get default` is an exact-key lookup that ignores the /1s, so this
// is stable whether or not the tunnel default is installed.
func (r *userspaceBSDRouter) physicalDefault(fam string) (gw, iface string, ok bool) {
	out, err := cmd("route", "-n", "get", "-"+fam, "default").CombinedOutput()
	if err != nil {
		return "", "", false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			switch f[0] {
			case "gateway:":
				gw = f[1]
			case "interface:":
				iface = f[1]
			}
		}
	}
	if gw == "" || iface == "" || iface == r.tunname || strings.HasPrefix(iface, "utun") {
		return "", "", false
	}
	return gw, iface, true
}

// ensureScopedMirror installs an RTF_IFSCOPE copy of the physical interface's
// default route for fam, mirroring what Apple's Network Extension does when a
// VPN takes over the default route.
//
// Why it is required: netns (net/netns/netns_darwin.go) binds the daemon's
// underlay sockets — the DERP/xray TCP dials, STUN UDP, control-plane HTTPS —
// to the physical default interface with IP_BOUND_IF. A scoped route lookup on
// macOS matches the most-specific route and then REJECTS it if its interface
// differs from the socket's scope, without falling back to the physical /0:
// with the split /1s installed and no ifscoped default present, every bound
// socket fails instantly with ENETUNREACH (verified: `route get -ifscope en1
// <derp-ip>` reports "not in table" while the /1s are up). DERP then becomes
// unreachable, and with a DERP-only exit node that is a routing chicken-and-egg
// that kills all exit-node traffic. The ifscoped mirror gives scoped lookups a
// route to resolve to; unscoped (application) traffic still prefers the more
// specific /1s into the tunnel, and net/netmon.isDefaultGateway ignores
// RTF_IFSCOPE routes, so default-interface detection is unaffected.
func (r *userspaceBSDRouter) ensureScopedMirror(fam string) {
	if _, dup := r.scopedMirrors[fam]; dup {
		return
	}
	gw, iface, ok := r.physicalDefault(fam)
	if !ok {
		r.logf("[v1] scoped mirror: no physical %s default; skipping", fam)
		return
	}
	routeadd := []string{"route", "-q", "-n", "add", "-" + fam, "default", gw, "-ifscope", iface}
	out, err := cmd(routeadd...).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "File exists") {
			// A scoped default for iface already exists (created by the OS or
			// a previous run). Leave it alone and don't claim it for teardown.
			r.logf("scoped mirror: %s default -ifscope %s already present; not managing it", fam, iface)
		} else {
			r.logf("scoped mirror add failed: %v: %v\n%s", routeadd, err, out)
		}
		return
	}
	r.logf("scoped mirror: added %s default via %s -ifscope %s", fam, gw, iface)
	mak.Set(&r.scopedMirrors, fam, scopedMirror{gw: gw, iface: iface})
}

// removeScopedMirror deletes the ifscoped mirror this router added for fam, if
// any. `-ifscope` deletes match only RTF_IFSCOPE routes, so the physical
// unscoped default can never be affected.
func (r *userspaceBSDRouter) removeScopedMirror(fam string) {
	m, ok := r.scopedMirrors[fam]
	if !ok {
		return
	}
	routedel := []string{"route", "-q", "-n", "delete", "-" + fam, "default", "-ifscope", m.iface}
	out, err := cmd(routedel...).CombinedOutput()
	if err != nil {
		r.logf("scoped mirror del failed: %v: %v\n%s", routedel, err, out)
	} else {
		r.logf("scoped mirror: removed %s default -ifscope %s", fam, m.iface)
	}
	delete(r.scopedMirrors, fam)
}

// __END_CYLONIX_ADD__

func (r *userspaceBSDRouter) Set(cfg *router.Config) (reterr error) {
	if cfg == nil {
		cfg = &shutdownConfig
	}

	setErr := func(err error) {
		if reterr == nil {
			reterr = err
		}
	}
	addrsToRemove := r.addrsToRemove(cfg.LocalAddrs)

	// If we're removing all addresses, we need to remove and re-add all
	// routes.
	resetRoutes := len(r.local) > 0 && len(addrsToRemove) == len(r.local)

	// Update the addresses.
	for _, addr := range addrsToRemove {
		arg := []string{"ifconfig", r.tunname, inet(addr), addr.String(), "-alias"}
		out, err := cmd(arg...).CombinedOutput()
		if err != nil {
			r.logf("addr del failed: %v => %v\n%s", arg, err, out)
			setErr(err)
		}
	}
	for _, addr := range r.addrsToAdd(cfg.LocalAddrs) {
		var arg []string
		if runtime.GOOS == "freebsd" && addr.Addr().Is6() && addr.Bits() == 128 {
			// FreeBSD rejects tun addresses of the form fc00::1/128 -> fc00::1,
			// https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=218508
			// Instead add our whole /48, which works because we use a /48 route.
			// Full history: https://github.com/tailscale/tailscale/issues/1307
			tmp := netip.PrefixFrom(addr.Addr(), 48)
			arg = []string{"ifconfig", r.tunname, inet(tmp), tmp.String()}
		} else {
			arg = []string{"ifconfig", r.tunname, inet(addr), addr.String(), addr.Addr().String()}
		}
		out, err := cmd(arg...).CombinedOutput()
		if err != nil {
			r.logf("addr add failed: %v => %v\n%s", arg, err, out)
			setErr(err)
		}
	}

	newRoutes := make(map[netip.Prefix]bool)
	for _, route := range cfg.Routes {
		if runtime.GOOS != "darwin" && route == tsaddr.TailscaleULARange() {
			// Because we added the interface address as a /48 above,
			// the kernel already created the Tailscale ULA route
			// implicitly. We mustn't try to add/delete it ourselves.
			continue
		}
		newRoutes[route] = true
	}
	// Delete any preexisting routes.
	for route := range r.routes {
		if resetRoutes || !newRoutes[route] {
			del := "del"
			if version.OS() == "macOS" {
				del = "delete"
			}
			// __BEGIN_CYLONIX_MOD__
			// A darwin default route is installed as two /1 subnets (see
			// routePrefixesToProgram), so it must be deleted as those same /1s.
			// Each /1 is a distinct, more-specific destination — never 0.0.0.0/0
			// or ::/0 — so the plain `-iface` delete matches only the tunnel's own
			// route and can never remove the physical (or another VPN's) default.
			// This replaces an earlier `-ifp default` form that matched a `default`
			// destination by destination only and deleted en1's physical default
			// when the tunnel had no default of that family.
			darwinDefault := runtime.GOOS == "darwin" && isDefaultRoute(route)
			for _, pfx := range routePrefixesToProgram(route) {
				net := netipx.PrefixIPNet(pfx)
				nip := net.IP.Mask(net.Mask)
				nstr := fmt.Sprintf("%v/%d", nip, pfx.Bits())
				routedel := []string{"route", "-q", "-n",
					del, "-" + inet(pfx), nstr, "-iface", r.tunname}
				out, err := cmd(routedel...).CombinedOutput()
				if err != nil {
					r.logf("route del failed: %v: %v\n%s", routedel, err, out)
					// A darwin default is torn down as two /1s; a benign
					// "not in table" on one must not fail the Set.
					if !darwinDefault {
						setErr(err)
					}
				}
			}
			if darwinDefault {
				r.removeScopedMirror(inet(route))
			}
			// __END_CYLONIX_MOD__
		}
	}
	// Add the routes.
	for route := range newRoutes {
		if resetRoutes || !r.routes[route] {
			// __BEGIN_CYLONIX_MOD__
			// On darwin a default route is programmed as two /1 subnets (see
			// routePrefixesToProgram) plus an ifscoped mirror of the physical
			// default so IP_BOUND_IF sockets keep working (see
			// ensureScopedMirror); every other route is added as-is.
			for _, pfx := range routePrefixesToProgram(route) {
				net := netipx.PrefixIPNet(pfx)
				nip := net.IP.Mask(net.Mask)
				nstr := fmt.Sprintf("%v/%d", nip, pfx.Bits())
				routeadd := []string{"route", "-q", "-n",
					"add", "-" + inet(pfx), nstr,
					"-iface", r.tunname}
				out, err := cmd(routeadd...).CombinedOutput()
				if err != nil {
					r.logf("addr add failed: %v: %v\n%s", routeadd, err, out)
					setErr(err)
				}
			}
			if runtime.GOOS == "darwin" && isDefaultRoute(route) {
				r.ensureScopedMirror(inet(route))
			}
			// __END_CYLONIX_MOD__
		}
	}

	// Store the interface and routes so we know what to change on an update.
	if reterr == nil {
		r.local = append([]netip.Prefix{}, cfg.LocalAddrs...)
	}
	r.routes = newRoutes

	return reterr
}

func (r *userspaceBSDRouter) Close() error {
	return nil
}
