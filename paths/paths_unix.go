// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !wasm && !plan9 && !tamago

package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
	"tailscale.com/customize"
	"tailscale.com/version/distro"
)

// __BEGIN_CYLONIX_ADD__
var (
	program       = customize.LinuxProgramName
	daemonProgram = customize.ServiceName
	darwinProgram = customize.ProgramName
)
// __END_CYLONIX_ADD__

func init() {
	stateFileFunc = stateFileUnix
	ensureStateDirPerms = ensureStateDirPermsUnix
}

func statePath() string {
	switch runtime.GOOS {
	case "linux", "illumos", "solaris":
		return fmt.Sprintf("/var/lib/%s/%s.state", program, daemonProgram) // __CYLONIX_MOD__
	case "freebsd", "openbsd":
		return fmt.Sprintf("/var/db/%s/%s.state", program, daemonProgram) // __CYLONIX_MOD__
	case "darwin":
		return fmt.Sprintf("/Library/%s/%s.state", darwinProgram, daemonProgram) // __CYLONIX_MOD__
	case "aix":
		return fmt.Sprintf("/var/%s/%s.state", program, daemonProgram) // __CYLONIX_MOD__
	default:
		return ""
	}
}

func stateFileUnix() string {
	if distro.Get() == distro.Gokrazy {
		return fmt.Sprintf("/perm/%s/%s.state", daemonProgram, daemonProgram) // __CYLONIX_MOD__
	}
	path := statePath()
	if path == "" {
		return ""
	}

	try := path
	for range 3 { // check writability of the file, /var/lib/tailscale, and /var/lib
		err := unix.Access(try, unix.O_RDWR)
		if err == nil {
			return path
		}
		try = filepath.Dir(try)
	}

	if os.Getuid() == 0 {
		return ""
	}

	// For non-root users, fall back to $XDG_DATA_HOME/tailscale/*.
	return filepath.Join(xdgDataHome(), program, fmt.Sprintf("%s.state", daemonProgram)) // __CYLONIX_MOD__
}

func xdgDataHome() string {
	if e := os.Getenv("XDG_DATA_HOME"); e != "" {
		return e
	}
	return filepath.Join(os.Getenv("HOME"), ".local/share")
}

func ensureStateDirPermsUnix(dir string) error {
	if filepath.Base(dir) != program { // __CYLONIX_MOD__
		return nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("expected %q to be a directory; is %v", dir, fi.Mode())
	}
	const perm = 0700
	if fi.Mode().Perm() == perm {
		// Already correct.
		return nil
	}
	return os.Chmod(dir, perm)
}
