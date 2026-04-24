// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package paths returns platform and user-specific default paths to
// Tailscale files and directories.
package paths

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"tailscale.com/customize"
	"tailscale.com/syncs"
	"tailscale.com/version/distro"
)

// AppSharedDir is a string set by the iOS or Android app on start
// containing a directory we can read/write in.
var AppSharedDir syncs.AtomicValue[string]

// DefaultTailscaledSocket returns the path to the tailscaled Unix socket
// or the empty string if there's no reasonable default.
func DefaultTailscaledSocket() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\ProtectedPrefix\Administrators\Tailscale\tailscaled`
	}
	if runtime.GOOS == "darwin" {
		return fmt.Sprintf("/var/run/%s/%s.sock", customize.LinuxProgramName, customize.ServiceName) // __CYLONIX_MOD__
	}
	if runtime.GOOS == "plan9" {
		return "/srv/" + customize.ServiceName + ".sock" // __CYLONIX_MOD__
	}
	switch distro.Get() {
	case distro.Synology:
		if distro.DSMVersion() == 6 {
			return fmt.Sprintf("/var/packages/%s/etc/%s.sock", customize.ProgramName, customize.ServiceName) // __CYLONIX_MOD__
		}
		// DSM 7 (and higher? or failure to detect.)
		return fmt.Sprintf("/var/packages/%s/var/%s.sock", customize.ProgramName, customize.ServiceName) // __CYLONIX_MOD__
	case distro.Gokrazy:
		return fmt.Sprintf("/perm/%s/%s.sock", customize.ServiceName, customize.ServiceName) // __CYLONIX_MOD__
	case distro.QNAP:
		return fmt.Sprintf("/tmp/%s/%s.sock", customize.ServiceName, customize.ServiceName) // __CYLONIX_MOD__
	}
	if fi, err := os.Stat("/var/run"); err == nil && fi.IsDir() {
		return fmt.Sprintf("/var/run/%s/%s.sock", customize.LinuxProgramName, customize.ServiceName) // __CYLONIX_MOD__
	}
	return fmt.Sprintf("%s.sock", customize.ServiceName) // __CYLONIX_MOD__
}

// Overridden in init by OS-specific files.
var (
	stateFileFunc func() string

	// ensureStateDirPerms applies a restrictive ACL/chmod
	// to the provided directory.
	ensureStateDirPerms = func(string) error { return nil }
)

// DefaultTailscaledStateFile returns the default path to the
// tailscaled state file, or the empty string if there's no reasonable
// default value.
func DefaultTailscaledStateFile() string {
	if f := stateFileFunc; f != nil {
		return f()
	}
	if runtime.GOOS == "windows" {
		_, programName := GetWindowsProgramName() // __CYLONIX_MOD__
		return filepath.Join(os.Getenv("ProgramData"), programName, "server-state.conf") // __CYLONIX_MOD__
	}
	return ""
}

// DefaultTailscaledStateDir returns the default state directory
// to use for tailscaled, for use when the user provided neither
// a state directory or state file path to use.
//
// It returns the empty string if there's no reasonable default.
func DefaultTailscaledStateDir() string {
	if runtime.GOOS == "plan9" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("failed to get home directory: %v", err)
		}
		return filepath.Join(home, "tailscale-state")
	}
	return filepath.Dir(DefaultTailscaledStateFile())
}

// MakeAutomaticStateDir reports whether the platform
// automatically creates the state directory for tailscaled
// when it's absent.
func MakeAutomaticStateDir() bool {
	switch runtime.GOOS {
	case "plan9":
		return true
	case "linux":
		if distro.Get() == distro.JetKVM {
			return true
		}
	}
	return false
}

// MkStateDir ensures that dirPath, the daemon's configuration directory
// containing machine keys etc, both exists and has the correct permissions.
// We want it to only be accessible to the user the daemon is running under.
func MkStateDir(dirPath string) error {
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return err
	}
	return ensureStateDirPerms(dirPath)
}

// LegacyStateFilePath returns the legacy path to the state file when
// it was stored under the current user's %LocalAppData%.
//
// It is only called on Windows.
func LegacyStateFilePath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LocalAppData"), "Tailscale", "server-state.conf")
	}
	return ""
}

// __BEGIN CYLONIX_MOD__
func GetWindowsProgramName() (name, capitalized string) {
	exe, err := os.Executable()
	if err != nil {
		return customize.WindowsProgramName, customize.WindowsCapitalizedProgramName
	}
	baseName := filepath.Base(exe)
	name = strings.TrimSuffix(baseName, filepath.Ext(baseName))
	if strings.HasSuffix(name, "d") {
		name = name[:len(name)-1]
	}
	capitalized = name
	r, size := utf8.DecodeRuneInString(name)
	if r != utf8.RuneError {
		capitalized = string(unicode.ToUpper(r)) + name[size:]
	}
	return
}

// __END CYLONIX_MOD__