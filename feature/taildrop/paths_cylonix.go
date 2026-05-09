// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"

	"tailscale.com/ipn"
)

// cylonixDownloadsSubfolder is the per-user subdirectory inside the OS
// Downloads folder where Taildrop deposits incoming files. Using a
// subfolder rather than Downloads itself avoids polluting the user's
// general Downloads dir and makes it easy to spot what arrived via
// Taildrop.
const cylonixDownloadsSubfolder = "Cylonix"

// cylonixDownloadsEnvVar opts the daemon into using the Downloads-based
// default direct file root. The cylonix daemon launchers (LaunchDaemon
// plist on macOS, systemd unit on Linux, service config on Windows)
// set this so users get the friendlier UX, while vanilla tailscaled
// (and the upstream tests) keep the legacy staging behavior.
const cylonixDownloadsEnvVar = "CYLONIX_TAILDROP_DEFAULT_DOWNLOADS"

// cylonixDefaultDownloadsRoot returns a per-user "Downloads/Cylonix"
// directory that the Taildrop extension can use as its DirectFileRoot,
// or "" if the env var opt-in is not set or no such directory can be
// safely determined for the current install. Selection order:
//
//  1. If prefs.OperatorUser is set and resolves to a real Unix user with
//     a home directory containing a Downloads folder, use that user's
//     Downloads/Cylonix.
//  2. Otherwise, if the daemon is running unprivileged (non-root on
//     Unix), use the current process user's Downloads/Cylonix.
//  3. Otherwise return "" so the caller falls back to the legacy
//     daemon-staged directory under varRoot.
//
// The returned directory is created if missing. When the daemon is
// running as root and we created the folder on behalf of a different
// (operator) user, we chown it so the operator can read what lands in
// it.
func cylonixDefaultDownloadsRoot(prefs ipn.PrefsView) string {
	if os.Getenv(cylonixDownloadsEnvVar) != "1" {
		return ""
	}
	if home, opUID, opGID := cylonixOperatorHome(prefs); home != "" {
		if path := cylonixEnsureDownloadsCylonix(home, opUID, opGID); path != "" {
			return path
		}
	}
	if !cylonixIsPrivilegedProcess() {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if path := cylonixEnsureDownloadsCylonix(home, -1, -1); path != "" {
				return path
			}
		}
	}
	return ""
}

// cylonixOperatorHome returns the home directory and uid/gid of the user
// named in prefs.OperatorUser, or "" / -1 / -1 if no operator is set or
// the lookup fails.
func cylonixOperatorHome(prefs ipn.PrefsView) (home string, uid, gid int) {
	if !prefs.Valid() {
		return "", -1, -1
	}
	op := prefs.OperatorUser()
	if op == "" {
		return "", -1, -1
	}
	u, err := user.Lookup(op)
	if err != nil {
		return "", -1, -1
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		uid = -1
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		gid = -1
	}
	return u.HomeDir, uid, gid
}

// cylonixEnsureDownloadsCylonix verifies that <home>/Downloads exists
// (the OS-managed user Downloads folder), then creates and returns
// <home>/Downloads/<subfolder>. Returns "" if the home Downloads folder
// is missing or the subfolder cannot be created.
//
// If uid/gid are non-negative and the subfolder is freshly created, it
// is chown'd to that user so a root daemon writes files the operator
// can read.
func cylonixEnsureDownloadsCylonix(home string, uid, gid int) string {
	downloads := filepath.Join(home, "Downloads")
	fi, err := os.Stat(downloads)
	if err != nil || !fi.IsDir() {
		return ""
	}
	target := filepath.Join(downloads, cylonixDownloadsSubfolder)
	created := false
	if _, err := os.Stat(target); err != nil {
		if !os.IsNotExist(err) {
			return ""
		}
		if err := os.Mkdir(target, 0o755); err != nil {
			return ""
		}
		created = true
	}
	if created && uid >= 0 && gid >= 0 {
		// Best-effort: ignore errors. On Windows os.Chown is a no-op
		// for these values which is fine because we only fall here on
		// Unix when an operator user is configured.
		_ = os.Chown(target, uid, gid)
	}
	return target
}

// cylonixIsPrivilegedProcess reports whether the current process is
// running as a privileged system identity (root on Unix; a service
// account on Windows). Privileged daemons cannot meaningfully default
// to "the user's Downloads" because they have no single user.
func cylonixIsPrivilegedProcess() bool {
	if runtime.GOOS == "windows" {
		// On Windows, treat the absence of USERPROFILE as a strong
		// signal that we're running as LocalSystem or another
		// non-interactive service identity.
		return os.Getenv("USERPROFILE") == ""
	}
	return os.Geteuid() == 0
}
