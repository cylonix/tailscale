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

// cylonixDownloadsEnvVar opts the binary into the Downloads-based
// direct file root. Cylonix-branded launchers (LaunchDaemon plist on
// macOS, systemd unit on Linux, service config on Windows) set this so
// users get the friendlier UX. Vanilla tailscaled (and upstream tests
// that don't want files dropped into the runner's real Downloads
// folder) keep the legacy staging behavior by leaving it unset.
const cylonixDownloadsEnvVar = "CYLONIX_TAILDROP_DEFAULT_DOWNLOADS"

// cylonixDefaultDownloadsRoot returns a per-user "Downloads/Cylonix"
// directory that the Taildrop extension can use as its DirectFileRoot,
// or "" if the env var opt-in is not set or no such directory can be
// safely determined for the current install. Selection order:
//
//  1. If prefs.OperatorUser is set and resolves to a real user with a
//     home directory containing a Downloads folder, use that user's
//     Downloads/Cylonix.
//  2. Otherwise, if the daemon is running unprivileged (non-root on
//     Unix), use the current process user's Downloads/Cylonix.
//  3. Otherwise (privileged daemon, no operator pref), try to resolve
//     the currently active GUI/console user and use their
//     Downloads/Cylonix. Best-effort; returns "" if no such user can
//     be determined.
//
// The returned directory is created if missing. When the daemon is
// running as root and we created the folder on behalf of a different
// user, we chown it so that user can read what lands in it.
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
		return ""
	}
	// Privileged daemon with no operator pref: best-effort resolve the
	// active GUI user. On a single-user desktop this is unambiguous; on
	// shared systems the admin can still pin a specific user via
	// `tailscale set --operator <user>`.
	if home, uid, gid := cylonixActiveUserHome(); home != "" {
		if path := cylonixEnsureDownloadsCylonix(home, uid, gid); path != "" {
			return path
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
	return cylonixLookupUser(op)
}

// cylonixLookupUser resolves a username to its home directory and
// numeric uid/gid. Returns "" / -1 / -1 on failure or when uid/gid
// cannot be parsed as integers (e.g. on Windows).
func cylonixLookupUser(name string) (home string, uid, gid int) {
	u, err := user.Lookup(name)
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

// cylonixInheritParentOwner best-effort hands ownership of path to the user
// that owns its parent directory, but only when the daemon is running as a
// privileged (root) process.
//
// Taildrop's direct file root lives under the GUI user's Downloads folder, but
// a root daemon creates files and directories owned by root:wheel that the
// user cannot read or traverse. cylonixEnsureDownloadsCylonix already chowns
// the Downloads/Cylonix folder, but only on its first creation. If the user
// deletes that folder, the per-file write path in fsFileOps recreates it (and
// writes files into it) as root without any chown, leaving an inaccessible
// directory. Calling this from the fsFileOps create/rename paths makes every
// directory and file inherit the parent's owner, which self-heals the folder
// on the next received file.
//
// It is a no-op on non-root daemons (the files are already user-owned) and on
// platforms without numeric uid/gid.
func cylonixInheritParentOwner(path string) {
	if !cylonixIsPrivilegedProcess() {
		return
	}
	fi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return
	}
	uid, gid, ok := cylonixStatOwnerIDs(fi)
	if !ok {
		return
	}
	// Best-effort: ignore errors (e.g. macOS TCC restrictions on Downloads).
	_ = os.Chown(path, int(uid), int(gid))
}

// cylonixIsPrivilegedProcess reports whether the current process is
// running as a privileged system identity (root on Unix; a service
// account on Windows). Privileged daemons cannot meaningfully default
// to "the user's Downloads" without first resolving which user.
func cylonixIsPrivilegedProcess() bool {
	if runtime.GOOS == "windows" {
		// On Windows, treat the absence of USERPROFILE as a strong
		// signal that we're running as LocalSystem or another
		// non-interactive service identity.
		return os.Getenv("USERPROFILE") == ""
	}
	return os.Geteuid() == 0
}

// cylonixActiveUserHome returns the home dir + uid/gid of the currently
// active GUI/console user, or "" / -1 / -1 if none can be determined.
// Used as a fallback when running as a privileged daemon with no
// operator pref configured.
//
// Resolution is OS-specific:
//
//   - macOS: stat /dev/console — its owner is the user logged in at
//     the loginwindow (or the fast-user-switching-active user).
//   - Linux: walk /run/user/<uid> entries; if exactly one regular
//     user (uid >= 1000) has a runtime dir, use that one. The XDG
//     runtime dir is created by systemd-logind for active sessions.
//   - Windows: not implemented; returns "". Admins should configure
//     the operator user via `tailscale set --operator`.
func cylonixActiveUserHome() (home string, uid, gid int) {
	switch runtime.GOOS {
	case "darwin":
		return cylonixDarwinConsoleUser()
	case "linux":
		return cylonixLinuxActiveUser()
	default:
		return "", -1, -1
	}
}

func cylonixDarwinConsoleUser() (home string, uid, gid int) {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return "", -1, -1
	}
	sysUID, ok := cylonixStatUID(fi)
	if !ok {
		return "", -1, -1
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(sysUID), 10))
	if err != nil {
		return "", -1, -1
	}
	parsedUID, err := strconv.Atoi(u.Uid)
	if err != nil {
		parsedUID = -1
	}
	parsedGID, err := strconv.Atoi(u.Gid)
	if err != nil {
		parsedGID = -1
	}
	// Skip system accounts (uid < 500 on macOS).
	if parsedUID >= 0 && parsedUID < 500 {
		return "", -1, -1
	}
	return u.HomeDir, parsedUID, parsedGID
}

func cylonixLinuxActiveUser() (home string, uid, gid int) {
	entries, err := os.ReadDir("/run/user")
	if err != nil {
		return "", -1, -1
	}
	var picked *user.User
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n, err := strconv.Atoi(e.Name())
		if err != nil || n < 1000 {
			continue
		}
		u, err := user.LookupId(e.Name())
		if err != nil {
			continue
		}
		if picked != nil {
			// Ambiguous (multiple active users) — defer to explicit
			// OperatorUser pref instead of guessing.
			return "", -1, -1
		}
		picked = u
	}
	if picked == nil {
		return "", -1, -1
	}
	parsedUID, err := strconv.Atoi(picked.Uid)
	if err != nil {
		parsedUID = -1
	}
	parsedGID, err := strconv.Atoi(picked.Gid)
	if err != nil {
		parsedGID = -1
	}
	return picked.HomeDir, parsedUID, parsedGID
}
