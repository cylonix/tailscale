// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package taildrop

// cylonixWindowsActiveUser is a no-op on non-Windows platforms; active-user
// resolution there is handled by cylonixDarwinConsoleUser / cylonixLinuxActiveUser.
func cylonixWindowsActiveUser() (home string, uid, gid int) {
	return "", -1, -1
}

// cylonixWindowsIsPrivileged is only meaningful on Windows; elsewhere
// cylonixIsPrivilegedProcess uses the euid check.
func cylonixWindowsIsPrivileged() bool { return false }
