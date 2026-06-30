// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package taildrop

import (
	"os/user"

	"golang.org/x/sys/windows"
	"tailscale.com/util/winutil"
)

// cylonixWindowsActiveUser resolves the home directory of the user logged in at
// the active console session, so a privileged (LocalSystem) daemon can default
// Taildrop's DirectFileRoot to that user's Downloads/Cylonix. Returns
// "" / -1 / -1 if no interactive user can be determined.
//
// uid/gid are always -1 on Windows: ownership is governed by ACL inheritance
// (the Cylonix subfolder created under the user's Downloads inherits the user's
// access from the profile), and os.Chown is a no-op there anyway.
// cylonixWindowsIsPrivileged reports whether the current process is running as
// a non-interactive service identity (LocalSystem / LocalService /
// NetworkService). Checked via the process token's user SID because USERPROFILE
// is populated even for LocalSystem and so cannot be used to tell them apart.
func cylonixWindowsIsPrivileged() bool {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	for _, wk := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,
		windows.WinLocalServiceSid,
		windows.WinNetworkServiceSid,
	} {
		if sid, err := windows.CreateWellKnownSid(wk); err == nil && tu.User.Sid.Equals(sid) {
			return true
		}
	}
	return false
}

func cylonixWindowsActiveUser() (home string, uid, gid int) {
	sessionID := winutil.WTSGetActiveConsoleSessionId()
	if sessionID == 0xFFFFFFFF {
		// No user is currently logged on to the console.
		return "", -1, -1
	}
	var token windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
		return "", -1, -1
	}
	defer token.Close()
	tu, err := token.GetTokenUser()
	if err != nil {
		return "", -1, -1
	}
	u, err := user.LookupId(tu.User.Sid.String())
	if err != nil {
		return "", -1, -1
	}
	return u.HomeDir, -1, -1
}
