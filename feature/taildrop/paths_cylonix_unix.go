// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package taildrop

import (
	"io/fs"
	"syscall"
)

func cylonixStatUID(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// cylonixStatOwnerIDs returns the numeric uid and gid that own fi, or ok=false
// if they cannot be determined.
func cylonixStatOwnerIDs(fi fs.FileInfo) (uid, gid uint32, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}
