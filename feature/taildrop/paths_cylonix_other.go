// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package taildrop

import "io/fs"

func cylonixStatUID(fs.FileInfo) (uint32, bool) {
	return 0, false
}

// cylonixStatOwnerIDs returns the numeric uid and gid that own fi, or ok=false
// if they cannot be determined. Always ok=false on non-unix platforms.
func cylonixStatOwnerIDs(fs.FileInfo) (uid, gid uint32, ok bool) {
	return 0, 0, false
}
