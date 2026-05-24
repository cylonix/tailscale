// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package taildrop

import "io/fs"

func cylonixStatUID(fs.FileInfo) (uint32, bool) {
	return 0, false
}
