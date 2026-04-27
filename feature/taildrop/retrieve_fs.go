// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//go:build !android

// __BEGIN_CYLONIX_ADD__
// File added by cylonix to host the non-android implementation of
// (*manager).GetFilePath. The android stub lives in retrieve_android.go.
// fsFileOps is itself only defined for !android (fileops_fs.go), so the
// type-assertion belongs here too.
// __END_CYLONIX_ADD__

package taildrop

import (
	"errors"
	"io/fs"
)

// GetFilePath returns the absolute filesystem path for a received file. This
// is a cylonix-only accessor used by the peer-message UI on platforms where a
// real on-disk path is meaningful (i.e. NOT Android SAF). It works by
// round-tripping through the fileOps abstraction's OpenWriter (which returns
// the path as its second return value) without actually writing — the
// fsFileOps OpenWriter implementation calls os.OpenFile, which creates a
// zero-byte handle we close immediately. On non-fs FileOps (e.g. SAF),
// callers will get an error — that's expected.
func (m *manager) GetFilePath(baseName string) (path string, err error) {
	if m == nil || m.opts.fileOps == nil {
		return "", ErrNoTaildrop
	}
	if m.opts.DirectFileMode {
		return "", errors.New("get file path not allowed in direct mode")
	}
	if _, err := m.opts.fileOps.Stat(baseName + deletedSuffix); err == nil {
		return "", redactError(&fs.PathError{Op: "get file path", Path: baseName, Err: fs.ErrNotExist})
	}
	if fs, ok := m.opts.fileOps.(fsFileOps); ok {
		return joinDir(fs.rootDir, baseName)
	}
	return "", errors.New("get file path: backing fileOps does not expose a filesystem path")
}
