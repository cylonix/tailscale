// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//go:build !android

// __BEGIN_CYLONIX_ADD__
// File added by cylonix to host (*manager).GetFilePath, gated to non-android
// builds. fsFileOps + joinDir are only defined for !android (see
// fileops_fs.go), and on android the FileOps backing is SAF (content://
// URIs, not filesystem paths), so a real path lookup isn't meaningful — the
// cylonix android callers (libtailscale/command.go) fall back to joining the
// configured directFileRoot with the basename rather than calling here.
// __END_CYLONIX_ADD__

package taildrop

import (
	"errors"
	"io/fs"
)

// GetFilePath returns the absolute filesystem path for a received file.
// It type-asserts the FileOps backing to fsFileOps (the os.OpenFile-backed
// implementation) and joins its rootDir with the basename. On non-fs
// backings, callers get an error.
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
