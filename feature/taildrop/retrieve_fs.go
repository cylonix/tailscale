// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//go:build !android

// __BEGIN_CYLONIX_ADD__
// File added by cylonix to host (*manager).GetFilePath. Gated to non-android
// builds because fsFileOps + joinDir are only defined for !android (see
// fileops_fs.go), and on android the FileOps backing is SAF (content://
// URIs, not filesystem paths), so a real path lookup isn't meaningful — the
// cylonix android callers (libtailscale/command.go) fall back to joining
// the configured directFileRoot with the basename rather than calling here.
//
// Why cylonix needs GetFilePath at all (vs. the upstream OpenFile):
//
// Upstream Tailscale ships taildrop in two modes:
//
//   - DirectFileMode = true: every received file is automatically dropped
//     into the user's Downloads folder (or the platform equivalent) at
//     receive time. No staging UI, no per-file save dialog.
//   - DirectFileMode = false (staged mode): files land in the taildrop
//     spool directory and the app surfaces them via OpenFile, which
//     returns an io.ReadCloser with no path information. To "save" a
//     received file the upstream UI streams the bytes through the
//     application code into whatever destination the user picked.
//
// Cylonix's flutter app uses staged mode and wants the user to confirm
// where a received file is saved (FilePicker dialog on macOS/iOS,
// copy-to-Downloads on Android). The save step in
// cylonix/lib/files_waiting_view.dart needs the staged file's actual
// on-disk path so it can do an OS-level copy/rename to the user's chosen
// destination instead of streaming the bytes through Dart. GetFilePath
// is the cylonix-only accessor that exposes that path.
//
// GetFilePath is intentionally rejected when DirectFileMode is true
// (there is no staged copy in that mode; the file is already at its
// final destination).
// __END_CYLONIX_ADD__

package taildrop

import (
	"errors"
	"io/fs"
)

// GetFilePath returns the absolute filesystem path of a staged received
// file. It type-asserts the FileOps backing to fsFileOps (the os.OpenFile
// implementation) and joins its rootDir with the basename. Returns an
// error in DirectFileMode (no staged copy exists) or when the backing
// FileOps doesn't expose a filesystem path.
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
