// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//go:build android

// __BEGIN_CYLONIX_ADD__
// File added by cylonix to provide an android-only stub of
// (*manager).GetFilePath. The non-android impl lives in retrieve_fs.go.
// On android the FileOps backing is SAF (URIs, not filesystem paths), so a
// real on-disk path lookup isn't meaningful — callers should fall back to
// joining the configured directFileRoot with the basename.
// __END_CYLONIX_ADD__

package taildrop

import "errors"

// GetFilePath always returns an error on android: there is no public
// filesystem path for SAF-backed received files.
func (m *manager) GetFilePath(baseName string) (path string, err error) {
	return "", errors.New("taildrop: GetFilePath not supported on android (SAF-backed)")
}
