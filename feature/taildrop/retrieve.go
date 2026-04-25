// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/util/backoff"
	"tailscale.com/util/set"
)

// __BEGIN_CYLONIX_ADD__
//
// Cylonix transferID sidecar — small per-incoming-file marker that records a
// stable peer-message transfer ID alongside the file. Upstream v1.96.4
// replaced direct filesystem access with the FileOps abstraction (so Android
// can use Storage Access Framework URIs), so the sidecar reader/writer here
// goes through fileOps too. The sidecar basename is `<file>.cylonix-transfer-id`,
// which lives in the same root as the file itself.
const transferIDSidecarSuffix = ".cylonix-transfer-id"

func (m *manager) transferIDSidecarName(baseName string) string {
	return baseName + transferIDSidecarSuffix
}

func (m *manager) SetWaitingFileTransferID(baseName, transferID string) error {
	if m == nil || m.opts.fileOps == nil {
		return ErrNoTaildrop
	}
	if transferID == "" {
		return nil
	}
	wc, _, err := m.opts.fileOps.OpenWriter(m.transferIDSidecarName(baseName), 0, 0600)
	if err != nil {
		return err
	}
	if _, werr := io.WriteString(wc, strings.TrimSpace(transferID)); werr != nil {
		_ = wc.Close()
		return werr
	}
	return wc.Close()
}

func (m *manager) WaitingFileTransferID(baseName string) string {
	if m == nil || m.opts.fileOps == nil {
		return ""
	}
	rc, err := m.opts.fileOps.OpenReader(m.transferIDSidecarName(baseName))
	if err != nil {
		return ""
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (m *manager) deleteWaitingFileTransferID(baseName string) {
	if m == nil || m.opts.fileOps == nil {
		return
	}
	_ = m.opts.fileOps.Remove(m.transferIDSidecarName(baseName))
}

// __END_CYLONIX_ADD__

// HasFilesWaiting reports whether any files are buffered in [Handler.Dir].
// This always returns false when [Handler.DirectFileMode] is false.
func (m *manager) HasFilesWaiting() bool {
	if m == nil || m.opts.fileOps == nil || m.opts.DirectFileMode {
		return false
	}

	// Optimization: this is usually empty, so avoid opening
	// the directory and checking. We can't cache the actual
	// has-files-or-not values as the macOS/iOS client might
	// in the future use+delete the files directly. So only
	// keep this negative cache.
	total := m.totalReceived.Load()
	if total == m.emptySince.Load() {
		return false
	}

	files, err := m.opts.fileOps.ListFiles()
	if err != nil {
		return false
	}

	// Build a set of filenames present in Dir
	fileSet := set.Of(files...)

	for _, filename := range files {
		if isPartialOrDeleted(filename) {
			continue
		}
		if fileSet.Contains(filename + deletedSuffix) {
			continue // already handled
		}
		// Found at least one downloadable file
		return true
	}

	// No waiting files → update negative‑result cache
	m.emptySince.Store(total)
	return false
}

// WaitingFiles returns the list of files that have been sent by a
// peer that are waiting in [Handler.Dir].
// This always returns nil when [Handler.DirectFileMode] is false.
func (m *manager) WaitingFiles() ([]apitype.WaitingFile, error) {
	if m == nil || m.opts.fileOps == nil {
		return nil, ErrNoTaildrop
	}
	if m.opts.DirectFileMode {
		return nil, nil
	}
	names, err := m.opts.fileOps.ListFiles()
	if err != nil {
		return nil, redactError(err)
	}
	var ret []apitype.WaitingFile
	for _, name := range names {
		// CYLONIX_ADD: hide our transferID sidecar files from the waiting
		// file listing.
		if strings.HasSuffix(name, transferIDSidecarSuffix) {
			continue
		}
		if isPartialOrDeleted(name) {
			continue
		}
		// A corresponding .deleted marker means the file was already handled.
		if _, err := m.opts.fileOps.Stat(name + deletedSuffix); err == nil {
			continue
		}
		fi, err := m.opts.fileOps.Stat(name)
		if err != nil {
			continue
		}
		ret = append(ret, apitype.WaitingFile{
			// CYLONIX_ADD: surface the persistent transfer ID so the peer
			// message UI can correlate file events.
			ID:   m.WaitingFileTransferID(name),
			Name: name,
			Size: fi.Size(),
		})
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i].Name < ret[j].Name })
	return ret, nil
}

// DeleteFile deletes a file of the given baseName from [Handler.Dir].
// This method is only allowed when [Handler.DirectFileMode] is false.
func (m *manager) DeleteFile(baseName string) error {
	if m == nil || m.opts.fileOps == nil {
		return ErrNoTaildrop
	}
	if m.opts.DirectFileMode {
		return errors.New("deletes not allowed in direct mode")
	}
	// CYLONIX_ADD: clean up the transferID sidecar when the file is deleted.
	defer m.deleteWaitingFileTransferID(baseName)

	var bo *backoff.Backoff
	logf := m.opts.Logf
	t0 := m.opts.Clock.Now()
	for {
		err := m.opts.fileOps.Remove(baseName)
		if err != nil && !os.IsNotExist(err) {
			err = redactError(err)
			// Put a retry loop around deletes on Windows.
			//
			// Windows file descriptor closes are effectively asynchronous,
			// as a bunch of hooks run on/after close,
			// and we can't necessarily delete the file for a while after close,
			// as we need to wait for everybody to be done with it.
			// On Windows, unlike Unix, a file can't be deleted if it's open anywhere.
			// So try a few times but ultimately just leave a "foo.jpg.deleted"
			// marker file to note that it's deleted and we clean it up later.
			if runtime.GOOS == "windows" {
				if bo == nil {
					bo = backoff.NewBackoff("delete-retry", logf, 1*time.Second)
				}
				if m.opts.Clock.Since(t0) < 5*time.Second {
					bo.BackOff(context.Background(), err)
					continue
				}
				if err := m.touchFile(baseName + deletedSuffix); err != nil {
					logf("peerapi: failed to leave deleted marker: %v", err)
				}
				m.deleter.Insert(baseName + deletedSuffix)
			}
			logf("peerapi: failed to DeleteFile: %v", err)
			return err
		}
		return nil
	}
}

func (m *manager) touchFile(name string) error {
	wc, _, err := m.opts.fileOps.OpenWriter(name /* offset= */, 0, 0666)
	if err != nil {
		return redactError(err)
	}
	return wc.Close()
}

// OpenFile opens a file of the given baseName from [Handler.Dir].
// This method is only allowed when [Handler.DirectFileMode] is false.
func (m *manager) OpenFile(baseName string) (rc io.ReadCloser, size int64, err error) {
	if m == nil || m.opts.fileOps == nil {
		return nil, 0, ErrNoTaildrop
	}
	if m.opts.DirectFileMode {
		return nil, 0, errors.New("opens not allowed in direct mode")
	}
	if _, err := m.opts.fileOps.Stat(baseName + deletedSuffix); err == nil {
		return nil, 0, redactError(&fs.PathError{Op: "open", Path: baseName, Err: fs.ErrNotExist})
	}
	f, err := m.opts.fileOps.OpenReader(baseName)
	if err != nil {
		return nil, 0, redactError(err)
	}
	fi, err := m.opts.fileOps.Stat(baseName)
	if err != nil {
		f.Close()
		return nil, 0, redactError(err)
	}
	return f, fi.Size(), nil
}

// __BEGIN_CYLONIX_ADD__
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
// __END_CYLONIX_MOD__
