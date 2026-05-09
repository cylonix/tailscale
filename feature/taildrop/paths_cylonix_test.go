// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/ipn"
)

// withTempHome redirects HOME (and creates a Downloads folder) so the
// helpers under test see a sandboxed user home. Returns the temp dir.
func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "Downloads"), 0o755); err != nil {
		t.Fatalf("mkdir Downloads: %v", err)
	}
	t.Setenv("HOME", dir)
	return dir
}

func TestCylonixDefaultDownloadsRoot_EnvVarGate(t *testing.T) {
	withTempHome(t)
	t.Setenv(cylonixDownloadsEnvVar, "")
	prefs := (&ipn.Prefs{}).View()
	if got := cylonixDefaultDownloadsRoot(prefs); got != "" {
		t.Fatalf("env var unset: got %q, want empty", got)
	}
}

func TestCylonixDefaultDownloadsRoot_CurrentUserHome(t *testing.T) {
	if cylonixIsPrivilegedProcess() {
		t.Skip("skip: running as privileged user, current-user fallback is gated off")
	}
	home := withTempHome(t)
	t.Setenv(cylonixDownloadsEnvVar, "1")
	prefs := (&ipn.Prefs{}).View()
	got := cylonixDefaultDownloadsRoot(prefs)
	want := filepath.Join(home, "Downloads", cylonixDownloadsSubfolder)
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if fi, err := os.Stat(got); err != nil || !fi.IsDir() {
		t.Fatalf("expected directory at %q: %v", got, err)
	}
}

func TestCylonixDefaultDownloadsRoot_NoDownloadsDir(t *testing.T) {
	if cylonixIsPrivilegedProcess() {
		t.Skip("skip: running as privileged user, current-user fallback is gated off")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv(cylonixDownloadsEnvVar, "1")
	prefs := (&ipn.Prefs{}).View()
	if got := cylonixDefaultDownloadsRoot(prefs); got != "" {
		t.Fatalf("missing Downloads: got %q, want empty", got)
	}
}
