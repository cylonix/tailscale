// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Peer-message attachment sending for the outbound peer-message queue.
//
// ipnlocal's peer-message queue (ipn/ipnlocal/peermessage.go) delivers
// queued messages even while the app front-end is suspended (e.g. the iOS
// Network Extension keeps running when the app is backgrounded). Messages
// with attachments need those files pushed to the peer over Taildrop before
// the message itself is sent; this file registers the hook that does that,
// reusing the same singleFilePut path (resume support, progress reporting)
// as localapi file-put sends so the UI keeps seeing outgoing-file progress.

package taildrop

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
)

func init() {
	ipnlocal.PeerMessageFileSender = sendPeerMessageAttachment
}

// sendPeerMessageAttachment pushes one staged peer-message attachment to the
// peer over Taildrop. The file's TransferID is forwarded as the cylonix
// transfer ID so the receiver correlates the arriving file with the message
// attachment it belongs to.
func sendPeerMessageAttachment(ctx context.Context, lb *ipnlocal.LocalBackend, peer tailcfg.NodeView, file ipnlocal.PeerMessageOutgoingAttachment) error {
	ext, ok := ipnlocal.GetExt[*Extension](lb)
	if !ok {
		return fmt.Errorf("taildrop extension not registered")
	}

	fts, err := ext.FileTargets()
	if err != nil {
		return fmt.Errorf("file targets: %w", err)
	}
	var dstURL *url.URL
	for _, ft := range fts {
		if ft.Node.StableID == peer.StableID() {
			dstURL, err = url.Parse(ft.PeerAPIURL)
			if err != nil {
				return fmt.Errorf("bogus peer URL %q: %w", ft.PeerAPIURL, err)
			}
			break
		}
	}
	if dstURL == nil {
		return fmt.Errorf("peer %q is not a taildrop file target", peer.StableID())
	}

	f, err := os.Open(file.Path)
	if err != nil {
		return fmt.Errorf("open attachment: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat attachment: %w", err)
	}

	outgoing := ipn.OutgoingFile{
		ID:                 file.TransferID,
		PeerID:             peer.StableID(),
		Name:               file.Name,
		DeclaredSize:       fi.Size(),
		CylonixPeerMessage: true,
	}

	// Mirror serveFilePut's progress plumbing so the app's attachment
	// progress bars keep working for queue-driven sends.
	outgoingFiles := make(map[string]*ipn.OutgoingFile)
	t := time.NewTicker(1 * time.Second)
	progressUpdates := make(chan ipn.OutgoingFile)
	defer close(progressUpdates)
	go func() {
		defer t.Stop()
		defer ext.updateOutgoingFiles(outgoingFiles)
		for {
			select {
			case u, ok := <-progressUpdates:
				if !ok {
					return
				}
				outgoingFiles[u.ID] = &u
			case <-t.C:
				ext.updateOutgoingFiles(outgoingFiles)
			}
		}
	}()

	ww := &multiFilePostResponseWriter{}
	if !singleFilePut(lb.PeerMessageLogf, lb, ctx, progressUpdates, ww, f, dstURL, outgoing, file.TransferID) {
		return fmt.Errorf("attachment put failed")
	}
	if ww.statusCode >= 400 {
		body := ""
		if ww.body != nil {
			body = ww.body.String()
		}
		return fmt.Errorf("attachment put failed: status=%d body=%s", ww.statusCode, body)
	}
	return nil
}
