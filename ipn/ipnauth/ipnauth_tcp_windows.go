// __BEGIN_CYLONIX_MOD__
//go:build ts_tcp_safesocket

package ipnauth

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"tailscale.com/ipn"
	"tailscale.com/net/netstat"
	"tailscale.com/types/logger"
	"tailscale.com/util/pidowner"
)

// GetConnIdentity extracts the identity information from the connection
// based on the user who owns the other end of the connection.
func GetConnIdentity(logf logger.Logf, c net.Conn) (ci *ConnIdentity, err error) {
	ci = &ConnIdentity{conn: c}
	la, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return ci, fmt.Errorf("parsing local address: %w", err)
	}
	ra, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return ci, fmt.Errorf("parsing local remote: %w", err)
	}
	if !la.Addr().IsLoopback() || !ra.Addr().IsLoopback() {
		return ci, errors.New("non-loopback connection")
	}
	tab, err := netstat.Get()
	if err != nil {
		return ci, fmt.Errorf("failed to get local connection table: %w", err)
	}
	pid := peerPid(tab.Entries, la, ra)
	if pid == 0 {
		return ci, errors.New("no local process found matching localhost connection")
	}
	ci.pid = pid
	return ci, nil
}

func peerPid(entries []netstat.Entry, la, ra netip.AddrPort) int {
	for _, e := range entries {
		if e.Local == ra && e.Remote == la {
			return e.Pid
		}
	}
	return 0
}

type token struct {
	userID ipn.WindowsUserID
}

func (t *token) UID() (ipn.WindowsUserID, error) {
	return t.userID, nil
}

func (t *token) Username() (string, error) {
	return "", fmt.Errorf("Username not implemented for token: %v", t)
}

func (t *token) IsAdministrator() (bool, error) {
	return false, fmt.Errorf("IsAdministrator not implemented for token: %v", t)
}

func (t *token) IsElevated() bool {
	return false // TODO: Implement this if needed
}

func (t *token) IsLocalSystem() bool {
	// https://web.archive.org/web/2024/https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
	const systemUID = ipn.WindowsUserID("S-1-5-18")
	return t.IsUID(systemUID)
}

func (t *token) UserDir(folderID string) (string, error) {
	return "", ErrNotImplemented
}

func (t *token) Close() error {
	return nil
}

func (t *token) EqualUIDs(other WindowsToken) bool {
	if t != nil && other == nil || t == nil && other != nil {
		return false
	}
	ot, ok := other.(*token)
	if !ok {
		return false
	}
	if t == ot {
		return true
	}
	return t.userID == ot.userID
}

func (t *token) IsUID(uid ipn.WindowsUserID) bool {
	return t.userID == uid
}

func (ci *ConnIdentity) WindowsToken() (WindowsToken, error) {
	uid, err := pidowner.OwnerOfPID(ci.pid)
	if err != nil {
		return nil, fmt.Errorf("failed to map connection's pid to a user (WSL?): %w", err)
	}
	return &token{userID: ipn.WindowsUserID(uid)}, nil
}

// __END_CYLONIX_MOD__
