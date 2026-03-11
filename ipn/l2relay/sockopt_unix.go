//go:build !windows

package l2relay

import "syscall"

func SetReuseAddr(fd uintptr) {
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
