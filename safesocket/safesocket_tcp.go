// __BEGIN_CYLONIX_MOD__
//go:build ts_tcp_safesocket

package safesocket

import (
	"context"
	"fmt"
	"log"
	"net"
)

func connect(ctx context.Context, path string) (net.Conn, error) {
	pipe, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", 41112))
	if err != nil {
		return nil, err
	}
	return pipe, err
}
func listen(path string) (_ net.Listener, _ error) {
	port := 41112
	log.Printf("listening at tcp @ port %v", port)
	pipe, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	return pipe, err
}

// __END_CYLONIX_MOD__
