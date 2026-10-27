package server

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A second admin on a socket that answers is refused rather than unlinking
// the first one's socket.
func TestServeUnixRefusesALiveSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	s, _ := newTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = s.ServeUnix(ctx, path)
	if err == nil || !strings.Contains(err.Error(), "already serving") {
		t.Fatalf("second admin: %v", err)
	}
	if _, err := net.Dial("unix", path); err != nil {
		t.Fatalf("the first admin's socket is gone: %v", err)
	}
}
