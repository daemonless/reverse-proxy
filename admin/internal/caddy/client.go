// Package caddy talks to Caddy's admin API over its unix socket and renders
// the full configuration from the admin's state.
package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Client is an HTTP client bound to Caddy's admin unix socket.
type Client struct {
	http *http.Client
}

// NewClient returns a client for the admin socket at path.
func NewClient(path string) *Client {
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}
	return &Client{http: &http.Client{
		Transport: &http.Transport{DialContext: dial},
		Timeout:   10 * time.Second,
	}}
}

// Load replaces Caddy's running configuration. A rejected config leaves the
// previous one live; the error carries Caddy's explanation.
func (c *Client) Load(cfg any) error {
	body, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	resp, err := c.http.Post("http://caddy/load", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("caddy rejected config: %s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	return nil
}

// Running reports whether Caddy answers on its admin socket.
// Stop makes Caddy exit; its supervisor starts it again with the bootstrap
// config. A reload keeps Caddy's in-memory certificate cache, so this is the
// only way to drop a cached staging certificate.
func (c *Client) Stop() error {
	resp, err := c.http.Post("http://caddy/stop", "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("caddy: stop: %s", resp.Status)
	}
	return nil
}

func (c *Client) Running() bool {
	resp, err := c.http.Get("http://caddy/config/")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode/100 == 2
}

// Loaded reports whether Caddy runs a full configuration. The bootstrap
// config has no apps, so a Caddy that restarted on its own answers null.
func (c *Client) Loaded() (bool, error) {
	resp, err := c.http.Get("http://caddy/config/apps")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return false, err
	}
	if resp.StatusCode/100 != 2 {
		return false, fmt.Errorf("caddy: %s", resp.Status)
	}
	return string(bytes.TrimSpace(body)) != "null", nil
}
