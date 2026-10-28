package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/app"
	"github.com/daemonless/reverse-proxy/admin/internal/netif"
)

// answerOn turns the chosen networks into addresses at every render, and
// renders again when they change (a new DHCP lease, a network coming up
// after the proxy did).
type answerOn struct {
	env  string // RP_LISTEN: wins over the saved choice
	mu   sync.Mutex
	want []string // the choice the last render saw
	last []string // and what it bound; nil is every network
}

// render is the addresses to bind (nil: every network) and the subnets
// shut out, for the choice saved or RP_LISTEN.
func (a *answerOn) render(saved []string) ([]string, []string) {
	want := saved
	if a.env != "" {
		want = strings.FieldsFunc(a.env, func(r rune) bool { return r == ',' || r == ' ' })
	}
	networks := netif.List()
	got := netif.Addresses(networks, want)
	a.mu.Lock()
	defer a.mu.Unlock()
	if !equal(want, a.want) || !equal(got, a.last) {
		on := strings.Join(want, ", ")
		switch {
		case got == nil:
			log.Printf("[admin] answering on every network")
		case len(got) == 0:
			log.Printf("[admin] answering on %s, which this container has no address on yet: only inside the container until it does. `reverse-proxy listen all` answers on every network again", on)
		default:
			log.Printf("[admin] answering on %s only (%s)", on, strings.Join(got, ", "))
		}
	}
	a.want, a.last = want, got
	return got, netif.Shut(networks, want)
}

// watch renders again when the chosen networks' addresses change.
func (a *answerOn) watch(ctx context.Context, m *app.Manager) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.mu.Lock()
		want, last := a.want, a.last
		a.mu.Unlock()
		if len(want) == 0 || equal(netif.Addresses(netif.List(), want), last) {
			continue
		}
		if err := m.Reload(); err != nil {
			log.Printf("[admin] the addresses on %s changed; loading the configuration failed: %v", strings.Join(want, ", "), err)
		}
	}
}

func equal(a, b []string) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// listenCmd is `reverse-proxy listen [all | <network>...]`: show or change
// the networks the proxy answers on, over the admin's socket.
func listenCmd(sock string, args []string) int {
	c := socketClient(sock)
	if len(args) == 0 {
		resp, err := c.Get("http://admin/api/v1/settings")
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot reach the admin at %s: %v\n", sock, err)
			return 1
		}
		defer resp.Body.Close()
		return printListen(resp)
	}
	want := args
	if len(args) == 1 && args[0] == "all" {
		want = []string{}
	}
	body, _ := json.Marshal(map[string][]string{"listen": want})
	resp, err := c.Post("http://admin/internal/listen", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot reach the admin at %s: %v\n", sock, err)
		return 1
	}
	defer resp.Body.Close()
	return printListen(resp)
}

func printListen(resp *http.Response) int {
	data, _ := io.ReadAll(resp.Body)
	var out struct {
		Error    string          `json:"error"`
		Listen   []string        `json:"listen"`
		SetBy    string          `json:"listenSetBy"`
		Networks []netif.Network `json:"networks"`
	}
	if json.Unmarshal(data, &out) != nil || resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "%s\n", strings.TrimSpace(cmpStr(out.Error, resp.Status+" "+string(data))))
		return 1
	}
	if len(out.Listen) == 0 {
		fmt.Println("Answers on every network:")
	} else {
		fmt.Printf("Answers on %s only", strings.Join(out.Listen, " and "))
		if out.SetBy != "" {
			fmt.Printf(" (set by %s)", out.SetBy)
		}
		fmt.Println(". Its networks:")
	}
	for _, n := range out.Networks {
		mark := " "
		if slices.Contains(out.Listen, n.Network) {
			mark = "*"
		}
		fmt.Printf("  %s %-6s %-18s %s\n", mark, n.Interface, n.Network, n.Address)
	}
	return 0
}

func cmpStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
