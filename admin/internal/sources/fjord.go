// Package sources reads other systems that know about services, so Add
// host can be a pick instead of typing. fjord is the first; its stacks API
// already says where each app lives.
package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Service is one thing the proxy could put a name in front of.
type Service struct {
	Stack   string `json:"stack"`
	Label   string `json:"label"`   // suggested host label
	Title   string `json:"title"`   // display name
	State   string `json:"state"`   // running, stopped, partial…
	Address string `json:"address"` // where the proxy should connect
	Port    int    `json:"port"`
	WebUI   bool   `json:"webUI"` // false: nothing to open (a database, a daemon)
	Ref     string `json:"ref"`   // "fjord:<host>:<stack>", stored on the host
}

// Fjord is a connection to one fjord instance.
type Fjord struct {
	URL string // e.g. http://nas.lan:3567
	Key string // bearer token, once fjord has auth; empty is fine today
}

var (
	webPortRe = regexp.MustCompile(`(?m)^\s*web_port:\s*["']?([^"'\s]+)`)
	labelRe   = regexp.MustCompile(`[^a-z0-9-]+`)
)

// fjordStack is the slice of fjord's /api/stacks we use.
type fjordStack struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Compose     string `json:"compose"`
	Env         string `json:"env"`
	LinkHost    string `json:"linkHost"`
	OwnAddress  bool   `json:"ownAddress"`
	Status      struct {
		State string `json:"state"`
	} `json:"status"`
	State struct {
		Origin struct {
			Type string `json:"type"`
		} `json:"origin"`
	} `json:"state"`
	Services []struct {
		Name  string `json:"name"`
		Ports []struct {
			HostPort      int `json:"hostPort"`
			ContainerPort int `json:"containerPort"`
		} `json:"ports"`
	} `json:"services"`
}

// Services asks fjord for its stacks and turns each into a Service.
func (f Fjord) Services(ctx context.Context) ([]Service, error) {
	u, err := url.Parse(strings.TrimRight(f.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("the fjord address must start with http:// or https://")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String()+"/api/stacks", nil)
	if f.Key != "" {
		req.Header.Set("Authorization", "Bearer "+f.Key)
	}
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach fjord at %s (%v)", u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, errors.New("fjord refused the key")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fjord answered %s", resp.Status)
	}
	var stacks []fjordStack
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&stacks); err != nil {
		return nil, errors.New("fjord's answer was not a stack list")
	}
	host := u.Hostname()
	out := make([]Service, 0, len(stacks))
	for _, st := range stacks {
		out = append(out, serviceFor(st, host))
	}
	return out, nil
}

// serviceFor applies fjord's own rules (see its appUrl.ts): the address a
// browser can reach is linkHost when the container has its own, else the
// fjord host; the port is x-fjord web_port (env-expanded), else the first
// published host port; a catalog app without web_port has no web UI.
func serviceFor(st fjordStack, fjordHost string) Service {
	title := st.DisplayName
	if title == "" {
		title = st.Name
	}
	s := Service{
		Stack: st.Name,
		Label: Label(st.Name),
		Title: title,
		State: st.Status.State,
		Ref:   "fjord:" + fjordHost + ":" + st.Name,
	}
	s.Address = st.LinkHost
	if s.Address == "" || !st.OwnAddress {
		s.Address = fjordHost
	}
	env := parseEnv(st.Env)
	if m := webPortRe.FindStringSubmatch(st.Compose); m != nil {
		if p, err := strconv.Atoi(expand(m[1], env)); err == nil {
			s.Port = p
		}
	}
	s.WebUI = s.Port > 0 || st.State.Origin.Type != "catalog"
	if s.Port == 0 {
		for _, svc := range st.Services {
			for _, p := range svc.Ports {
				if st.OwnAddress && p.ContainerPort > 0 {
					s.Port = p.ContainerPort
				} else if p.HostPort > 0 {
					s.Port = p.HostPort
				}
				if s.Port > 0 {
					break
				}
			}
			if s.Port > 0 {
				break
			}
		}
	}
	return s
}

// Label turns a stack name into a host label: lower case, letters, digits
// and hyphens, no leading or trailing hyphen.
func Label(name string) string {
	l := labelRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	l = strings.Trim(l, "-")
	if len(l) > 63 {
		l = strings.Trim(l[:63], "-")
	}
	return l
}

func parseEnv(env string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(env, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			out[line[:i]] = strings.Trim(line[i+1:], `"'`)
		}
	}
	return out
}

var varRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

func expand(s string, env map[string]string) string {
	return varRe.ReplaceAllStringFunc(s, func(m string) string {
		sm := varRe.FindStringSubmatch(m)
		if v, ok := env[sm[1]]; ok && v != "" {
			return v
		}
		return sm[2]
	})
}

// HostOf returns the host part of a source URL, for refs.
func HostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if h, _, err := net.SplitHostPort(u.Host); err == nil {
		return h
	}
	return u.Host
}
