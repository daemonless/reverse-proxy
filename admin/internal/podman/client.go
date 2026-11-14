package podman

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client is podman's libpod API over its unix socket.
type Client struct {
	Socket  string
	http    *http.Client
	mu      sync.Mutex
	drivers map[string]string // network name -> driver, asked once
}

func NewClient(socket string) *Client {
	return &Client{Socket: socket, drivers: map[string]string{}, http: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}}
}

const apiBase = "http://podman/v5.0.0/libpod"

// requestTimeout bounds one API call (not the events stream): a podman that
// stalls on a stuck container must not hold the unit's only reconcile.
const requestTimeout = 30 * time.Second

// errGone is a container that went away between being listed and inspected.
var errGone = errors.New("no such container")

func (c *Client) get(ctx context.Context, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		err := fmt.Errorf("podman %s: %s: %s", path, resp.Status, strings.TrimSpace(string(raw)))
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("%w: %v", errGone, err)
		}
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// HostName is the name of the machine podman runs on, from /info.
func (c *Client) HostName(ctx context.Context) (string, error) {
	var info struct {
		Host struct {
			Hostname string `json:"hostname"`
		} `json:"host"`
	}
	if err := c.get(ctx, "/info", &info); err != nil {
		return "", err
	}
	return info.Host.Hostname, nil
}

// Ping says whether the socket answers (the answer is the text "OK").
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/_ping", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(raw)) != "OK" {
		return fmt.Errorf("podman _ping: %s %q", resp.Status, strings.TrimSpace(string(raw)))
	}
	return nil
}

type listed struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

type inspected struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	State  struct{ Status string }
	Config struct {
		Hostname     string                     `json:"Hostname"`
		Labels       map[string]string          `json:"Labels"`
		ExposedPorts map[string]json.RawMessage `json:"ExposedPorts"`
	}
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	}
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
		Ports map[string][]struct {
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	}
}

// Labelled lists the containers that ask for a name, inspected.
func (c *Client) Labelled(ctx context.Context) ([]Container, error) {
	var all []listed
	if err := c.get(ctx, "/containers/json?all=true", &all); err != nil {
		return nil, err
	}
	var out []Container
	for _, l := range all {
		if !Labelled(l.Labels) {
			continue
		}
		ct, err := c.Inspect(ctx, l.ID)
		if errors.Is(err, errGone) {
			continue // removed since the list: its name goes, as it should
		}
		if err != nil {
			return nil, err
		}
		out = append(out, ct)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Self finds the container this process runs in: by the hostname as an id
// or name (podman's default), else the running container whose hostname
// was set to it (a compose `hostname:`).
func (c *Client) Self(ctx context.Context, hostname string) (Container, error) {
	if ct, err := c.Inspect(ctx, hostname); err == nil {
		return ct, nil
	}
	var all []listed
	if err := c.get(ctx, "/containers/json", &all); err != nil {
		return Container{}, err
	}
	for _, l := range all {
		ct, err := c.Inspect(ctx, l.ID)
		if err == nil && ct.Hostname == hostname {
			return ct, nil
		}
	}
	return Container{}, fmt.Errorf("no container is named or has the hostname %q", hostname)
}

// Inspect reads one container by id or name. On FreeBSD, inspect reports
// no address for a container on an epair (macvlan-style) network; a running
// one is then asked with ifconfig and each address matched to its network's
// subnet.
func (c *Client) Inspect(ctx context.Context, id string) (Container, error) {
	var in inspected
	if err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &in); err != nil {
		return Container{}, err
	}
	ct := Container{
		ID: in.ID, Name: strings.TrimPrefix(in.Name, "/"), State: in.State.Status, Hostname: in.Config.Hostname,
		Labels: in.Config.Labels, HostNet: in.HostConfig.NetworkMode == "host",
		IPs: map[string]string{}, Published: map[int]int{},
	}
	blank := false
	for n, v := range in.NetworkSettings.Networks {
		ct.Networks = append(ct.Networks, n)
		if d := c.driver(ctx, n); d == "macvlan" || d == "ipvlan" || d == "epair" {
			ct.LAN = append(ct.LAN, n)
		}
		if v.IPAddress != "" {
			ct.IPs[n] = v.IPAddress
			if ip := net.ParseIP(v.IPAddress); ip != nil {
				ct.Addrs = append(ct.Addrs, ip)
			}
		} else {
			blank = true
		}
	}
	sort.Strings(ct.Networks)
	sort.Strings(ct.LAN)
	if blank && ct.State == "running" {
		if addrs, err := c.ifconfig(ctx, in.ID); err == nil {
			ct.Addrs = append(ct.Addrs, addrs...)
		}
	}
	for spec := range in.Config.ExposedPorts {
		if p := portOf(spec); p > 0 {
			ct.Exposed = append(ct.Exposed, p)
		}
	}
	sort.Ints(ct.Exposed)
	for spec, binds := range in.NetworkSettings.Ports {
		p := portOf(spec)
		for _, b := range binds {
			if hp, _ := strconv.Atoi(b.HostPort); p > 0 && hp > 0 {
				ct.Published[p] = hp
			}
		}
	}
	return ct, nil
}

// driver is a network's driver ("bridge", "macvlan" ...); empty when podman
// does not say. Remembered: a network's driver never changes.
func (c *Client) driver(ctx context.Context, name string) string {
	c.mu.Lock()
	d, ok := c.drivers[name]
	c.mu.Unlock()
	if ok {
		return d
	}
	var nw struct {
		Driver string `json:"driver"`
	}
	if err := c.get(ctx, "/networks/"+url.PathEscape(name)+"/json", &nw); err != nil {
		return ""
	}
	c.mu.Lock()
	c.drivers[name] = nw.Driver
	c.mu.Unlock()
	return nw.Driver
}

var inetRe = regexp.MustCompile(`(?m)^\s*inet (\d+\.\d+\.\d+\.\d+)`)

// ifconfig runs ifconfig inside a container and returns its IPv4 addresses
// but loopback: the ground truth for epair networks.
func (c *Client) ifconfig(ctx context.Context, id string) ([]net.IP, error) {
	out, err := c.Exec(ctx, id, []string{"ifconfig"})
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, m := range inetRe.FindAllStringSubmatch(out, -1) {
		if ip := net.ParseIP(m[1]); ip != nil && !ip.IsLoopback() {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// Exec runs a command in a container and returns what it printed.
func (c *Client) Exec(ctx context.Context, id string, cmd []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	body, _ := json.Marshal(map[string]any{"Cmd": cmd, "AttachStdout": true, "AttachStderr": true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/containers/"+url.PathEscape(id)+"/exec", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	var made struct {
		ID string `json:"Id"`
	}
	err = json.NewDecoder(resp.Body).Decode(&made)
	resp.Body.Close()
	if err != nil || made.ID == "" {
		return "", fmt.Errorf("exec create: %s", resp.Status)
	}
	start, _ := json.Marshal(map[string]any{"Detach": false, "Tty": false})
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/exec/"+made.ID+"/start", bytes.NewReader(start))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return demux(raw), nil
}

// demux strips the stream frames (8-byte header: type, 3 zero bytes, big
// endian length) an exec without a tty is sent in; plain output passes.
func demux(raw []byte) string {
	if len(raw) < 8 || raw[0] > 2 || raw[1] != 0 || raw[2] != 0 || raw[3] != 0 {
		return string(raw)
	}
	var out bytes.Buffer
	for len(raw) >= 8 {
		n := int(binary.BigEndian.Uint32(raw[4:8]))
		raw = raw[8:]
		if n > len(raw) {
			n = len(raw)
		}
		out.Write(raw[:n])
		raw = raw[n:]
	}
	return out.String()
}

// portOf reads "1411/tcp" as 1411; udp-only entries do not count.
func portOf(spec string) int {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) == 2 && parts[1] == "udp" {
		return 0
	}
	n, _ := strconv.Atoi(parts[0])
	return n
}

// Event is one line of the events stream.
type Event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
}

// Events follows container events until ctx ends or the stream breaks;
// each event is handed to fn. The error says why it stopped.
func (c *Client) Events(ctx context.Context, fn func(Event)) error {
	q := url.Values{"stream": {"true"}, "filters": {`{"type":["container"]}`}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/events?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("podman events: %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		fn(ev)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return fmt.Errorf("events stream ended")
}

// Interesting says whether an event can change a name: anything but the
// chatter of a running container (exec, health, attach).
func Interesting(ev Event) bool {
	switch ev.Action {
	case "create", "start", "died", "stop", "remove", "rename", "restart", "init", "cleanup":
		return true
	}
	return false
}

// Backoff waits between reconnects: 2 s doubling to a minute.
func Backoff(attempt int) time.Duration {
	d := 2 * time.Second << uint(attempt)
	if d > time.Minute {
		d = time.Minute
	}
	return d
}
