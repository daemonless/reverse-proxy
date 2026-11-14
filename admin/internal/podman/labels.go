// Package podman names containers by their labels. A container on the
// proxy's host that carries io.daemonless.proxy.name (or io.daemonless.proxy
// alone, which names it after the container) becomes a host, the same
// record a pasted address or fjord makes, with Ref "podman:<container name>".
//
// The labels own what they say (name, extra names, port, public, HTTPS,
// own origin); the UI owns the rest (trusted networks, icon, watched). A
// stopped container keeps its name and shows down; only a removed one loses
// it, restorably. Anything the proxy cannot honor is reported, never guessed.
package podman

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/daemonless/reverse-proxy/admin/internal/sources"
)

const (
	LabelOn        = "io.daemonless.proxy"
	LabelName      = "io.daemonless.proxy.name"
	LabelPort      = "io.daemonless.proxy.port"
	LabelNames     = "io.daemonless.proxy.names"
	LabelPublic    = "io.daemonless.proxy.public"
	LabelHTTPS     = "io.daemonless.proxy.https"
	LabelOwnOrigin = "io.daemonless.proxy.own-origin"
	// LabelImagePort is the port a daemonless image declares for itself.
	LabelImagePort = "io.daemonless.port"

	RefPrefix = "podman:"
)

// Container is what the unit needs to know about one container.
type Container struct {
	ID        string
	Name      string
	State     string // running, exited, created ...
	Hostname  string // what the container calls itself
	Labels    map[string]string
	HostNet   bool              // network_mode: host
	Networks  []string          // the networks it is on
	LAN       []string          // of those, macvlan/ipvlan/epair: its address is on the LAN
	IPs       map[string]string // network name -> address, when inspect knows it
	Addrs     []net.IP          // every IPv4 address it has (inspect, else ifconfig)
	Exposed   []int             // ports the image exposes
	Published map[int]int       // container port -> host port
}

// Want is what a container's labels ask for.
type Want struct {
	Ref        string
	Container  string
	Name       string
	ExtraNames []string
	Port       int
	Public     bool
	HTTPS      bool
	OwnOrigin  *bool
	// Problem is why no host can be made from this container (empty when it can).
	Problem string
	// Note is a label the proxy could not honor and says so on the host.
	Note string
}

// Labelled says whether a container asks for a name at all.
func Labelled(labels map[string]string) bool {
	if v, set := labels[LabelOn]; set {
		return truthy(v) // io.daemonless.proxy=false opts out, whatever else is set
	}
	for k := range labels {
		if strings.HasPrefix(k, LabelName) || strings.HasPrefix(k, LabelPort) || k == LabelNames || k == LabelPublic {
			return true
		}
	}
	return false
}

// Parse reads a container's labels. *homeOnly* is the proxy's mode: a
// public label is then kept home-only and noted.
func Parse(c Container, homeOnly bool) Want {
	w := Want{Ref: RefPrefix + c.Name, Container: c.Name}
	name := strings.TrimSpace(c.Labels[LabelName])
	if name == "" {
		name = c.Name
	}
	w.Name = sources.Label(name)
	if w.Name == "" {
		w.Problem = fmt.Sprintf("%s is not a usable name", name)
		return w
	}
	for _, n := range strings.Split(c.Labels[LabelNames], ",") {
		if n = sources.Label(n); n != "" && n != w.Name {
			w.ExtraNames = append(w.ExtraNames, n)
		}
	}
	w.Port, w.Problem = port(c)
	if w.Problem != "" {
		return w
	}
	if truthy(c.Labels[LabelPublic]) {
		if homeOnly {
			w.Note = "public asked, this proxy is home only"
		} else {
			w.Public = true
		}
	}
	w.HTTPS = truthy(c.Labels[LabelHTTPS])
	if v, ok := c.Labels[LabelOwnOrigin]; ok {
		b := truthy(v)
		w.OwnOrigin = &b
	}
	return w
}

// port is the label, else the image's own port, else the one exposed port.
func port(c Container) (int, string) {
	for _, key := range []string{LabelPort, LabelImagePort} {
		v := strings.TrimSpace(c.Labels[key])
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(strings.Split(v, "/")[0])
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Sprintf("%s is not a port (%s)", v, key)
		}
		return n, ""
	}
	if len(c.Exposed) == 1 {
		return c.Exposed[0], ""
	}
	if len(c.Exposed) > 1 {
		return 0, fmt.Sprintf("the image exposes %d ports; say which with %s", len(c.Exposed), LabelPort)
	}
	return 0, "no port: the image declares none, add " + LabelPort
}

// Reach is what the proxy can reach directly: the networks it is on, by
// name, and the subnets of its own interfaces (on FreeBSD inspect knows
// no address on an epair network, so an address read with ifconfig is
// matched to the proxy's own subnets instead).
type Reach struct {
	Networks []string
	Subnets  []*net.IPNet
}

// Address picks where the proxy reaches the container: its address on a
// network the proxy is on too, else the host and a published port. The
// second return is a note for the Names page, the third a problem.
func Address(c Container, reach Reach, hostAddress string, port int) (string, int, string, string) {
	for _, n := range reach.Networks {
		if ip := c.IPs[n]; ip != "" {
			return ip, port, "", ""
		}
	}
	for _, sn := range reach.Subnets {
		for _, a := range c.Addrs {
			if sn.Contains(a) {
				return a.String(), port, "", ""
			}
		}
	}
	shared := ""
	for _, n := range reach.Networks {
		for _, cn := range c.Networks {
			if cn == n {
				shared = n
			}
		}
	}
	if shared != "" && !c.HostNet && c.Published[port] == 0 {
		return "", 0, "", fmt.Sprintf("on %s with the proxy, but its address there is not known yet", shared)
	}
	// A macvlan/ipvlan container has its own address on the LAN: the proxy
	// reaches it there like any other machine, no shared network needed.
	for _, n := range c.LAN {
		if ip := c.IPs[n]; ip != "" {
			return ip, port, "", ""
		}
	}
	if len(c.LAN) == len(c.Networks) && len(c.LAN) > 0 {
		for _, a := range c.Addrs {
			if !a.IsLoopback() {
				return a.String(), port, "", ""
			}
		}
	}
	if c.HostNet {
		if hostAddress == "" {
			return "", 0, "", "runs on the host network, and the proxy does not know the host's address yet"
		}
		return hostAddress, port, "", ""
	}
	if hp := c.Published[port]; hp != 0 && hostAddress != "" {
		return hostAddress, hp, fmt.Sprintf("reached through the host's port %d: not on a network the proxy is on", hp), ""
	}
	nets := make([]string, 0, len(c.IPs))
	for n := range c.IPs {
		nets = append(nets, n)
	}
	sort.Strings(nets)
	if len(nets) == 0 {
		return "", 0, "", "not reachable: no network address and no published port"
	}
	return "", 0, "", fmt.Sprintf("not reachable: on %s, the proxy is not; publish port %d or share a network", strings.Join(nets, ", "), port)
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
