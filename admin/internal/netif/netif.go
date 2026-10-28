// Package netif lists the networks the container is on, and turns the one
// the proxy answers on into the addresses Caddy binds.
package netif

import (
	"net"
	"sort"
	"strings"
)

// Network is one interface with an IPv4 address: what a person picks from.
type Network struct {
	Interface string `json:"interface"`
	Network   string `json:"network"` // 192.168.86.0/24
	Address   string `json:"address"` // 192.168.86.11
	// Addresses are every address it answers on there: the IPv4 one and
	// any global IPv6 ones. Link-local addresses need a zone Caddy cannot
	// bind by name, and nobody types them.
	Addresses []string `json:"-"`
}

// Interfaces is the system's list; tests replace it.
var Interfaces = func() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Iface
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		var nets []*net.IPNet
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				nets = append(nets, n)
			}
		}
		out = append(out, Iface{Name: i.Name, Addrs: nets})
	}
	return out, nil
}

// Iface is an interface and its addresses.
type Iface struct {
	Name  string
	Addrs []*net.IPNet
}

// List is the networks the container is on, by interface name.
func List() []Network {
	ifs, err := Interfaces()
	if err != nil {
		return nil
	}
	var out []Network
	for _, i := range ifs {
		var n Network
		for _, a := range i.Addrs {
			if a.IP.IsLoopback() || a.IP.IsLinkLocalUnicast() {
				continue
			}
			if v4 := a.IP.To4(); v4 != nil && n.Address == "" {
				n.Address = v4.String()
				n.Network = (&net.IPNet{IP: v4.Mask(a.Mask), Mask: a.Mask}).String()
			}
			n.Addresses = append(n.Addresses, a.IP.String())
		}
		if n.Address == "" {
			continue
		}
		n.Interface = i.Name
		out = append(out, n)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Interface < out[b].Interface })
	return out
}

// Find is the network a setting names: its subnet (192.168.86.0/24), an
// address on it, or an interface name (eth0). ok is false when the
// container is not on it (yet: a DHCP lease still to come).
func Find(networks []Network, want string) (Network, bool) {
	want = strings.TrimSpace(want)
	_, cidr, cerr := net.ParseCIDR(want)
	ip := net.ParseIP(want)
	for _, n := range networks {
		switch {
		case n.Interface == want, n.Network == want:
			return n, true
		case cerr == nil && cidr.Contains(net.ParseIP(n.Address)):
			return n, true
		case ip != nil:
			for _, a := range n.Addresses {
				if net.ParseIP(a).Equal(ip) {
					return n, true
				}
			}
		}
	}
	return Network{}, false
}

// Contains reports whether address (an IP, maybe with a port) is on n.
func (n Network) Contains(address string) bool {
	if h, _, err := net.SplitHostPort(address); err == nil {
		address = h
	}
	ip := net.ParseIP(strings.Trim(address, "[]"))
	if ip == nil {
		return false
	}
	for _, a := range n.Addresses {
		if net.ParseIP(a).Equal(ip) {
			return true
		}
	}
	return false
}

// Addresses is what a choice of networks binds: the addresses of each one
// the container is on, in order. nil for no choice (every network); empty
// when none of them has an address yet.
func Addresses(networks []Network, wants []string) []string {
	if len(wants) == 0 {
		return nil
	}
	out := []string{}
	seen := map[string]bool{}
	for _, w := range wants {
		n, ok := Find(networks, w)
		if !ok || seen[n.Network] {
			continue
		}
		seen[n.Network] = true
		out = append(out, n.Addresses...)
	}
	return out
}

// Shut is the subnets of the networks a choice leaves out (none when there
// is no choice: every network).
func Shut(networks []Network, wants []string) []string {
	if len(wants) == 0 {
		return nil
	}
	chosen := map[string]bool{}
	for _, w := range wants {
		if n, ok := Find(networks, w); ok {
			chosen[n.Network] = true
		}
	}
	var out []string
	for _, n := range networks {
		if !chosen[n.Network] {
			out = append(out, n.Network)
		}
	}
	return out
}
