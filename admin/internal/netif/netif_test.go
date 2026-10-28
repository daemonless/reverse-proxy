package netif

import (
	"net"
	"testing"
)

func cidr(s string) *net.IPNet {
	ip, n, _ := net.ParseCIDR(s)
	n.IP = ip
	return n
}

func TestListAndFind(t *testing.T) {
	Interfaces = func() ([]Iface, error) {
		return []Iface{
			{Name: "eth1", Addrs: []*net.IPNet{cidr("192.168.5.145/24")}},
			{Name: "eth0", Addrs: []*net.IPNet{cidr("192.168.86.11/24"), cidr("fe80::1/64"), cidr("2001:db8::5/64")}},
			{Name: "eth9", Addrs: []*net.IPNet{cidr("fe80::9/64")}}, // no IPv4: not offered
		}, nil
	}
	nets := List()
	if len(nets) != 2 || nets[0].Interface != "eth0" || nets[0].Network != "192.168.86.0/24" || nets[0].Address != "192.168.86.11" {
		t.Fatalf("list: %+v", nets)
	}
	if a := nets[0].Addresses; len(a) != 2 || a[1] != "2001:db8::5" {
		t.Fatalf("eth0 binds %v (no link-local)", a)
	}
	for _, want := range []string{"eth0", "192.168.86.0/24", "192.168.86.11", "2001:db8::5", "192.168.86.0/25"} {
		if n, ok := Find(nets, want); !ok || n.Interface != "eth0" {
			t.Fatalf("Find(%q) = %+v %v", want, n, ok)
		}
	}
	if _, ok := Find(nets, "10.0.0.0/8"); ok {
		t.Fatal("found a network it is not on")
	}
	if !nets[0].Contains("192.168.86.11:443") || nets[0].Contains("192.168.5.145") {
		t.Fatal("Contains")
	}
}

func TestAddresses(t *testing.T) {
	nets := []Network{
		{Interface: "eth0", Network: "192.168.86.0/24", Address: "192.168.86.11", Addresses: []string{"192.168.86.11", "2001:db8::5"}},
		{Interface: "eth2", Network: "192.168.5.0/24", Address: "192.168.5.145", Addresses: []string{"192.168.5.145"}},
	}
	if Addresses(nets, nil) != nil {
		t.Fatal("no choice must be every network (nil)")
	}
	if got := Addresses(nets, []string{"192.168.86.0/24", "eth2", "eth0"}); len(got) != 3 || got[2] != "192.168.5.145" {
		t.Fatalf("two networks: %v", got)
	}
	if got := Addresses(nets, []string{"10.0.0.0/8"}); got == nil || len(got) != 0 {
		t.Fatalf("not on it yet must be empty, not nil: %v", got)
	}
}

func TestShut(t *testing.T) {
	nets := []Network{
		{Interface: "eth0", Network: "192.168.86.0/24", Address: "192.168.86.11"},
		{Interface: "eth1", Network: "192.168.4.0/24", Address: "192.168.4.204"},
		{Interface: "eth2", Network: "192.168.5.0/24", Address: "192.168.5.145"},
	}
	if Shut(nets, nil) != nil {
		t.Fatal("no choice shuts nothing")
	}
	if got := Shut(nets, []string{"eth0", "192.168.5.0/24"}); len(got) != 1 || got[0] != "192.168.4.0/24" {
		t.Fatalf("shut %v", got)
	}
}
