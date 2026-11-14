package podman

import (
	"net"
	"strings"
	"testing"
)

func ct(name string, labels map[string]string) Container {
	return Container{ID: "id-" + name, Name: name, State: "running", Labels: labels, Networks: []string{"podman"},
		IPs: map[string]string{"podman": "10.88.0.5"}, Addrs: []net.IP{net.ParseIP("10.88.0.5")}, Published: map[int]int{}}
}

var bridge = Reach{Networks: []string{"podman"}}

func TestParseNameAndShorthand(t *testing.T) {
	w := Parse(ct("radarr", map[string]string{LabelName: "Movies", LabelImagePort: "7878"}), false)
	if w.Name != "movies" || w.Port != 7878 || w.Ref != "podman:radarr" || w.Problem != "" {
		t.Fatalf("got %+v", w)
	}
	w = Parse(ct("Radarr_Movies", map[string]string{LabelOn: "true", LabelImagePort: "7878"}), false)
	if w.Name != "radarr-movies" {
		t.Fatalf("shorthand names after the container: %+v", w)
	}
	if !Labelled(map[string]string{LabelOn: "yes"}) || Labelled(map[string]string{LabelImagePort: "80"}) {
		t.Fatal("Labelled")
	}
}

func TestParsePortSources(t *testing.T) {
	c := ct("x", map[string]string{LabelOn: "true", LabelPort: "9000", LabelImagePort: "80"})
	if w := Parse(c, false); w.Port != 9000 {
		t.Fatalf("the label wins: %+v", w)
	}
	c = ct("x", map[string]string{LabelOn: "true"})
	c.Exposed = []int{1411}
	if w := Parse(c, false); w.Port != 1411 {
		t.Fatalf("one exposed port: %+v", w)
	}
	c.Exposed = []int{80, 443}
	if w := Parse(c, false); !strings.Contains(w.Problem, "exposes 2 ports") {
		t.Fatalf("several exposed: %+v", w)
	}
	c.Exposed = nil
	if w := Parse(c, false); !strings.HasPrefix(w.Problem, "no port") {
		t.Fatalf("no port: %+v", w)
	}
	c.Labels[LabelPort] = "lots"
	if w := Parse(c, false); !strings.Contains(w.Problem, "not a port") {
		t.Fatalf("bad port: %+v", w)
	}
}

func TestParseExtrasPublicHTTPSOwnOrigin(t *testing.T) {
	c := ct("unifi", map[string]string{LabelOn: "1", LabelImagePort: "8443", LabelNames: "Wifi, unifi ,net",
		LabelPublic: "true", LabelHTTPS: "true", LabelOwnOrigin: "true"})
	w := Parse(c, false)
	if strings.Join(w.ExtraNames, ",") != "wifi,net" || !w.Public || !w.HTTPS || w.OwnOrigin == nil || !*w.OwnOrigin {
		t.Fatalf("got %+v", w)
	}
	w = Parse(c, true)
	if w.Public || w.Note != "public asked, this proxy is home only" {
		t.Fatalf("home only: %+v", w)
	}
	w = Parse(ct("y", map[string]string{LabelOn: "true", LabelImagePort: "80"}), false)
	if w.OwnOrigin != nil {
		t.Fatal("own-origin absent means untouched")
	}
}

func TestAddress(t *testing.T) {
	c := ct("a", nil)
	addr, port, note, problem := Address(c, bridge, "192.168.1.5", 7878)
	if addr != "10.88.0.5" || port != 7878 || note != "" || problem != "" {
		t.Fatalf("shared network: %s %d %q %q", addr, port, note, problem)
	}
	c.Networks, c.IPs = []string{"other"}, map[string]string{"other": "10.89.0.9"}
	c.Published[7878] = 17878
	c.Addrs = []net.IP{net.ParseIP("10.89.0.9")}
	addr, port, note, _ = Address(c, bridge, "192.168.1.5", 7878)
	if addr != "192.168.1.5" || port != 17878 || !strings.Contains(note, "host's port 17878") {
		t.Fatalf("published: %s %d %q", addr, port, note)
	}
	c.Published = map[int]int{}
	if _, _, _, problem = Address(c, bridge, "192.168.1.5", 7878); !strings.Contains(problem, "on other, the proxy is not") {
		t.Fatalf("unreachable: %q", problem)
	}
	c.HostNet, c.IPs = true, nil
	if addr, port, _, _ = Address(c, Reach{}, "192.168.1.5", 7878); addr != "192.168.1.5" || port != 7878 {
		t.Fatalf("host network: %s %d", addr, port)
	}
	if _, _, _, problem = Address(c, Reach{}, "", 7878); problem == "" {
		t.Fatal("host network without a host address is a problem")
	}
}

func TestAddressEpairBySubnet(t *testing.T) {
	// jupiter: inspect knows no address on vlan5; ifconfig in the container does
	c := ct("radarr", nil)
	c.Networks, c.IPs, c.Addrs = []string{"vlan5"}, map[string]string{}, []net.IP{net.ParseIP("192.168.5.10")}
	_, own, _ := net.ParseCIDR("192.168.5.145/24")
	addr, port, note, problem := Address(c, Reach{Networks: []string{"vlan5", "lan86"}, Subnets: []*net.IPNet{own}}, "192.168.86.4", 7878)
	if addr != "192.168.5.10" || port != 7878 || note != "" || problem != "" {
		t.Fatalf("epair by subnet: %s %d %q %q", addr, port, note, problem)
	}
	c.Addrs = nil // stopped, or ifconfig failed
	if _, _, _, problem = Address(c, Reach{Networks: []string{"vlan5"}}, "192.168.86.4", 7878); !strings.Contains(problem, "on vlan5 with the proxy") {
		t.Fatalf("shared but unknown: %q", problem)
	}
}

func TestDemux(t *testing.T) {
	framed := append([]byte{1, 0, 0, 0, 0, 0, 0, 5}, []byte("hello")...)
	framed = append(framed, append([]byte{2, 0, 0, 0, 0, 0, 0, 2}, []byte("!\n")...)...)
	if got := demux(framed); got != "hello!\n" {
		t.Fatalf("framed: %q", got)
	}
	if got := demux([]byte("plain text\n")); got != "plain text\n" {
		t.Fatalf("plain: %q", got)
	}
	out := "lo0: flags=8049\n\tinet 127.0.0.1 netmask 0xff000000\neth0: flags=8843\n\tinet 192.168.5.10 netmask 0xffffff00 broadcast 192.168.5.255\n"
	m := inetRe.FindAllStringSubmatch(out, -1)
	if len(m) != 2 || m[1][1] != "192.168.5.10" {
		t.Fatalf("inet parse: %v", m)
	}
}

func TestAddressMacvlanOwnAddress(t *testing.T) {
	// venus: plex on the vlan4_net macvlan, the proxy on the default bridge
	c := ct("plex", nil)
	c.Networks, c.LAN = []string{"vlan4_net"}, []string{"vlan4_net"}
	c.IPs, c.Addrs = map[string]string{"vlan4_net": "192.168.4.2"}, []net.IP{net.ParseIP("192.168.4.2")}
	addr, port, note, problem := Address(c, bridge, "192.168.86.6", 32400)
	if addr != "192.168.4.2" || port != 32400 || note != "" || problem != "" {
		t.Fatalf("macvlan: %s %d %q %q", addr, port, note, problem)
	}
	// FreeBSD: inspect knows no address on a macvlan-style network; ifconfig does
	c.IPs = map[string]string{}
	if addr, _, _, problem = Address(c, bridge, "192.168.86.6", 32400); addr != "192.168.4.2" || problem != "" {
		t.Fatalf("macvlan by ifconfig: %s %q", addr, problem)
	}
}

func TestLabelledOptOutWins(t *testing.T) {
	if Labelled(map[string]string{LabelOn: "false", LabelPort: "8080", LabelPublic: "true"}) {
		t.Fatal("io.daemonless.proxy=false opts out even with other proxy labels")
	}
	if !Labelled(map[string]string{LabelPort: "8080"}) {
		t.Fatal("a proxy label alone still opts in")
	}
}
