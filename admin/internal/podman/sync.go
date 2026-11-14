package podman

import (
	"fmt"
	"sort"
	"strings"
)

// Host is the slice of the admin's host view the sync compares against.
type Host struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	ExtraNames      []string `json:"extraNames,omitempty"`
	Ref             string   `json:"ref,omitempty"`
	Access          string   `json:"access"`
	TrustedNetworks []string `json:"trustedNetworks,omitempty"`
	OwnOrigin       bool     `json:"ownOrigin,omitempty"`
	Note            string   `json:"note,omitempty"`
	Unwatched       bool     `json:"unwatched,omitempty"`
	By              string   `json:"by,omitempty"`
	Target          struct {
		Address         string `json:"address"`
		Port            int    `json:"port"`
		HTTPS           bool   `json:"https"`
		AcceptUntrusted bool   `json:"acceptUntrusted"`
	} `json:"target"`
}

// HostInput is what the sync sends to create or update a host: the label-
// owned fields, with the UI-owned ones copied back so nothing is lost.
type HostInput struct {
	Name            string   `json:"name"`
	ExtraNames      []string `json:"extraNames"`
	Ref             string   `json:"ref"`
	Access          string   `json:"access"`
	TrustedNetworks []string `json:"trustedNetworks"`
	OwnOrigin       *bool    `json:"ownOrigin,omitempty"`
	Note            *string  `json:"note,omitempty"`
	Target          struct {
		Address         string `json:"address"`
		Port            int    `json:"port"`
		HTTPS           bool   `json:"https"`
		AcceptUntrusted bool   `json:"acceptUntrusted"`
	} `json:"target"`
}

// Problem is a container the sync could not name, and why.
type Problem struct {
	Container string `json:"container"`
	Message   string `json:"message"`
}

// Plan is what one reconcile does.
type Plan struct {
	Create   []HostInput
	Update   map[string]HostInput // host id -> fields
	Delete   []string             // host ids whose container is gone
	Problems []Problem
	// Elsewhere are containers another app already names: the same name at
	// the same place, or another name at the same place. Not problems.
	Elsewhere []Problem
}

// Env is what the plan needs to know about the proxy itself.
type Env struct {
	Self        string // the proxy's own container name, skipped
	Reach       Reach  // what the proxy reaches directly
	HostAddress string // the host's address, for published ports and host-network containers
	HomeOnly    bool   // no internet names possible
	// HostNames are every way a name can point at the host itself: its
	// addresses and its name. A published port behind any of them is the
	// container's.
	HostNames []string
	// Who says who made a host ("fjord on jupiter"); nil: the host's name.
	Who func(Host) string
}

// who made h, for a message.
func (e Env) who(h Host) string {
	if strings.HasPrefix(h.Ref, RefPrefix) {
		return "container " + strings.TrimPrefix(h.Ref, RefPrefix)
	}
	if e.Who != nil {
		if w := e.Who(h); w != "" {
			return w
		}
	}
	if h.Ref == "" && h.By == "" {
		return "you" // made by hand on the Names page
	}
	return h.Name
}

// pointsAt says whether h already sends its name to the container's port:
// one of the container's own addresses, or the host and the port it
// publishes (the host network: the host and the port itself).
func pointsAt(h Host, c Container, port int, hostNames []string) bool {
	a := strings.ToLower(strings.TrimSuffix(h.Target.Address, "."))
	if h.Target.Port == port && !c.HostNet {
		for _, ip := range c.IPs {
			if ip == a {
				return true
			}
		}
		for _, ip := range c.Addrs {
			if ip.String() == a {
				return true
			}
		}
	}
	hostPort := c.Published[port]
	if c.HostNet {
		hostPort = port
	}
	if hostPort == 0 || h.Target.Port != hostPort {
		return false
	}
	for _, n := range hostNames {
		if n = strings.ToLower(n); n != "" && (n == a || strings.HasPrefix(a, n+".") || strings.HasPrefix(n, a+".")) {
			return true
		}
	}
	return false
}

// Reconcile turns the labelled containers and the admin's hosts into a plan.
func Reconcile(containers []Container, hosts []Host, env Env) Plan {
	p := Plan{Update: map[string]HostInput{}}
	byRef := map[string]Host{}
	taken := map[string]Host{} // every live name, label and extra, by whoever holds it
	for _, h := range hosts {
		if h.Ref != "" {
			byRef[h.Ref] = h
		}
		taken[h.Name] = h
		for _, n := range h.ExtraNames {
			taken[n] = h
		}
	}
	seen := map[string]bool{}
	claimed := map[string]string{} // names this plan hands out, by container
	for _, c := range containers {
		if c.Name == env.Self {
			continue
		}
		w := Parse(c, env.HomeOnly)
		existing, have := byRef[w.Ref]
		// A stopped container keeps its name and shows down (it has no
		// address to compare); one that never ran gets its name on start.
		if c.State != "running" {
			if have {
				seen[existing.ID] = true
			}
			continue
		}
		// A container the plan cannot name keeps the host it already has,
		// as it is, rather than losing it over a label edit gone wrong.
		keep := func() {
			if have {
				seen[existing.ID] = true
			}
		}
		if w.Problem != "" {
			p.Problems = append(p.Problems, Problem{c.Name, w.Problem})
			keep()
			continue
		}
		addr, port, note, problem := Address(c, env.Reach, env.HostAddress, w.Port)
		if problem != "" {
			p.Problems = append(p.Problems, Problem{c.Name, problem})
			keep()
			continue
		}
		conflict, same := "", ""
		for _, n := range append([]string{w.Name}, w.ExtraNames...) {
			if by, ok := claimed[n]; ok && by != c.Name {
				conflict = fmt.Sprintf("name %s is taken by container %s", n, by)
				break
			}
			if h, ok := taken[n]; ok && h.Ref != w.Ref {
				if !strings.HasPrefix(h.Ref, RefPrefix) && pointsAt(h, c, w.Port, append([]string{env.HostAddress}, env.HostNames...)) {
					same = fmt.Sprintf("already named %s by %s", n, env.who(h))
					break
				}
				conflict = fmt.Sprintf("name %s is taken by %s", n, env.who(h))
				break
			}
		}
		if same != "" {
			// One app, two sources: the other one's name stays, nothing
			// is wrong, and a name the label made earlier is not kept twice.
			p.Elsewhere = append(p.Elsewhere, Problem{c.Name, same})
			continue
		}
		if conflict != "" {
			p.Problems = append(p.Problems, Problem{c.Name, conflict})
			keep()
			continue
		}
		var also []string
		for _, h := range hosts {
			if h.Ref != w.Ref && !strings.HasPrefix(h.Ref, RefPrefix) && pointsAt(h, c, w.Port, append([]string{env.HostAddress}, env.HostNames...)) {
				also = append(also, fmt.Sprintf("%s by %s", h.Name, env.who(h)))
			}
		}
		if len(also) > 0 {
			sort.Strings(also)
			p.Elsewhere = append(p.Elsewhere, Problem{c.Name, "also named " + strings.Join(also, ", ")})
		}
		for _, n := range append([]string{w.Name}, w.ExtraNames...) {
			claimed[n] = c.Name
		}
		in := HostInput{Name: w.Name, ExtraNames: w.ExtraNames, Ref: w.Ref, Access: "home"}
		if in.ExtraNames == nil {
			in.ExtraNames = []string{}
		}
		if w.Public {
			in.Access = "internet"
		}
		in.Target.Address, in.Target.Port, in.Target.HTTPS = addr, port, w.HTTPS
		in.Target.AcceptUntrusted = w.HTTPS
		in.OwnOrigin = w.OwnOrigin
		noteText := strings.TrimSpace(strings.Join(nonEmpty(w.Note, note), "; "))
		in.Note = &noteText
		if !have {
			in.TrustedNetworks = []string{}
			p.Create = append(p.Create, in)
			continue
		}
		seen[existing.ID] = true
		in.TrustedNetworks = existing.TrustedNetworks
		if in.TrustedNetworks == nil {
			in.TrustedNetworks = []string{}
		}
		if differs(existing, in) {
			p.Update[existing.ID] = in
		}
	}
	for _, h := range hosts {
		if strings.HasPrefix(h.Ref, RefPrefix) && !seen[h.ID] {
			p.Delete = append(p.Delete, h.ID)
		}
	}
	sort.Strings(p.Delete)
	return p
}

func differs(h Host, in HostInput) bool {
	if h.Name != in.Name || !equal(h.ExtraNames, in.ExtraNames) || h.Access != in.Access {
		return true
	}
	if h.Target.Address != in.Target.Address || h.Target.Port != in.Target.Port || h.Target.HTTPS != in.Target.HTTPS {
		return true
	}
	if in.OwnOrigin != nil && h.OwnOrigin != *in.OwnOrigin {
		return true
	}
	if in.Note != nil && h.Note != *in.Note {
		return true
	}
	return false
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
