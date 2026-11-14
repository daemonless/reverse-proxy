package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/podman"
)

// The podman-labels command: the root unit that names containers by their
// labels. It reads podman over its socket and talks to the admin over the
// admin's socket like the hosts command, so the admin itself never holds
// socket access. It never exits on its own: no socket means idle and a
// report saying so, a broken socket means retry.

const podmanLabelsUsage = `Usage:
  reverse-proxy podman-labels [--podman-socket PATH] [--self NAME] [--interval 5m]

Names containers that carry io.daemonless.proxy labels. Runs until stopped.
`

type labelsUnit struct {
	admin    *hostsCLI
	sock     string
	self     string
	interval time.Duration
	log      *log.Logger
	// lastProblems is what was logged last, so a problem is said once.
	lastProblems string
	// waiting: labelled containers seen before setup gave an ending. Setup
	// finishing is no podman event, so the unit looks again every few
	// seconds until the names are made.
	waiting bool
	// hostWarned is the host name an unresolvable-name warning was logged for.
	hostWarned string
	// lastReport is the last report the admin took, as sent.
	lastReport string
	// off: container labels are turned off in Settings. A switch flip is
	// no podman event either, so while off the unit looks every few seconds.
	off bool
}

func podmanLabelsCmd(adminSock string, args []string) int {
	fs := flag.NewFlagSet("podman-labels", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sock := fs.String("podman-socket", "/var/run/podman/podman.sock", "podman's API socket")
	self := fs.String("self", "", "the proxy's own container name (default: this container)")
	interval := fs.Duration("interval", 5*time.Minute, "full re-read between events")
	if err := fs.Parse(args); err != nil {
		fmt.Fprint(os.Stderr, podmanLabelsUsage)
		return 2
	}
	u := &labelsUnit{
		admin:    &hostsCLI{c: socketClient(adminSock), out: os.Stdout, err: os.Stderr},
		sock:     *sock,
		self:     *self,
		interval: *interval,
		log:      log.New(os.Stdout, "[podman-labels] ", 0),
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	u.run(ctx)
	return 0
}

func (u *labelsUnit) run(ctx context.Context) {
	u.waitForAdmin(ctx)
	attempt := 0
	answered := false                  // the socket has answered since the unit started
	client := podman.NewClient(u.sock) // one client: it dials the socket path anew
	quick := 0                         // events streams that broke at once, in a row
	for ctx.Err() == nil {
		if _, err := os.Stat(u.sock); err != nil {
			if answered {
				// podman's service restarting: the socket file comes back
				// in a moment. Not "off": the mount is still there.
				if attempt == 0 {
					u.report(podmanReport{Socket: true, Error: "podman's socket went away; waiting for it to come back"})
					u.log.Printf("podman socket went away; waiting for it to come back")
				}
				attempt++
				sleep(ctx, podman.Backoff(attempt))
				continue
			}
			u.report(podmanReport{Socket: false})
			if attempt == 0 {
				u.log.Printf("no podman socket at %s: names from labels are off (mount the host's /var/run/podman to turn them on)", u.sock)
			}
			attempt++
			sleep(ctx, 30*time.Second)
			continue
		}
		if err := client.Ping(ctx); err != nil {
			u.report(podmanReport{Socket: false, Error: "the podman socket does not answer: " + err.Error()})
			u.log.Printf("podman socket does not answer (%v); retrying", err)
			sleep(ctx, podman.Backoff(attempt))
			attempt++
			continue
		}
		if attempt > 0 {
			u.log.Printf("podman socket answers")
		}
		answered = true
		attempt = 0
		began := time.Now()
		u.follow(ctx, client)
		// A stream that breaks at once (podman answers _ping but not
		// /events) must not turn into a reconcile loop with no pause.
		if time.Since(began) < 30*time.Second {
			quick++
			sleep(ctx, podman.Backoff(quick))
		} else {
			quick = 0
		}
	}
}

// follow reconciles once, then on every container event (coalesced) and
// every interval, until the events stream breaks.
func (u *labelsUnit) follow(ctx context.Context, client *podman.Client) {
	u.reconcile(ctx, client)
	kick := make(chan struct{}, 1)
	go func() {
		err := client.Events(ctx, func(ev podman.Event) {
			if podman.Interesting(ev) {
				select {
				case kick <- struct{}{}:
				default:
				}
			}
		})
		if ctx.Err() == nil {
			u.log.Printf("events stream stopped (%v); reconnecting", err)
		}
		close(kick)
	}()
	for {
		next := u.interval
		if u.waiting || u.off {
			next = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
			u.reconcile(ctx, client)
		case _, ok := <-kick:
			if !ok {
				return
			}
			sleep(ctx, time.Second) // a compose up fires several events at once
			u.reconcile(ctx, client)
		}
	}
}

// waitForAdmin gives the admin unit time to open its socket at start,
// quietly: the two come up together and the order is not fixed.
func (u *labelsUnit) waitForAdmin(ctx context.Context) {
	for i := 0; ctx.Err() == nil; i++ {
		var st struct{}
		if err := u.admin.call(http.MethodGet, "/api/v1/status", nil, &st); err == nil {
			return
		} else if i == 10 {
			u.log.Printf("still waiting for the admin: %v", err)
		}
		sleep(ctx, 2*time.Second)
	}
}

type podmanReport struct {
	Socket     bool             `json:"socket"`
	Containers int              `json:"containers"`
	Waiting    []string         `json:"waiting,omitempty"`
	Problems   []podman.Problem `json:"problems,omitempty"`
	Elsewhere  []podman.Problem `json:"elsewhere,omitempty"`
	Error      string           `json:"error,omitempty"`
}

func (u *labelsUnit) report(r podmanReport) {
	if r.Waiting == nil {
		r.Waiting = []string{}
	}
	if r.Problems == nil {
		r.Problems = []podman.Problem{}
	}
	// Only a change is sent: each report is a write of the admin's state.
	key, _ := json.Marshal(r)
	if string(key) == u.lastReport {
		return
	}
	if err := u.admin.call(http.MethodPut, "/api/v1/sources/podman", r, nil); err != nil {
		u.log.Printf("cannot report to the admin: %v", err)
		return
	}
	u.lastReport = string(key)
}

// reconcile reads podman and the admin and makes them agree.
func (u *labelsUnit) reconcile(ctx context.Context, client *podman.Client) {
	rep := podmanReport{Socket: true}
	var src struct {
		Enabled bool `json:"enabled"`
	}
	if err := u.admin.call(http.MethodGet, "/api/v1/sources/podman", nil, &src); err == nil && !src.Enabled {
		// The admin removed the names when the switch went off; say once.
		if !u.off {
			u.log.Printf("names from container labels are turned off in Settings")
			u.off, u.lastProblems = true, ""
			u.report(rep)
		}
		return
	}
	if u.off {
		u.log.Printf("names from container labels are turned on in Settings")
		u.off = false
	}
	env, err := u.env(ctx, client)
	if ctx.Err() != nil {
		return // stopping: a cut-off request is not an error
	}
	if err != nil {
		rep.Error = err.Error()
		u.log.Printf("%v", err)
		u.report(rep)
		return
	}
	containers, err := client.Labelled(ctx)
	if err != nil {
		rep.Error = "cannot list containers: " + err.Error()
		u.log.Printf("%v", rep.Error)
		u.report(rep)
		return
	}
	rep.Containers = len(containers)
	var hosts struct {
		Hosts []podman.Host `json:"hosts"`
	}
	if err := u.admin.call(http.MethodGet, "/api/v1/hosts", nil, &hosts); err != nil {
		rep.Error = "cannot read the hosts: " + err.Error()
		u.log.Printf("%v", rep.Error)
		u.report(rep)
		return
	}
	plan := podman.Reconcile(containers, hosts.Hosts, env.Env)
	rep.Problems, rep.Elsewhere = plan.Problems, plan.Elsewhere
	u.waiting = env.domain == "" && len(plan.Create) > 0
	if env.domain == "" {
		for _, in := range plan.Create {
			rep.Waiting = append(rep.Waiting, strings.TrimPrefix(in.Ref, podman.RefPrefix))
		}
		if len(rep.Waiting) > 0 && u.lastProblems != "waiting" {
			u.log.Printf("%d labelled container(s) waiting for setup to finish", len(rep.Waiting))
			u.lastProblems = "waiting"
		}
		u.report(rep)
		return
	}
	for _, in := range plan.Create {
		if err := u.admin.call(http.MethodPost, "/api/v1/hosts", in, nil); err != nil {
			rep.Problems = append(rep.Problems, podman.Problem{Container: strings.TrimPrefix(in.Ref, podman.RefPrefix), Message: err.Error()})
			continue
		}
		u.log.Printf("named container %s: %s -> %s:%d", strings.TrimPrefix(in.Ref, podman.RefPrefix), in.Name, in.Target.Address, in.Target.Port)
	}
	for id, in := range plan.Update {
		if err := u.admin.call(http.MethodPut, "/api/v1/hosts/"+url.PathEscape(id), in, nil); err != nil {
			rep.Problems = append(rep.Problems, podman.Problem{Container: strings.TrimPrefix(in.Ref, podman.RefPrefix), Message: err.Error()})
			continue
		}
		u.log.Printf("updated container %s: %s -> %s:%d", strings.TrimPrefix(in.Ref, podman.RefPrefix), in.Name, in.Target.Address, in.Target.Port)
	}
	for _, id := range plan.Delete {
		if err := u.admin.call(http.MethodDelete, "/api/v1/hosts/"+url.PathEscape(id), nil, nil); err != nil {
			u.log.Printf("cannot remove host %s: %v", id, err)
			continue
		}
		u.log.Printf("removed the name of a container that is gone (host %s)", id)
	}
	// Problems are logged when they change, not on every event.
	var lines []string
	for _, p := range rep.Problems {
		lines = append(lines, p.Container+": "+p.Message)
	}
	if joined := strings.Join(lines, "\n"); joined != u.lastProblems {
		for _, l := range lines {
			u.log.Printf("%s", l)
		}
		if joined == "" && u.lastProblems != "" {
			u.log.Printf("every labelled container has its name")
		}
		u.lastProblems = joined
	}
	u.report(rep)
}

type unitEnv struct {
	podman.Env
	domain string
}

// env is what the plan needs: the proxy's own container (networks, name)
// and the admin's domain, mode and host address.
func (u *labelsUnit) env(ctx context.Context, client *podman.Client) (unitEnv, error) {
	var out unitEnv
	self := u.self
	if self == "" {
		self, _ = os.Hostname()
	}
	me, err := client.Self(ctx, self)
	if err != nil {
		return out, fmt.Errorf("cannot find the proxy's own container in podman: %v", err)
	}
	if u.self == "" {
		u.self = me.Name // found once; a compose hostname: is not the container's name
	}
	out.Self = me.Name
	out.Reach.Networks = me.Networks
	// The unit runs inside the proxy: its interfaces say which subnets the
	// proxy reaches directly, whatever podman calls the networks.
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
				out.Reach.Subnets = append(out.Reach.Subnets, n)
			}
		}
	}
	var st struct {
		Domain   string `json:"domain"`
		Mode     string `json:"mode"`
		AdminURL string `json:"adminUrl"`
	}
	if err := u.admin.call(http.MethodGet, "/api/v1/status", nil, &st); err != nil {
		return out, errors.New("cannot read the admin's status: " + err.Error())
	}
	out.domain = st.Domain
	out.HomeOnly = st.Mode == "private"
	// A container on a network the proxy is not on is reached through a
	// port published on the host, so the host's own address is needed: the
	// machine's name from podman, resolved. The admin's address is only a
	// fallback, since a proxy with its own address on the LAN would point a
	// name at itself.
	if name, err := client.HostName(ctx); err == nil && name != "" {
		out.HostNames = append(out.HostNames, name)
		if addrs, err := net.DefaultResolver.LookupHost(ctx, name); err == nil {
			for _, a := range addrs {
				if ip := net.ParseIP(a); ip != nil && ip.To4() != nil && !ip.IsLoopback() {
					out.HostNames = append(out.HostNames, a)
					if out.HostAddress == "" {
						out.HostAddress = a
					}
				}
			}
		}
		if out.HostAddress == "" && u.hostWarned != name {
			u.log.Printf("cannot resolve the host's name %q from inside the container; a container the proxy shares no network with gets no name", name)
			u.hostWarned = name
		}
	}
	if out.HostAddress == "" {
		if pu, err := url.Parse(st.AdminURL); err == nil {
			out.HostAddress = pu.Hostname()
		}
	}
	for _, ip := range me.Addrs {
		if ip.String() == out.HostAddress {
			out.HostAddress = "" // the proxy's own address: a name there would point at itself
		}
	}
	out.Who = u.who()
	return out, nil
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// who names the app that made a host, as the Names page does: by the app's
// id in its ref ("fjord:<id>:<stack>"), else by the key that made it, else,
// for a fjord ref, the app that installed the proxy.
func (u *labelsUnit) who() func(podman.Host) string {
	var tok struct {
		Tokens []struct {
			ID       string `json:"id"`
			Label    string `json:"label"`
			ClientID string `json:"clientId"`
			Paired   bool   `json:"paired"`
		} `json:"tokens"`
	}
	if err := u.admin.call(http.MethodGet, "/api/v1/tokens", nil, &tok); err != nil {
		return nil
	}
	return func(h podman.Host) string {
		parts := strings.SplitN(h.Ref, ":", 3)
		for _, t := range tok.Tokens {
			if len(parts) > 1 && t.ClientID != "" && t.ClientID == parts[1] {
				return t.Label
			}
		}
		for _, t := range tok.Tokens {
			if h.By != "" && t.ID == h.By {
				return t.Label
			}
		}
		if parts[0] == "fjord" {
			for _, t := range tok.Tokens {
				if t.Paired {
					return t.Label
				}
			}
			return "fjord"
		}
		return ""
	}
}
