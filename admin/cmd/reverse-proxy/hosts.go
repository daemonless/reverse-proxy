package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// The hosts command: the v1 hosts API from inside the container, over the
// admin's unix socket (no key needed there). Same calls as openapi.json.

const hostsUsage = `Usage:
  reverse-proxy hosts                            list hosts
  reverse-proxy hosts add NAME ADDRESS:PORT      add one (NAME is the label: radarr)
      --https          the service itself speaks HTTPS (detected when left out)
      --internet       open to the internet, not just the home network
  reverse-proxy hosts remove NAME                remove one (restorable for 24 hours)
  reverse-proxy hosts restore NAME               bring a removed one back
`

// socketClient talks HTTP to the admin over its unix socket.
func socketClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}, Timeout: 30 * time.Second}
}

type apiHost struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	ExtraNames []string `json:"extraNames,omitempty"`
	Names      []string `json:"names"`
	URL        string   `json:"url"`
	Access     string   `json:"access"`
	Ref        string   `json:"ref,omitempty"`
	DeletedAt  *string  `json:"deletedAt,omitempty"`
	Target     struct {
		Address         string `json:"address"`
		Port            int    `json:"port"`
		HTTPS           bool   `json:"https"`
		AcceptUntrusted bool   `json:"acceptUntrusted"`
	} `json:"target"`
}

type hostsCLI struct {
	c   *http.Client
	out io.Writer
	err io.Writer
}

func hostsCmd(sock string, args []string) int {
	h := &hostsCLI{c: socketClient(sock), out: os.Stdout, err: os.Stderr}
	if len(args) == 0 {
		return h.list()
	}
	switch args[0] {
	case "list", "ls":
		return h.list()
	case "add":
		return h.add(args[1:])
	case "remove", "rm":
		return h.remove(args[1:])
	case "restore":
		return h.restore(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(h.out, hostsUsage)
		return 0
	}
	fmt.Fprintf(h.err, "reverse-proxy hosts: unknown command %q\n\n%s", args[0], hostsUsage)
	return 2
}

// call makes one API request and decodes a JSON object; an error status
// becomes a message in the proxy's own words.
func (h *hostsCLI) call(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://admin"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.c.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the admin: %v (is the container running?)", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e struct {
			Error, Field, Detail string
		}
		json.Unmarshal(raw, &e)
		switch {
		case e.Error == "":
			return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(raw)))
		case e.Detail != "":
			return fmt.Errorf("%s (%s)", e.Error, e.Detail)
		case e.Field != "":
			return fmt.Errorf("%s: %s", e.Field, e.Error)
		}
		return fmt.Errorf("%s", e.Error)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (h *hostsCLI) fail(err error) int {
	fmt.Fprintf(h.err, "reverse-proxy hosts: %v\n", err)
	return 1
}

// domain is the ending, or an error that says to finish setup first.
func (h *hostsCLI) domain() (string, error) {
	var st struct {
		Domain   string `json:"domain"`
		AdminURL string `json:"adminUrl"`
		Setup    struct {
			Complete bool `json:"complete"`
		} `json:"setup"`
	}
	if err := h.call("GET", "/api/v1/status", nil, &st); err != nil {
		return "", err
	}
	if !st.Setup.Complete || st.Domain == "" {
		where := st.AdminURL
		if where == "" {
			where = adminPlace
		}
		return "", fmt.Errorf("the proxy is not set up yet; open %s first", where)
	}
	return st.Domain, nil
}

func (h *hostsCLI) hosts() ([]apiHost, error) {
	var res struct {
		Hosts []apiHost `json:"hosts"`
	}
	err := h.call("GET", "/api/v1/hosts?include=removed", nil, &res)
	return res.Hosts, err
}

// find matches a label (radarr) or a full name (radarr.apps.lan); deleted
// says which kind of host is wanted.
func find(hosts []apiHost, name string, deleted bool) *apiHost {
	name = strings.ToLower(strings.TrimSpace(name))
	for i := range hosts {
		x := &hosts[i]
		if (x.DeletedAt != nil) != deleted {
			continue
		}
		if x.Name == name {
			return x
		}
		for _, n := range x.Names {
			if n == name {
				return x
			}
		}
	}
	return nil
}

func accessWords(a string) string {
	if a == "internet" {
		return "open to the internet"
	}
	return "home network only"
}

func target(x apiHost) string {
	t := net.JoinHostPort(x.Target.Address, strconv.Itoa(x.Target.Port))
	if x.Target.HTTPS {
		return "https://" + t
	}
	return t
}

func (h *hostsCLI) list() int {
	if _, err := h.domain(); err != nil {
		return h.fail(err)
	}
	hosts, err := h.hosts()
	if err != nil {
		return h.fail(err)
	}
	if len(hosts) == 0 {
		fmt.Fprintln(h.out, "No hosts yet. Add one:\n\n    reverse-proxy hosts add radarr 192.168.1.20:7878")
		return 0
	}
	w := tabwriter.NewWriter(h.out, 0, 8, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTARGET\tACCESS\t")
	for _, x := range hosts {
		note := ""
		if x.DeletedAt != nil {
			note = "removed; restore with: reverse-proxy hosts restore " + x.Name
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", x.Names[0], target(x), accessWords(x.Access), note)
	}
	w.Flush()
	return 0
}

func (h *hostsCLI) add(args []string) int {
	fs := flag.NewFlagSet("hosts add", flag.ContinueOnError)
	fs.SetOutput(h.err)
	https := fs.Bool("https", false, "the service itself speaks HTTPS")
	internet := fs.Bool("internet", false, "open to the internet")
	// Flags may follow the positional arguments (hosts add radarr host:port --https).
	var pos []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		rest = fs.Args()
		if len(rest) > 0 {
			pos = append(pos, rest[0])
			rest = rest[1:]
		}
	}
	if len(pos) != 2 {
		fmt.Fprint(h.err, hostsUsage)
		return 2
	}
	name := pos[0]
	addr, portStr, err := net.SplitHostPort(pos[1])
	if err != nil {
		return h.fail(fmt.Errorf("give the service as ADDRESS:PORT, like 192.168.1.20:7878"))
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return h.fail(fmt.Errorf("%q is not a port", portStr))
	}
	if _, err := h.domain(); err != nil {
		return h.fail(err)
	}

	// Detect what is there, as the UI does: HTTPS and its certificate.
	var probe struct {
		Reachable     bool `json:"reachable"`
		HTTPS         bool `json:"https"`
		UntrustedCert bool `json:"untrustedCert"`
	}
	h.call("GET", "/api/v1/probe?address="+addr+"&port="+portStr, nil, &probe)

	in := map[string]any{"name": name, "access": "home"}
	if *internet {
		in["access"] = "internet"
	}
	t := map[string]any{"address": addr, "port": port, "https": *https || probe.HTTPS, "acceptUntrusted": probe.HTTPS && probe.UntrustedCert}
	in["target"] = t
	var made apiHost
	if err := h.call("POST", "/api/v1/hosts", in, &made); err != nil {
		return h.fail(err)
	}
	fmt.Fprintf(h.out, "%s  ->  %s, %s.\n", made.URL, target(made), accessWords(made.Access))
	switch {
	case !probe.Reachable:
		fmt.Fprintf(h.out, "Nothing answered at %s:%d just now; the name is served and will work once the service is up.\n", addr, port)
	case probe.HTTPS && probe.UntrustedCert:
		fmt.Fprintln(h.out, "The service uses a self-signed certificate; the proxy accepts it.")
	}
	return 0
}

func (h *hostsCLI) remove(args []string) int {
	if len(args) != 1 {
		fmt.Fprint(h.err, hostsUsage)
		return 2
	}
	hosts, err := h.hosts()
	if err != nil {
		return h.fail(err)
	}
	x := find(hosts, args[0], false)
	if x == nil {
		return h.fail(fmt.Errorf("no host called %q; reverse-proxy hosts lists them", args[0]))
	}
	var res struct {
		UndoUntil time.Time `json:"undoUntil"`
	}
	if err := h.call("DELETE", "/api/v1/hosts/"+x.ID, nil, &res); err != nil {
		return h.fail(err)
	}
	fmt.Fprintf(h.out, "Removed %s. Until %s you can bring it back:\n\n    reverse-proxy hosts restore %s\n", x.Names[0], res.UndoUntil.Local().Format("15:04 on Jan 2"), x.Name)
	return 0
}

func (h *hostsCLI) restore(args []string) int {
	if len(args) != 1 {
		fmt.Fprint(h.err, hostsUsage)
		return 2
	}
	hosts, err := h.hosts()
	if err != nil {
		return h.fail(err)
	}
	x := find(hosts, args[0], true)
	if x == nil {
		if find(hosts, args[0], false) != nil {
			fmt.Fprintf(h.out, "%s is already live.\n", args[0])
			return 0
		}
		return h.fail(fmt.Errorf("no removed host called %q", args[0]))
	}
	var back apiHost
	if err := h.call("POST", "/api/v1/hosts/"+x.ID+"/restore", nil, &back); err != nil {
		return h.fail(err)
	}
	fmt.Fprintf(h.out, "%s is back  ->  %s, %s.\n", back.URL, target(back), accessWords(back.Access))
	return 0
}
