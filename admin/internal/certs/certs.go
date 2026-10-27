// Package certs reports how the public wildcard certificate is doing:
// what Caddy serves right now, and what its issuance log says went wrong.
package certs

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/dns"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// Issuer classes, from the certificate Caddy actually serves.
const (
	IssuerNone        = ""            // no certificate yet
	IssuerInternal    = "internal"    // the admin's own root
	IssuerStaging     = "staging"     // Let's Encrypt staging: the trial
	IssuerLetsEncrypt = "letsencrypt" // the real thing
)

// Observation is what a TLS handshake with the proxy showed.
type Observation struct {
	Issuer   string
	NotAfter time.Time
}

// Observe connects to addr with serverName and classifies the leaf.
func Observe(ctx context.Context, network, addr, serverName string) Observation {
	d := tls.Dialer{Config: &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} //nolint:gosec // classifying, not trusting
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(c, network, addr)
	if err != nil {
		return Observation{}
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return Observation{}
	}
	leaf := certs[0]
	org := strings.Join(leaf.Issuer.Organization, " ")
	obs := Observation{Issuer: IssuerInternal, NotAfter: leaf.NotAfter}
	switch {
	case strings.Contains(org, "(STAGING)") || strings.Contains(leaf.Issuer.CommonName, "(STAGING)"):
		obs.Issuer = IssuerStaging
	case strings.Contains(org, "Let's Encrypt"):
		obs.Issuer = IssuerLetsEncrypt
	}
	return obs
}

// Event is the last thing Caddy logged about the wildcard.
type Event struct {
	At     time.Time
	OK     bool   // obtained or renewed
	Issuer string // Caddy's issuer key, e.g. acme-v02.api.letsencrypt.org-directory
	Error  string
}

// LastEvent scans the issuance log for the newest line about identifier.
// Only the tail is read; the file is rolled at 1 MB anyway.
func LastEvent(path, identifier string) (Event, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Event{}, false
	}
	defer f.Close()
	const tail = 256 << 10
	if fi, err := f.Stat(); err == nil && fi.Size() > tail {
		f.Seek(fi.Size()-tail, io.SeekStart)
	}
	var last Event
	found := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if !bytes.Contains(line, []byte(identifier)) {
			continue
		}
		var rec struct {
			TS         float64 `json:"ts"`
			Msg        string  `json:"msg"`
			Identifier string  `json:"identifier"`
			Issuer     string  `json:"issuer"`
			Error      string  `json:"error"`
		}
		if json.Unmarshal(line, &rec) != nil || rec.Identifier != identifier {
			continue
		}
		ev := Event{At: time.Unix(0, int64(rec.TS*float64(time.Second))), Issuer: rec.Issuer}
		switch rec.Msg {
		case "certificate obtained successfully", "certificate renewed successfully":
			ev.OK = true
		case "could not get certificate from issuer":
			ev.Error = rec.Error
		default:
			continue
		}
		last, found = ev, true
	}
	return last, found
}

var retryAfter = regexp.MustCompile(`retry after ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC)`)

// Explain turns an issuance error into one plain message with a next
// step, matching the failure states in the plan.
func Explain(errText, zone, providerLabel string) (msg, detail string) {
	msg, detail, _ = explain(errText, zone, providerLabel)
	return msg, detail
}

// kindCAA is a failure only the person can fix, but not with a new token.
const kindCAA = "caa"

// explain also says whose move it is: a dns.Kind* or kindCAA when only the
// person can fix it, "" when retrying may (rate limits, slow DNS, outages).
func explain(errText, zone, providerLabel string) (msg, detail, kind string) {
	errText = redact(errText)
	e := strings.ToLower(errText)
	has := func(parts ...string) bool {
		for _, p := range parts {
			if strings.Contains(e, p) {
				return true
			}
		}
		return false
	}
	if zone == "" {
		zone = "your domain"
	}
	switch {
	case has("expected (ok) but got (ko)"):
		// DuckDNS says only KO: a wrong token, or a name the token's
		// account doesn't have.
		return "DuckDNS refused the token or the name. Check that " + zone + " is on the account the token comes from.", errText, dns.KindRejected
	case has("ratelimited", "rate limit", "too many certificates", "too many failed", "429"):
		when := "in an hour"
		if m := retryAfter.FindStringSubmatch(errText); m != nil {
			if t, err := time.Parse("2006-01-02 15:04:05 MST", m[1]); err == nil {
				when = "after " + t.Local().Format("15:04 on Jan 2")
			}
		}
		return "Let's Encrypt is limiting requests for " + zone + ". It will be tried again " + when + ".", errText, ""
	case has("nosuchhostedzone", "1003") || (has("zone") && has("not found", "could not find", "unknown", "no zone", "missing", "does not exist")):
		return "The token works, but it can't change records for " + zone + ". Give it access to that zone.", errText, dns.KindZone
	case has("401", "403", "unauthorized", "unauthenticated", "forbidden", "authentication", "appears invalid", "invalid token", "invalid api", "invalid key", "invalid credentials", "accessdenied", "invalidclienttokenid", "signaturedoesnotmatch", "tsig", "bad auth", "bad key", "6003", "10000"):
		return "The token was rejected by " + providerLabel + ". Check it and try again.", errText, dns.KindRejected
	case has("caa"):
		return "A CAA record on " + zone + " does not allow Let's Encrypt. Allow letsencrypt.org there, or remove it.", errText, kindCAA
	case has("propagat", "timed out waiting", "no txt record", "nxdomain", "not yet"):
		return "The verification record never showed up at " + zone + "'s nameservers. Check that " + zone + " is really hosted at " + providerLabel + "; records usually appear within two minutes.", errText, ""
	}
	return "Couldn't get a certificate. It will be tried again automatically.", errText, ""
}

// tokenInURL is a credential some providers' errors repeat in the request
// URL they quote (DuckDNS: ...&token=<uuid>&...).
var tokenInURL = regexp.MustCompile(`(?i)((?:token|key|secret|password)=)[^&\s\]"]+`)

// redact blanks credentials out of an error before anyone sees it.
func redact(errText string) string {
	return tokenInURL.ReplaceAllString(errText, "${1}…")
}

// renewalTrouble is what to say while the certificate still works but
// renewing it can't succeed until the person acts.
func renewalTrouble(kind, label, zone, until string) string {
	works := "Everything works until " + until + ": "
	switch kind {
	case dns.KindRejected:
		return label + " stopped accepting your token. " + works + "make a new token before then."
	case dns.KindZone:
		return "Your " + label + " token can't change " + zone + " any more. " + works + "give it access to " + zone + " again, or make a new token."
	case dns.KindPermission:
		return "Your " + label + " token can't change " + zone + "'s DNS records any more. " + works + "make a new token with the Edit zone DNS template."
	case kindCAA:
		return "A CAA record on " + zone + " now blocks Let's Encrypt. " + works + "allow letsencrypt.org there, or remove it."
	}
	return ""
}

// fixFor is the Status.Fix for a kind: a new token mends all but CAA.
func fixFor(kind string) string {
	if kind == "" || kind == kindCAA {
		return ""
	}
	return "token"
}

// Status is what the UI shows.
type Status struct {
	// State: manual (own root), trial (proving the token), issuing (the
	// real certificate is on its way), ok, failed.
	State    string     `json:"state"`
	Provider string     `json:"provider,omitempty"`
	Issuer   string     `json:"issuer,omitempty"`
	NotAfter *time.Time `json:"notAfter,omitempty"`
	DaysLeft int        `json:"daysLeft,omitempty"`
	Message  string     `json:"message,omitempty"`
	Detail   string     `json:"detail,omitempty"`
	Since    *time.Time `json:"since,omitempty"`
	// Fix is what mends it: "token" means a new token, pasted in Settings.
	Fix string `json:"fix,omitempty"`
}

// Compute combines the settings, what is served, the last log event and
// the last token check (nil: fine, or not checked; dns.Check knows only
// some providers, and Caddy's renewal error tells for the rest).
func Compute(s state.Settings, obs Observation, ev *Event, check *dns.Problem, zone string, now time.Time) Status {
	c := s.Certificates
	if c == nil || s.Mode() != state.ModePublic {
		return Status{State: "manual"}
	}
	label := c.Provider
	if p, ok := dns.Find(c.Provider); ok {
		label = p.Label
	}
	st := Status{Provider: c.Provider, Since: &c.StartedAt}
	fresh := ev != nil && !ev.At.Before(c.StartedAt)
	failed := func() Status {
		var kind string
		st.State = "failed"
		st.Message, st.Detail, kind = explain(ev.Error, zone, label)
		st.Fix = fixFor(kind)
		return st
	}
	switch c.Stage {
	case state.StageTrial:
		switch {
		case obs.Issuer == IssuerStaging:
			st.State = "issuing" // the watcher moves to live any moment
		case fresh && ev.Error != "":
			return failed()
		default:
			st.State = "trial"
		}
	default:
		switch {
		case obs.Issuer == IssuerLetsEncrypt:
			st.State, st.Issuer = "ok", obs.Issuer
			t := obs.NotAfter
			st.NotAfter = &t
			st.DaysLeft = int(math.Ceil(obs.NotAfter.Sub(now).Hours() / 24))
			// Said as soon as it is known, not 10 days before the end: a
			// revoked token fails every renewal from 30 days out.
			until := obs.NotAfter.Local().Format("Jan 2")
			var kind string
			if fresh && ev.Error != "" {
				_, _, kind = explain(ev.Error, zone, label)
			}
			switch {
			case check != nil:
				st.Message, st.Detail, st.Fix = renewalTrouble(check.Kind, label, zone, until), check.Msg, "token"
			case kind != "":
				st.Message, st.Detail, st.Fix = renewalTrouble(kind, label, zone, until), redact(ev.Error), fixFor(kind)
			case st.DaysLeft < 10:
				st.Message = "Renewal has been failing; the certificate runs out in " + plural(st.DaysLeft, "day") + "."
				if fresh && ev.Error != "" {
					_, st.Detail = Explain(ev.Error, zone, label)
				}
			}
		case fresh && ev.Error != "" && (obs.Issuer == IssuerNone || obs.Issuer == IssuerInternal || obs.Issuer == IssuerStaging):
			return failed()
		default:
			st.State = "issuing"
		}
	}
	return st
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

// Applier is the manager's write path.
type Applier interface {
	State() *state.State
	Apply(func(*state.State) error) error
}

// Watch moves a trial to live once the staging certificate is served:
// from then on Caddy asks the real CA. It returns when ctx ends.
// restart is called once, right after the switch to live: Caddy keeps the
// staging certificate in memory across reloads, so it must start over.
func Watch(ctx context.Context, mgr Applier, observe func(context.Context, string) Observation, restart func() error) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		tick(mgr, func(name string) Observation { return observe(ctx, name) }, restart)
	}
}

func tick(mgr Applier, observe func(string) Observation, restart func() error) {
	st := mgr.State()
	c := st.Settings.Certificates
	if c == nil || c.Stage != state.StageTrial || st.Settings.Domain == "" {
		return
	}
	if observe("proxy."+st.Settings.Domain).Issuer != IssuerStaging {
		return
	}
	err := mgr.Apply(func(st *state.State) error {
		if c := st.Settings.Certificates; c != nil && c.Stage == state.StageTrial {
			c.Stage = state.StageLive
			c.StartedAt = time.Now()
		}
		return nil
	})
	if err != nil {
		log.Printf("[admin] certificates: trial passed but switching to the real CA failed: %v", err)
		return
	}
	log.Printf("[admin] certificates: the token works (staging certificate issued); restarting Caddy to ask Let's Encrypt for the real one")
	if err := restart(); err != nil {
		log.Printf("[admin] certificates: restarting Caddy failed, the real certificate waits for the next restart: %v", err)
	}
}
