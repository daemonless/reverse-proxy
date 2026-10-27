// Package dns knows the DNS providers Caddy can edit records at, keeps the
// credentials for the one in use, and guesses which one a domain lives at.
package dns

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// Field is one thing a provider needs from the person.
type Field struct {
	Key         string `json:"key"` // the Caddy module's JSON key
	Label       string `json:"label"`
	Secret      bool   `json:"secret"`
	Placeholder string `json:"placeholder,omitempty"`
	Optional    bool   `json:"optional,omitempty"`
	// Shape, when set, is what a value must look like (a regexp), and
	// ShapeMsg what to say when it doesn't: a wrong paste is caught here,
	// not by a failed certificate.
	Shape    string `json:"-"`
	ShapeMsg string `json:"-"`
}

// Free is a provider that gives out names under its own domain at no cost:
// the person makes one there and the proxy uses it as their ending.
type Free struct {
	Suffix string `json:"suffix"` // the shared domain, e.g. duckdns.org
	SignUp string `json:"signUp"` // where the name is made
	// Steps make the name; {name} is the one the person is typing.
	Steps []string `json:"steps"`
	// Note is what to know before picking it.
	Note string `json:"note,omitempty"`
}

// Provider is one compiled-in Caddy DNS module.
type Provider struct {
	ID     string  `json:"id"` // Caddy's dns.providers.<id>
	Label  string  `json:"label"`
	Fields []Field `json:"fields"`
	// Help says where the credential comes from, in the provider's words.
	Help string `json:"help"`
	// Steps walk through making the credential; {zone} is the domain. The
	// first step goes with URL. Empty: Help alone.
	Steps []string `json:"steps,omitempty"`
	// URL opens the page that makes one, when there is a stable one.
	URL string `json:"url,omitempty"`
	// Nameservers are substrings of the zone's NS names that identify it.
	Nameservers []string `json:"-"`
	// Checked: Connect asks the provider whether the credentials work
	// (Check) before the test certificate.
	Checked bool `json:"checked,omitempty"`
	// Generic providers (a DNS server, acme-dns) are offered last.
	Generic bool `json:"generic,omitempty"`
	// Free names: set for a provider that gives them out.
	Free *Free `json:"free,omitempty"`
}

// Providers is the catalog, in the order the UI offers them. Field keys
// are the libdns provider structs' JSON tags, read from their sources.
var Providers = []Provider{
	{ID: "cloudflare", Label: "Cloudflare",
		Fields: []Field{{Key: "api_token", Label: "API token", Secret: true}},
		Help:   "Make an API token with the Zone › DNS › Edit permission for this zone.",
		// developers.cloudflare.com/fundamentals/api/get-started/create-token/
		Steps: []string{
			"Open Cloudflare's API Tokens page and sign in.",
			"Click Create Token.",
			// The blue Get started at the top makes a custom token from
			// nothing; the template is further down.
			"Find Edit zone DNS in the list and click its Use template button, not Get started.",
			"Under Zone Resources, leave Include and Specific zone, and choose {zone}.",
			"Click Continue to summary, then Create Token.",
			"Copy the token Cloudflare shows and paste it below. Cloudflare shows it only once.",
		},
		URL:         "https://dash.cloudflare.com/profile/api-tokens",
		Checked:     true,
		Nameservers: []string{"ns.cloudflare.com"}},
	{ID: "route53", Label: "Amazon Route 53",
		Fields: []Field{
			{Key: "access_key_id", Label: "Access key ID", Placeholder: "AKIA…"},
			{Key: "secret_access_key", Label: "Secret access key", Secret: true},
			{Key: "region", Label: "Region", Placeholder: "us-east-1", Optional: true},
		},
		Help:        "An IAM user or key that may change records in the hosted zone (route53:ChangeResourceRecordSets, ListHostedZones).",
		Nameservers: []string{"awsdns-"}},
	{ID: "duckdns", Label: "DuckDNS",
		Fields: []Field{{Key: "api_token", Label: "Token", Secret: true, Placeholder: "a1b2c3d4-…",
			Shape:    `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
			ShapeMsg: "a DuckDNS token is 36 characters, like a1b2c3d4-e5f6-… Copy the one next to \"token\" at the top of duckdns.org."}},
		Help: "The token at the top of your duckdns.org page.",
		Steps: []string{
			"Open duckdns.org and sign in.",
			"Copy the token shown at the top of the page, next to \"token\", and paste it below.",
		},
		URL: "https://www.duckdns.org",
		Free: &Free{Suffix: "duckdns.org", SignUp: "https://www.duckdns.org",
			Steps: []string{
				"Open duckdns.org and sign in with Google, GitHub, Reddit or X.",
				"Type {name} under \"sub domain\" and click \"add domain\".",
			}}},
	// deSEC also gave out free dedyn.io names, until it suspended new ones
	// "until further notice" (2026-09-21): here it is for domains people
	// already have there, not a free name to sign up for.
	{ID: "desec", Label: "deSEC",
		Fields:      []Field{{Key: "token", Label: "Token", Secret: true}},
		Help:        "Make a token under Token management.",
		URL:         "https://desec.io/tokens",
		Nameservers: []string{"desec.io", "desec.org"}},
	{ID: "porkbun", Label: "Porkbun",
		Fields: []Field{
			{Key: "api_key", Label: "API key", Placeholder: "pk1_…"},
			{Key: "api_secret_key", Label: "Secret key", Secret: true, Placeholder: "sk1_…"},
		},
		Help:        "Make an API key, then switch on API access for the domain on its details page.",
		URL:         "https://porkbun.com/account/api",
		Nameservers: []string{"porkbun.com"}},
	{ID: "hetzner", Label: "Hetzner",
		Fields:      []Field{{Key: "api_token", Label: "API token", Secret: true}},
		Help:        "Make an API token in the DNS console settings.",
		URL:         "https://dns.hetzner.com/settings/api-token",
		Nameservers: []string{"hetzner.com", "hetzner.de", "your-server.de"}},
	{ID: "ovh", Label: "OVH",
		Fields: []Field{
			{Key: "endpoint", Label: "Endpoint", Placeholder: "ovh-eu"},
			{Key: "application_key", Label: "Application key"},
			{Key: "application_secret", Label: "Application secret", Secret: true},
			{Key: "consumer_key", Label: "Consumer key", Secret: true},
		},
		Help:        "Create API keys with GET, PUT, POST and DELETE rights on /domain/zone/*.",
		URL:         "https://www.ovh.com/auth/api/createToken",
		Nameservers: []string{"ovh.net", "anycast.me"}},
	{ID: "gandi", Label: "Gandi",
		Fields:      []Field{{Key: "bearer_token", Label: "Personal access token", Secret: true}},
		Help:        "Make a personal access token for the organization that owns the domain, allowed to manage domain name technical configurations.",
		Nameservers: []string{"gandi.net"}},
	{ID: "rfc2136", Label: "My own DNS server (RFC 2136)", Generic: true,
		Fields: []Field{
			{Key: "server", Label: "Server", Placeholder: "ns1.example.com:53"},
			{Key: "key_name", Label: "Key name", Placeholder: "proxy-key"},
			{Key: "key_alg", Label: "Key algorithm", Placeholder: "hmac-sha256"},
			{Key: "key", Label: "Key", Secret: true},
		},
		Help: "A TSIG key the server accepts dynamic updates with (BIND, PowerDNS, Knot)."},
	{ID: "acmedns", Label: "acme-dns", Generic: true,
		Fields: []Field{
			{Key: "server_url", Label: "Server", Placeholder: "https://auth.acme-dns.io"},
			{Key: "username", Label: "Username"},
			{Key: "password", Label: "Password", Secret: true},
			{Key: "subdomain", Label: "Subdomain"},
		},
		Help: "The account acme-dns returned when you registered. Point _acme-challenge under your domain at that account's name with a CNAME record."},
}

// Find returns the provider with id.
func Find(id string) (Provider, bool) {
	for _, p := range Providers {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

// Config is the provider in use and what it was given. It lives in the
// secrets directory, never in the state file.
type Config struct {
	Provider string            `json:"provider"`
	Fields   map[string]string `json:"fields"`
}

// File is the secrets file name; the backup carries it.
const File = "dns.json"

// Load reads the saved configuration; ErrNotExist when there is none.
func Load(secrets string) (*Config, error) {
	raw, err := os.ReadFile(filepath.Join(secrets, File))
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save writes the configuration, readable by the admin only.
func Save(secrets string, c *Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		return err
	}
	p := filepath.Join(secrets, File)
	tmp, err := os.CreateTemp(secrets, ".dns-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Remove forgets the configuration.
func Remove(secrets string) error {
	err := os.Remove(filepath.Join(secrets, File))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Validate checks a configuration the person entered and trims it.
func Validate(c *Config) error {
	p, ok := Find(c.Provider)
	if !ok {
		return &state.FieldError{Field: "provider", Msg: "choose where your domain's DNS is hosted"}
	}
	clean := map[string]string{}
	for _, f := range p.Fields {
		v := strings.TrimSpace(c.Fields[f.Key])
		if v == "" && !f.Optional {
			return &state.FieldError{Field: f.Key, Msg: "enter the " + strings.ToLower(f.Label)}
		}
		if v != "" && f.Shape != "" && !regexp.MustCompile(f.Shape).MatchString(v) {
			return &state.FieldError{Field: f.Key, Msg: f.ShapeMsg}
		}
		if v != "" {
			clean[f.Key] = v
		}
	}
	c.Fields = clean
	return nil
}

// Guess is what Detect learned about a domain.
type Guess struct {
	Zone        string   `json:"zone"`               // the zone the domain is in
	Nameservers []string `json:"nameservers"`        // its NS names
	Provider    string   `json:"provider,omitempty"` // a catalog id, when recognised
}

// Detect finds the zone a domain belongs to (the nearest ancestor with NS
// records) and which provider those nameservers belong to.
func Detect(ctx context.Context, domain string) Guess {
	return detect(ctx, domain, net.DefaultResolver.LookupNS)
}

func detect(ctx context.Context, domain string, lookupNS func(context.Context, string) ([]*net.NS, error)) Guess {
	labels := strings.Split(strings.Trim(strings.ToLower(domain), "."), ".")
	// A free name is its own zone, whatever DNS says: you.duckdns.org has
	// no NS records of its own, and the shared domain is not the person's.
	for _, p := range Providers {
		if p.Free == nil {
			continue
		}
		suffix := strings.Split(p.Free.Suffix, ".")
		if n := len(labels) - len(suffix); n >= 1 && slices.Equal(labels[n:], suffix) {
			return Guess{Zone: strings.Join(labels[n-1:], "."), Nameservers: []string{}, Provider: p.ID}
		}
	}
	for i := 0; i+1 < len(labels); i++ {
		zone := strings.Join(labels[i:], ".")
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		nss, err := lookupNS(c, zone)
		cancel()
		if err != nil || len(nss) == 0 {
			continue
		}
		g := Guess{Zone: zone}
		for _, ns := range nss {
			g.Nameservers = append(g.Nameservers, strings.TrimSuffix(strings.ToLower(ns.Host), "."))
		}
		sort.Strings(g.Nameservers)
		g.Provider = match(g.Nameservers)
		return g
	}
	return Guess{}
}

func match(nameservers []string) string {
	for _, p := range Providers {
		for _, hint := range p.Nameservers {
			for _, ns := range nameservers {
				if strings.Contains(ns, hint) {
					return p.ID
				}
			}
		}
	}
	return ""
}
