// Package state is the admin's single source of truth: the typed model and
// the file it persists to. Everything Caddy runs is rendered from here.
package state

import "time"

// SchemaVersion is bumped whenever State changes shape; Store migrates
// older files forward and keeps a copy of the original.
const SchemaVersion = 1

// State is the whole persisted model.
type State struct {
	SchemaVersion int        `json:"schemaVersion"`
	Settings      Settings   `json:"settings"`
	Hosts         []Host     `json:"hosts"`
	Tokens        []ApiToken `json:"tokens,omitempty"`
	// PairedKeys are the hashes of every key ever registered from
	// RP_PAIRING_KEY, so one the person removed stays removed although the
	// variable is still set.
	PairedKeys []string `json:"pairedKeys,omitempty"`
}

// Settings is everything that is not per host.
type Settings struct {
	// Domain is the address services live under, e.g. "home.example.com"
	// or "apps.home.lan". Empty until setup.
	Domain string `json:"domain"`
	// TrustedNetworks are extra CIDRs that count as the home network.
	TrustedNetworks []string `json:"trustedNetworks"`
	// AdminPasswordHash is set by setup (checkpoint 3).
	AdminPasswordHash string `json:"adminPasswordHash,omitempty"`
	// AdminAddress is host[:port] as the browser sent it the last time the
	// account set up or signed in: the one address the container knows it
	// is reached at (its published port is invisible from inside), used
	// for the links the commands and the first-run banner print.
	AdminAddress string `json:"adminAddress,omitempty"`
	// AdminIPAddress is the last such address that was an IP address: the
	// way back in when a name stops working (a new ending, a certificate
	// change), since an IP never depends on DNS or the certificate's names.
	AdminIPAddress string `json:"adminIpAddress,omitempty"`
	// Sources are other systems that know about services (Add host → From …).
	Sources Sources `json:"sources,omitempty"`
	// Certificates is set once a public domain has a DNS provider: public
	// certificates for *.Domain instead of the internal CA. The provider's
	// credentials live in the secrets directory, not here.
	Certificates *Certificates `json:"certificates,omitempty"`
	// ShortLinks is the one-word name that makes http://go/radarr open
	// radarr.<Domain>, like go links at work: nil means "go", "" is off.
	ShortLinks *string `json:"shortLinks,omitempty"`
	// Listen are the networks (subnets, 192.168.86.0/24) the proxy answers
	// on, for a container on several that reaches apps on all of them;
	// none answers on every network.
	Listen []string `json:"answerOn,omitempty"`
}

// DefaultShortLinks is the short-link name when none was chosen.
const DefaultShortLinks = "go"

// ShortName is the short-link name in use, "" when off.
func (s Settings) ShortName() string {
	if s.ShortLinks == nil {
		return DefaultShortLinks
	}
	return *s.ShortLinks
}

// Certificates is the automatic-certificate setup for a public domain.
type Certificates struct {
	Provider string `json:"provider"` // a dns.Providers id
	// Stage is StageTrial until a certificate from the staging CA proves
	// the credentials, then StageLive. A wrong token therefore never
	// counts against the real CA's limits.
	Stage     string    `json:"stage"`
	StartedAt time.Time `json:"startedAt"` // when this stage began; log lines before it are history
}

const (
	StageTrial = "trial"
	StageLive  = "live"
)

// Sources holds the connections Add host can pick from.
type Sources struct {
	Fjord *FjordSource `json:"fjord,omitempty"`
}

// FjordSource is a fjord instance to read stacks from.
type FjordSource struct {
	URL string `json:"url"`
	Key string `json:"key,omitempty"`
}

// Host is one name in front of one service.
type Host struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`                 // label under Settings.Domain
	ExtraNames []string `json:"extraNames,omitempty"` // more labels for the same service
	Target     Target   `json:"target"`
	Access     Access   `json:"access"`
	// Ref says where a host came from ("fjord:<host>:<stack>"), so a
	// source can show "already added". Empty for hand-made hosts.
	Ref string `json:"ref,omitempty"`
	// TrustedNetworks overrides Settings.TrustedNetworks for this host when set.
	TrustedNetworks []string `json:"trustedNetworks,omitempty"`
	// OwnOrigin: the app expects requests from its own address (UniFi
	// refuses a login, then every call, whose Origin or Referer names the
	// proxy). Requests from this name's own pages then reach it with its
	// address in those headers. Off by default: most apps compare Origin
	// with Host, and the rewrite would break them (Django).
	OwnOrigin bool `json:"ownOrigin,omitempty"`
	// Icon is "<hash>.<kind>" of the app's icon (server/icons.go); set by
	// its own call, never by an edit of the host.
	Icon      string     `json:"icon,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	DeletedAt *time.Time `json:"deletedAt,omitempty"` // soft delete; Undo clears it
}

// Target is where the service is.
type Target struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	HTTPS   bool   `json:"https"`
	// AcceptUntrusted lets the target use a self-signed certificate.
	AcceptUntrusted bool `json:"acceptUntrusted"`
}

// Access is who can open a host.
type Access string

const (
	AccessHome     Access = "home"     // devices on the home network only
	AccessInternet Access = "internet" // anyone
)

// ApiToken is a connected app's credential; only its hash is stored.
type ApiToken struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Hash       string     `json:"hash"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	// Paired tokens came from RP_PAIRING_KEY: the app that installed the
	// proxy chose the key, and sends it as the whole bearer token.
	Paired bool `json:"paired,omitempty"`
	// Disabled keys are refused but kept, so Reconnect (or Undo) brings
	// one back: a paired key cannot be shown again or re-entered.
	Disabled bool `json:"disabled,omitempty"`
	// URL is where the paired app is opened (RP_PAIRING_URL): the way back
	// to it from here. Optional.
	URL string `json:"url,omitempty"`
	// ClientID is the app's own permanent id (a fjord's instance id): the
	// refs of the hosts it makes carry it, so a rename or a move of the app
	// changes nothing here. Optional.
	ClientID string `json:"clientId,omitempty"`
}

// Mode is how certificates are obtained, derived from the domain suffix.
type Mode string

const (
	ModeUnset   Mode = ""        // no domain yet
	ModePublic  Mode = "public"  // real domain: wildcard via DNS challenge
	ModePrivate Mode = "private" // private suffix: internal CA
)

// Mode derives the certificate mode from the domain.
func (s Settings) Mode() Mode {
	if s.Domain == "" {
		return ModeUnset
	}
	if IsPrivateSuffix(s.Domain) {
		return ModePrivate
	}
	return ModePublic
}

// FQDN is the full name of a label under the settings domain.
func (s Settings) FQDN(label string) string {
	if s.Domain == "" {
		return label
	}
	return label + "." + s.Domain
}

// Names returns every full name a host answers to.
func (h Host) Names(s Settings) []string {
	out := []string{s.FQDN(h.Name)}
	for _, n := range h.ExtraNames {
		out = append(out, s.FQDN(n))
	}
	return out
}

// Live hosts are the ones not soft-deleted.
func (st *State) Live() []Host {
	var out []Host
	for _, h := range st.Hosts {
		if h.DeletedAt == nil {
			out = append(out, h)
		}
	}
	return out
}

// Find returns the index of the host with id, or -1.
func (st *State) Find(id string) int {
	for i, h := range st.Hosts {
		if h.ID == id {
			return i
		}
	}
	return -1
}

// UndoWindow is how long a deleted host can be restored.
const UndoWindow = 24 * time.Hour

// Purge drops soft-deleted hosts whose undo window has passed.
func (st *State) Purge(now time.Time) {
	// One removed record per name, the latest: remove-and-add-again used to
	// leave one behind each time, and a restore then picked any of them.
	// A removed name a live host holds cannot come back either.
	live := map[string]bool{}
	latest := map[string]time.Time{}
	for _, h := range st.Hosts {
		if h.DeletedAt == nil {
			live[h.Name] = true
		} else if h.DeletedAt.After(latest[h.Name]) {
			latest[h.Name] = *h.DeletedAt
		}
	}
	kept := st.Hosts[:0]
	for _, h := range st.Hosts {
		if h.DeletedAt != nil {
			if now.Sub(*h.DeletedAt) > UndoWindow {
				continue
			}
			if h.Name != "" && (live[h.Name] || !h.DeletedAt.Equal(latest[h.Name])) {
				continue
			}
		}
		kept = append(kept, h)
	}
	st.Hosts = kept
}

// Clone returns a deep copy, so a failed change never touches the live state.
func (st *State) Clone() *State {
	c := *st
	c.Settings.TrustedNetworks = append([]string(nil), st.Settings.TrustedNetworks...)
	c.Settings.Listen = append([]string(nil), st.Settings.Listen...)
	if st.Settings.Sources.Fjord != nil {
		f := *st.Settings.Sources.Fjord
		c.Settings.Sources.Fjord = &f
	}
	if st.Settings.Certificates != nil {
		cc := *st.Settings.Certificates
		c.Settings.Certificates = &cc
	}
	c.Hosts = make([]Host, len(st.Hosts))
	for i, h := range st.Hosts {
		h.ExtraNames = append([]string(nil), h.ExtraNames...)
		h.TrustedNetworks = append([]string(nil), h.TrustedNetworks...)
		if h.DeletedAt != nil {
			t := *h.DeletedAt
			h.DeletedAt = &t
		}
		c.Hosts[i] = h
	}
	c.Tokens = append([]ApiToken(nil), st.Tokens...)
	c.PairedKeys = append([]string(nil), st.PairedKeys...)
	return &c
}
