package state

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

// FieldError names the field a rejected value belongs to, so the UI can show
// the message next to it.
type FieldError struct {
	Field string
	Msg   string
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// privateSuffixes can never get a public certificate.
var privateSuffixes = []string{".lan", ".internal", ".home.arpa", ".home", ".test", ".localdomain"}

// IsPrivateSuffix reports whether a domain ends in a suffix no public CA
// will issue for.
func IsPrivateSuffix(domain string) bool {
	d := strings.ToLower(domain)
	for _, s := range privateSuffixes {
		if strings.HasSuffix(d, s) || d == s[1:] {
			return true
		}
	}
	return false
}

// IsMDNSSuffix reports a .local domain, which clashes with mDNS.
func IsMDNSSuffix(domain string) bool {
	d := strings.ToLower(domain)
	return strings.HasSuffix(d, ".local") || d == "local"
}

// ValidateDomain checks the address services live under.
func ValidateDomain(domain string) error {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "" {
		return &FieldError{"domain", "enter the address your services should live under"}
	}
	if len(d) > 253 {
		return &FieldError{"domain", "that address is too long"}
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return &FieldError{"domain", "the address needs at least one dot, like home.example.com"}
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return &FieldError{"domain", "use only letters, digits and hyphens between the dots"}
		}
	}
	if IsMDNSSuffix(d) {
		return &FieldError{"domain", "addresses ending in .local often don't work; try .lan or .home.arpa"}
	}
	return nil
}

// NormalizeDomain lower-cases and trims a validated domain.
func NormalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// ValidateLabel checks one host name label.
func ValidateLabel(field, label string) error {
	l := strings.ToLower(strings.TrimSpace(label))
	if l == "" {
		return &FieldError{field, "enter a name"}
	}
	if !labelRe.MatchString(l) {
		return &FieldError{field, "use letters, digits and hyphens only, like radarr or my-nas"}
	}
	return nil
}

// ValidateTarget checks where a service is.
func ValidateTarget(t Target) error {
	a := strings.TrimSpace(t.Address)
	if a == "" {
		return &FieldError{"target.address", "enter the address of the service"}
	}
	if _, err := netip.ParseAddr(a); err != nil {
		// Not an IP: accept a hostname.
		for _, l := range strings.Split(strings.TrimSuffix(strings.ToLower(a), "."), ".") {
			if !labelRe.MatchString(l) {
				return &FieldError{"target.address", "enter an IP address or a host name"}
			}
		}
	}
	if t.Port < 1 || t.Port > 65535 {
		return &FieldError{"target.port", "enter a port between 1 and 65535"}
	}
	return nil
}

// ValidateNetworks checks a list of CIDRs.
func ValidateNetworks(field string, nets []string) error {
	for _, n := range nets {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(n)); err != nil {
			return &FieldError{field, fmt.Sprintf("%q is not a network like 100.64.0.0/10", n)}
		}
	}
	return nil
}

// ValidateHost checks a whole host and that its names are free.
func ValidateHost(h Host, others []Host) error {
	if err := ValidateLabel("name", h.Name); err != nil {
		return err
	}
	for _, n := range h.ExtraNames {
		if err := ValidateLabel("extraNames", n); err != nil {
			return err
		}
	}
	if err := ValidateTarget(h.Target); err != nil {
		return err
	}
	switch h.Access {
	case AccessHome, AccessInternet:
	default:
		return &FieldError{"access", "choose who can open it"}
	}
	if err := ValidateNetworks("trustedNetworks", h.TrustedNetworks); err != nil {
		return err
	}
	taken := map[string]string{}
	for _, o := range others {
		if o.ID == h.ID || o.DeletedAt != nil {
			continue
		}
		taken[o.Name] = o.Name
		for _, n := range o.ExtraNames {
			taken[n] = o.Name
		}
	}
	for _, n := range append([]string{h.Name}, h.ExtraNames...) {
		if by, ok := taken[n]; ok {
			return &FieldError{"name", fmt.Sprintf("%s is already used by %s", n, by)}
		}
	}
	return nil
}

// IsFieldError reports whether err is a validation failure.
func IsFieldError(err error) bool {
	var fe *FieldError
	return errors.As(err, &fe)
}

// ValidateShortLinks checks a short-link name: one word a browser can take
// as a host name ("go"), or "" for off.
func ValidateShortLinks(name string) error {
	if name == "" {
		return nil
	}
	if !labelRe.MatchString(name) {
		return &FieldError{Field: "shortLinks", Msg: "one word: letters, digits and dashes, like go"}
	}
	return nil
}

// ShortHosts are the host names a short-link word answers to: the word as
// typed (go), and the word under each home suffix, for whoever types the
// full go.lan. Nothing longer, so it never shadows an app under a domain.
func ShortHosts(word string) []string {
	if word == "" {
		return nil
	}
	hosts := []string{word}
	for _, s := range privateSuffixes {
		hosts = append(hosts, word+s)
	}
	return hosts
}
