// Package ca makes the private-mode root certificate. The admin owns the
// root so it can restrict it to the user's domain: a stolen key then cannot
// mint certificates for anything else. Caddy issues the intermediate and
// the leaves under it.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Root describes the root certificate on disk.
type Root struct {
	CertPath    string
	KeyPath     string
	Domain      string
	Fingerprint string // SHA-256 of the DER, colon-separated, upper case
	NotAfter    time.Time
	Created     bool // true when Ensure just generated it
}

const (
	certFile = "ca-root.crt"
	keyFile  = "ca-root.key"
	lifetime = 10 * 365 * 24 * time.Hour
)

// Ensure returns the root for domain, generating it on first use or when
// the domain changed. The old pair is kept beside it with a timestamp, and
// an ending that comes back gets its kept root back: the devices that
// trusted it still do, so a round trip costs nobody a re-trust.
func Ensure(dir, domain string) (*Root, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, errors.New("no domain")
	}
	certPath := filepath.Join(dir, certFile)
	keyPath := filepath.Join(dir, keyFile)

	if r, err := Load(dir); err == nil {
		if r.Domain == domain {
			return r, nil
		}
		stamp := time.Now().UTC().Format("20060102T150405Z")
		_ = os.Rename(certPath, certPath+"."+r.Domain+"."+stamp)
		_ = os.Rename(keyPath, keyPath+"."+r.Domain+"."+stamp)
	}
	if stamp := keptStamp(dir, domain); stamp != "" {
		if os.Rename(certPath+"."+domain+"."+stamp, certPath) == nil && os.Rename(keyPath+"."+domain+"."+stamp, keyPath) == nil {
			if r, err := Load(dir); err == nil && r.Domain == domain {
				return r, nil
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   domain + " proxy root",
			Organization: []string{"reverse-proxy"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(lifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// The whole point: only names under the domain may be issued.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	r, err := Load(dir)
	if err != nil {
		return nil, err
	}
	r.Created = true
	return r, nil
}

// keptStamp is the newest kept pair for domain ("" when none): the stamp
// after "ca-root.crt.<domain>." on a file that has its key beside it.
func keptStamp(dir, domain string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	prefix := certFile + "." + domain + "."
	best := ""
	for _, e := range entries {
		stamp, ok := strings.CutPrefix(e.Name(), prefix)
		if !ok || stamp <= best {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, keyFile+"."+domain+"."+stamp)); err == nil {
			best = stamp
		}
	}
	return best
}

// Load reads the root on disk.
func Load(dir string) (*Root, error) {
	certPath := filepath.Join(dir, certFile)
	keyPath := filepath.Join(dir, keyFile)
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(keyPath); err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: not a PEM certificate", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if len(cert.PermittedDNSDomains) != 1 {
		return nil, fmt.Errorf("%s: root is not restricted to one domain", certPath)
	}
	return &Root{
		CertPath:    certPath,
		KeyPath:     keyPath,
		Domain:      cert.PermittedDNSDomains[0],
		Fingerprint: Fingerprint(block.Bytes),
		NotAfter:    cert.NotAfter,
	}, nil
}

// ID is a short, stable name for this root, used as Caddy's CA id so a new
// root never shares storage with an old one.
func (r *Root) ID() string {
	return "rp-" + strings.ToLower(strings.ReplaceAll(r.Fingerprint[:23], ":", ""))
}

// Fingerprint formats a SHA-256 the way browsers show it.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, 32)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}
