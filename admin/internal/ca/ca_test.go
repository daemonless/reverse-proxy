package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func leafSignedBy(t *testing.T, r *Root, name string) *x509.Certificate {
	rootPEM, _ := os.ReadFile(r.CertPath)
	rb, _ := pem.Decode(rootPEM)
	root, _ := x509.ParseCertificate(rb.Bytes)
	keyPEM, _ := os.ReadFile(r.KeyPath)
	kb, _ := pem.Decode(keyPEM)
	key, _ := x509.ParseECPrivateKey(kb.Bytes)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &lk.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return leaf
}

func TestRootIsRestrictedToDomain(t *testing.T) {
	dir := t.TempDir()
	r, err := Ensure(dir, "Apps.Home.LAN")
	if err != nil {
		t.Fatal(err)
	}
	if r.Domain != "apps.home.lan" || len(r.Fingerprint) != 95 {
		t.Fatalf("root %+v", r)
	}
	info, _ := os.Stat(r.KeyPath)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", info.Mode().Perm())
	}
	rootPEM, _ := os.ReadFile(r.CertPath)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	inside := leafSignedBy(t, r, "radarr.apps.home.lan")
	if _, err := inside.Verify(x509.VerifyOptions{Roots: pool, DNSName: "radarr.apps.home.lan"}); err != nil {
		t.Fatalf("name inside the domain rejected: %v", err)
	}
	outside := leafSignedBy(t, r, "evil.example.com")
	if _, err := outside.Verify(x509.VerifyOptions{Roots: pool, DNSName: "evil.example.com"}); err == nil {
		t.Fatal("name outside the domain was accepted")
	}
}

func TestEnsureIsStableAndRotatesOnDomainChange(t *testing.T) {
	dir := t.TempDir()
	a, _ := Ensure(dir, "a.lan")
	b, _ := Ensure(dir, "a.lan")
	if a.Fingerprint != b.Fingerprint {
		t.Fatal("same domain regenerated the root")
	}
	c, _ := Ensure(dir, "b.lan")
	if c.Fingerprint == a.Fingerprint || c.Domain != "b.lan" {
		t.Fatal("domain change did not make a new root")
	}
	entries, _ := os.ReadDir(dir)
	var kept int
	for _, e := range entries {
		if strings.Contains(e.Name(), ".a.lan.") {
			kept++
		}
	}
	if kept != 2 {
		t.Fatalf("old root not kept: %v", entries)
	}
	// Back to a.lan: the kept root returns, so devices that trusted it
	// still do; b.lan's pair is kept in turn.
	d, _ := Ensure(dir, "a.lan")
	if d.Fingerprint != a.Fingerprint || d.Domain != "a.lan" {
		t.Fatal("switching back did not restore the kept root")
	}
	entries, _ = os.ReadDir(dir)
	var keptA, keptB int
	for _, e := range entries {
		if strings.Contains(e.Name(), ".a.lan.") {
			keptA++
		}
		if strings.Contains(e.Name(), ".b.lan.") {
			keptB++
		}
	}
	if keptA != 0 || keptB != 2 {
		t.Fatalf("kept pairs after switching back: %v", entries)
	}
	if _, err := Load(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("Load on empty dir succeeded")
	}
}
