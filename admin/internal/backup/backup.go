// Package backup packs everything needed to bring a proxy back (state,
// secrets, the root CA) into one file, encrypted with a passphrase. The
// format is deliberately dull: a tar of the files, sealed with
// XChaCha20-Poly1305 under an argon2id-derived key.
package backup

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	magic      = "RPBK1" // reverse-proxy backup, format 1
	saltLen    = 16
	argonTime  = 2
	argonMem   = 64 * 1024
	argonLanes = 4
)

// Files are the paths (relative to the state directory) a backup carries.
// The setup certificate is deliberately left out: it is regenerated.
var Files = []string{"state.json", "secrets/ca-root.crt", "secrets/ca-root.key", "secrets/dns.json"}

// Create writes an encrypted backup of dir to w.
func Create(w io.Writer, dir, passphrase string) error {
	// Optional: with no passphrase the file is sealed under the empty one,
	// which is to say anyone with the file can open it. Short ones are
	// refused; "" is a choice, "abc" is a mistake.
	if passphrase != "" && len(passphrase) < 8 {
		return errors.New("use a passphrase of at least 8 characters, or none")
	}
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, rel := range Files {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if errors.Is(err, os.ErrNotExist) {
			continue // no CA yet, for example
		}
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: rel, Mode: 0o600, Size: int64(len(data)), ModTime: time.Now()}); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMem, argonLanes, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := aead.Seal(nil, nonce, tarBuf.Bytes(), []byte(magic))

	// magic | salt | nonce | len | ciphertext
	if _, err := io.WriteString(w, magic); err != nil {
		return err
	}
	for _, part := range [][]byte{salt, nonce} {
		if _, err := w.Write(part); err != nil {
			return err
		}
	}
	if err := binary.Write(w, binary.BigEndian, uint64(len(sealed))); err != nil {
		return err
	}
	_, err = w.Write(sealed)
	return err
}

// ErrWrongPassphrase is returned when the file does not open.
var ErrWrongPassphrase = errors.New("that passphrase doesn't open this backup")

// ErrNotABackup is returned for a file in another format.
var ErrNotABackup = errors.New("this isn't a Daemonless Reverse Proxy backup file")

// Open decrypts a backup and returns its files by relative path.
func Open(r io.Reader, passphrase string) (map[string][]byte, error) {
	head := make([]byte, len(magic)+saltLen+chacha20poly1305.NonceSizeX+8)
	if _, err := io.ReadFull(r, head); err != nil || string(head[:len(magic)]) != magic {
		return nil, ErrNotABackup
	}
	salt := head[len(magic) : len(magic)+saltLen]
	nonce := head[len(magic)+saltLen : len(magic)+saltLen+chacha20poly1305.NonceSizeX]
	n := binary.BigEndian.Uint64(head[len(head)-8:])
	if n > 64<<20 {
		return nil, ErrNotABackup
	}
	sealed := make([]byte, n)
	if _, err := io.ReadFull(r, sealed); err != nil {
		return nil, ErrNotABackup
	}
	key := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMem, argonLanes, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, sealed, []byte(magic))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	out := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(plain))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading backup: %w", err)
		}
		if !allowed(h.Name) {
			return nil, fmt.Errorf("backup contains an unexpected file %q", h.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, 16<<20))
		if err != nil {
			return nil, err
		}
		out[h.Name] = data
	}
	if _, ok := out["state.json"]; !ok {
		return nil, ErrNotABackup
	}
	return out, nil
}

func allowed(name string) bool {
	for _, f := range Files {
		if f == name {
			return true
		}
	}
	return false
}

// Write puts the files from Open into dir with safe modes. Existing files
// are kept beside them with a timestamp so a restore is never destructive.
func Write(dir string, files map[string][]byte) error {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	for rel, data := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if _, err := os.Stat(p); err == nil {
			_ = os.Rename(p, p+".before-restore-"+stamp)
		}
		mode := os.FileMode(0o600)
		if strings.HasSuffix(rel, ".crt") {
			mode = 0o644
		}
		if err := os.WriteFile(p, data, mode); err != nil {
			return err
		}
	}
	return nil
}
