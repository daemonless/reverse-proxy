package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"strings"
)

// alphabet avoids characters people confuse when retyping (0/O, 1/I/L).
const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// NewSetupToken makes a one-time token like "K7RT-9XPM-2WQF-HJ4N": easy to
// read from a log and type into a phone.
func NewSetupToken() string {
	var b [16]byte
	rand.Read(b[:])
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	return sb.String()
}

// NormalizeSetupToken forgives case, spaces and missing dashes.
func NormalizeSetupToken(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.NewReplacer(" ", "", "-", "", "0", "O", "1", "I", "L", "I").Replace(s)
	// Our alphabet has no O or I either; map them to the look-alikes we do use.
	s = strings.NewReplacer("O", "Q", "I", "J").Replace(s)
	return s
}

// EqualTokens compares two normalized tokens in constant time.
func EqualTokens(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// NewSecret returns a random URL-safe secret of n bytes.
func NewSecret(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// HashSecret is for high-entropy random tokens, where a plain SHA-256 is
// the right tool (argon2 is for things people choose).
func HashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
