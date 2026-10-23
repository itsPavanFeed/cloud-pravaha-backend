// Package secure holds the platform's cryptographic primitives: AES-256-GCM
// sealing for data at rest, and random bearer tokens that are stored only as
// SHA-256 hashes.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Sealer encrypts blobs (saved plans, signing keys) with AES-256-GCM. The
// associated data binds a ciphertext to its owner, so a sealed plan for one
// run cannot be swapped in for another.
type Sealer struct{ aead cipher.AEAD }

func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("master key must be 32 bytes (base64-encoded in PRAVAHA_MASTER_KEY)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// ParseKey decodes a base64 (std or URL) 32-byte key.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("key must be 32 random bytes, base64-encoded (generate with: openssl rand -base64 32)")
}

const sealVersion = 1

func (s *Sealer) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := append([]byte{sealVersion}, nonce...)
	return s.aead.Seal(out, nonce, plaintext, aad), nil
}

func (s *Sealer) Open(sealed, aad []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < 1+n || sealed[0] != sealVersion {
		return nil, errors.New("sealed data is malformed")
	}
	pt, err := s.aead.Open(nil, sealed[1:1+n], sealed[1+n:], aad)
	if err != nil {
		return nil, errors.New("sealed data failed authentication")
	}
	return pt, nil
}

// NewToken returns a random bearer token with a readable prefix, e.g. "pvh_u_…".
func NewToken(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return fmt.Sprintf("pvh_%s_%s", prefix, base64.RawURLEncoding.EncodeToString(b)), nil
}

// HashToken is what gets stored; the token itself is shown once and never kept.
func HashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

func Equal(a, b []byte) bool { return hmac.Equal(a, b) }

func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Derive returns a hex HMAC-SHA256 of label under key, used for per-stack keys.
func Derive(key []byte, label string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(label))
	return hex.EncodeToString(m.Sum(nil))
}
