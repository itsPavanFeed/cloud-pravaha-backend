package secure

import (
	"bytes"
	"strings"
	"testing"
)

func TestSealRoundTripAndBinding(t *testing.T) {
	s, err := NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := s.Seal([]byte("plan"), []byte("run-a"))
	if pt, err := s.Open(ct, []byte("run-a")); err != nil || string(pt) != "plan" {
		t.Fatal("round trip failed")
	}
	if _, err := s.Open(ct, []byte("run-b")); err == nil {
		t.Fatal("a sealed plan must not open for another run")
	}
	ct[len(ct)-1] ^= 1
	if _, err := s.Open(ct, []byte("run-a")); err == nil {
		t.Fatal("tampering must be detected")
	}
	if _, err := NewSealer([]byte("short")); err == nil {
		t.Fatal("weak keys must be rejected")
	}
}

func TestTokens(t *testing.T) {
	a, _ := NewToken("u")
	b, _ := NewToken("u")
	if a == b || !strings.HasPrefix(a, "pvh_u_") || len(a) < 40 {
		t.Fatal("tokens must be unique and long")
	}
	if Equal(HashToken(a), HashToken(b)) || !Equal(HashToken(a), HashToken(a)) {
		t.Fatal("hash mismatch")
	}
}
