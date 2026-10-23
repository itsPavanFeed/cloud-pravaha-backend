package oidc

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	k, _ := GenerateKey()
	iss, err := New("https://pravaha.example.com/", k)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := iss.Sign(Claims{Subject: Subject("prod", "network", "apply"), Audience: "sts.amazonaws.com", TTL: time.Hour}, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := iss.Verify(tok, now)
	if err != nil {
		t.Fatal(err)
	}
	if c["sub"] != "pravaha:env:prod:stack:network:phase:apply" || c["iss"] != "https://pravaha.example.com" || c["aud"] != "sts.amazonaws.com" {
		t.Fatalf("claims: %v", c)
	}
	if _, err := iss.Verify(tok, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := iss.Verify(tok[:len(tok)-4]+"AAAA", now); err == nil {
		t.Fatal("tampered token accepted")
	}
	var jwks struct{ Keys []map[string]string }
	json.Unmarshal(iss.JWKS(), &jwks)
	if len(jwks.Keys) != 1 || jwks.Keys[0]["alg"] != "ES256" {
		t.Fatal("bad JWKS")
	}
}
