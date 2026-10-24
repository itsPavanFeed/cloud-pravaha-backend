package githubapp

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

func TestParsePrivateKey(t *testing.T) {
	_, p1 := testKey(t)
	if _, err := ParsePrivateKey(p1); err != nil {
		t.Fatal(err)
	}
	k, _ := testKey(t)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	if _, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKey([]byte("not a key")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestAppJWT(t *testing.T) {
	k, _ := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	tok, err := AppJWT(5450441, k, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatal(tok)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatal("bad signature")
	}
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	json.Unmarshal(cb, &c)
	if c["iss"] != "5450441" || c["iat"].(float64) != float64(now.Unix()-60) || c["exp"].(float64) != float64(now.Unix()+540) {
		t.Fatalf("claims = %v", c)
	}
}

func TestVerifySignature(t *testing.T) {
	body := []byte(`{"zen":"Keep it logically awesome."}`)
	m := hmac.New(sha256.New, []byte("s3cret"))
	m.Write(body)
	good := "sha256=" + hex.EncodeToString(m.Sum(nil))
	if !VerifySignature([]byte("s3cret"), body, good) {
		t.Fatal("valid signature rejected")
	}
	for _, bad := range []string{"", "sha1=abc", "sha256=zz", good[:len(good)-2] + "00"} {
		if VerifySignature([]byte("s3cret"), body, bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
	if VerifySignature([]byte("other"), body, good) || VerifySignature(nil, body, good) {
		t.Fatal("wrong or empty secret accepted")
	}
}

func TestTokenIsCached(t *testing.T) {
	k, _ := testKey(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/42/access_tokens" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ey") {
			http.Error(w, `{"message":"bad"}`, 401)
			return
		}
		calls.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"token": "ghs_x", "expires_at": time.Now().Add(time.Hour)})
	}))
	defer srv.Close()
	a := &App{ID: 1, Key: k, API: srv.URL}
	for i := 0; i < 3; i++ {
		tok, err := a.Token(context.Background(), 42)
		if err != nil || tok != "ghs_x" {
			t.Fatal(tok, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("minted %d tokens", calls.Load())
	}
	if _, err := a.Token(context.Background(), 7); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v", err)
	}
}
