// Package oidc makes the control plane an OpenID Connect issuer for runs.
//
// Each run gets a short-lived ES256 JWT whose subject names the environment and
// stack. Customers configure their cloud to trust this issuer (AWS IAM OIDC
// provider, GCP workload identity pool, Azure federated credential) and scope
// the trust to specific subjects. No long-lived cloud credential exists anywhere.
package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type Issuer struct {
	URL string
	key *ecdsa.PrivateKey
	kid string
}

// GenerateKey returns a new P-256 key in PKCS#8 DER form.
func GenerateKey() ([]byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKCS8PrivateKey(k)
}

func New(url string, pkcs8 []byte) (*Issuer, error) {
	k, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("OIDC signing key must be ECDSA P-256")
	}
	pub, _ := x509.MarshalPKIXPublicKey(&ek.PublicKey)
	sum := sha256.Sum256(pub)
	return &Issuer{URL: strings.TrimRight(url, "/"), key: ek, kid: b64(sum[:8])}, nil
}

type Claims struct {
	Subject     string
	Audience    string
	Entity      string
	Environment string
	Stack       string
	RunID       string
	Phase       string // plan | apply
	TTL         time.Duration
}

// Subject is the "sub" claim cloud trust policies match on. Environment names
// are unique within an entity, so the entity is part of it.
func Subject(entity, env, stack, phase string) string {
	return "pravaha:entity:" + entity + ":env:" + env + ":stack:" + stack + ":phase:" + phase
}

func (i *Issuer) Sign(c Claims, now time.Time) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": i.kid})
	payload, _ := json.Marshal(map[string]any{
		"iss":         i.URL,
		"sub":         c.Subject,
		"aud":         c.Audience,
		"iat":         now.Unix(),
		"nbf":         now.Add(-30 * time.Second).Unix(),
		"exp":         now.Add(c.TTL).Unix(),
		"jti":         b64(jti),
		"entity":      c.Entity,
		"environment": c.Environment,
		"stack":       c.Stack,
		"run_id":      c.RunID,
		"phase":       c.Phase,
	})
	signing := b64(header) + "." + b64(payload)
	h := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, i.key, h[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64(sig), nil
}

// Verify checks a token's signature and expiry; used by tests and the CLI.
func (i *Issuer) Verify(tok string, now time.Time) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, errors.New("malformed signature")
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&i.key.PublicKey, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, errors.New("bad signature")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, err
	}
	if exp, _ := claims["exp"].(float64); int64(exp) < now.Unix() {
		return nil, errors.New("token expired")
	}
	return claims, nil
}

// PublicKeyPEM is the signing key in PEM form, for verifiers that cannot
// fetch the JWKS (for example OpenBao's jwt_validation_pubkeys).
func (i *Issuer) PublicKeyPEM() string {
	der, err := x509.MarshalPKIXPublicKey(&i.key.PublicKey)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func (i *Issuer) JWKS() []byte {
	pub := i.key.PublicKey
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	b, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": i.kid, "x": b64(x), "y": b64(y),
	}}})
	return b
}

func (i *Issuer) Discovery() []byte {
	b, _ := json.Marshal(map[string]any{
		"issuer":                                i.URL,
		"jwks_uri":                              i.URL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"claims_supported":                      []string{"sub", "aud", "exp", "iat", "iss", "jti", "environment", "stack", "run_id", "phase"},
	})
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// SignJWT signs arbitrary claims with the issuer's key. The caller sets
// time-based claims; iss is always the issuer URL.
func (i *Issuer) SignJWT(claims map[string]any) (string, error) {
	claims["iss"] = i.URL
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": i.kid})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64(header) + "." + b64(payload)
	h := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, i.key, h[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64(sig), nil
}

// Verifier checks ES256 and RS256 JWTs against a set of public keys (a JWKS).
type Verifier struct {
	Issuer string
	keys   map[string]*ecdsa.PublicKey
	rsa    map[string]*rsa.PublicKey
}

// NewVerifier parses a JWKS document containing P-256 keys.
func NewVerifier(issuer string, jwks []byte) (*Verifier, error) {
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &doc); err != nil {
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}
	v := &Verifier{Issuer: strings.TrimRight(issuer, "/"), keys: map[string]*ecdsa.PublicKey{}, rsa: map[string]*rsa.PublicKey{}}
	for _, k := range doc.Keys {
		if k["kty"] == "RSA" && (k["use"] == "" || k["use"] == "sig") {
			n, err1 := base64.RawURLEncoding.DecodeString(k["n"])
			e, err2 := base64.RawURLEncoding.DecodeString(k["e"])
			if err1 != nil || err2 != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
				continue // RSA keys under 2048 bits are ignored
			}
			v.rsa[k["kid"]] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
			continue
		}
		if k["kty"] != "EC" || k["crv"] != "P-256" {
			continue
		}
		x, err1 := base64.RawURLEncoding.DecodeString(k["x"])
		y, err2 := base64.RawURLEncoding.DecodeString(k["y"])
		if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
			continue
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			continue
		}
		v.keys[k["kid"]] = pub
	}
	if len(v.keys)+len(v.rsa) == 0 {
		return nil, errors.New("JWKS contains no usable P-256 or RSA keys")
	}
	return v, nil
}

// Verify checks signature, issuer, audience, and time claims (with 30s skew).
func (v *Verifier) Verify(tok, audience string, now time.Time) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed header")
	}
	var hdr struct{ Alg, Kid string }
	if json.Unmarshal(hb, &hdr) != nil {
		return nil, errors.New("malformed header")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("malformed signature")
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch hdr.Alg {
	case "ES256":
		pub := v.keys[hdr.Kid]
		if pub == nil {
			return nil, errors.New("unknown signing key")
		}
		if len(sig) != 64 || !ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, errors.New("bad signature")
		}
	case "RS256":
		pub := v.rsa[hdr.Kid]
		if pub == nil {
			return nil, errors.New("unknown signing key")
		}
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) != nil {
			return nil, errors.New("bad signature")
		}
	default:
		return nil, errors.New("unsupported token algorithm")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed payload")
	}
	var c map[string]any
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, errors.New("malformed payload")
	}
	if c["iss"] != v.Issuer {
		return nil, errors.New("wrong issuer")
	}
	if !audienceMatches(c["aud"], audience) {
		return nil, errors.New("wrong audience")
	}
	exp, _ := c["exp"].(float64)
	nbf, _ := c["nbf"].(float64)
	skew := int64(30)
	if int64(exp)+skew < now.Unix() {
		return nil, errors.New("token expired")
	}
	if int64(nbf)-skew > now.Unix() {
		return nil, errors.New("token not yet valid")
	}
	return c, nil
}

// audienceMatches accepts a string aud or an array containing the audience.
func audienceMatches(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if x == want {
				return true
			}
		}
	}
	return false
}
