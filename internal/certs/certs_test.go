package certs

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
	"testing"
	"time"
)

func write(t *testing.T, dir, cn string) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	os.WriteFile(filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	later := time.Now().Add(time.Duration(len(cn)) * time.Second) // distinct mtimes
	os.Chtimes(filepath.Join(dir, "tls.crt"), later, later)
	os.Chtimes(filepath.Join(dir, "tls.key"), later, later)
}

func cn(t *testing.T, kp *KeyPair) string {
	c, _ := kp.GetCertificate(nil)
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return x.Subject.CommonName
}

func TestReload(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "first")
	kp, err := NewKeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	if cn(t, kp) != "first" {
		t.Fatal("initial certificate")
	}
	write(t, dir, "rotated")
	kp.ForceCheck()
	if cn(t, kp) != "rotated" {
		t.Fatal("rotated certificate not picked up")
	}
	// A half-written rotation keeps serving the last good pair.
	os.WriteFile(filepath.Join(dir, "tls.key"), []byte("garbage"), 0o600)
	future := time.Now().Add(time.Hour)
	os.Chtimes(filepath.Join(dir, "tls.key"), future, future)
	kp.ForceCheck()
	if cn(t, kp) != "rotated" {
		t.Fatal("a broken key must not replace the working certificate")
	}
}
