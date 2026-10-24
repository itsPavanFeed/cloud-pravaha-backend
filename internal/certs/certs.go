// Package certs reloads TLS material from disk when it changes, so
// certificates rotated by cert-manager (or any PKI) take effect without a
// restart. Files are re-checked at most every interval.
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"sync"
	"time"
)

const interval = 30 * time.Second

// KeyPair serves a certificate and key that may be replaced on disk.
type KeyPair struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	modCert, modKey   time.Time
	checked           time.Time
}

func NewKeyPair(certFile, keyFile string) (*KeyPair, error) {
	k := &KeyPair{certFile: certFile, keyFile: keyFile}
	if err := k.load(); err != nil {
		return nil, err
	}
	return k, nil
}

func (k *KeyPair) load() error {
	ci, err := os.Stat(k.certFile)
	if err != nil {
		return err
	}
	ki, err := os.Stat(k.keyFile)
	if err != nil {
		return err
	}
	c, err := tls.LoadX509KeyPair(k.certFile, k.keyFile)
	if err != nil {
		return err
	}
	k.cert, k.modCert, k.modKey = &c, ci.ModTime(), ki.ModTime()
	return nil
}

// current returns the certificate, reloading it if the files changed. A
// half-written rotation (cert and key not matching yet) keeps the old one.
func (k *KeyPair) current() *tls.Certificate {
	k.mu.Lock()
	defer k.mu.Unlock()
	if time.Since(k.checked) < interval {
		return k.cert
	}
	k.checked = time.Now()
	ci, err1 := os.Stat(k.certFile)
	ki, err2 := os.Stat(k.keyFile)
	if err1 == nil && err2 == nil && (!ci.ModTime().Equal(k.modCert) || !ki.ModTime().Equal(k.modKey)) {
		old := k.cert
		if err := k.load(); err != nil {
			k.cert = old
		}
	}
	return k.cert
}

func (k *KeyPair) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return k.current(), nil
}

func (k *KeyPair) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return k.current(), nil
}

// ForceCheck makes the next use re-check the files (tests).
func (k *KeyPair) ForceCheck() { k.mu.Lock(); k.checked = time.Time{}; k.mu.Unlock() }

// Pool serves a CA bundle that may be replaced on disk.
type Pool struct {
	file    string
	mu      sync.Mutex
	pool    *x509.CertPool
	mod     time.Time
	checked time.Time
}

func NewPool(file string) (*Pool, error) {
	p := &Pool{file: file}
	if err := p.load(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Pool) load() error {
	fi, err := os.Stat(p.file)
	if err != nil {
		return err
	}
	pem, err := os.ReadFile(p.file)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return errors.New(p.file + " contains no certificates")
	}
	p.pool, p.mod = pool, fi.ModTime()
	return nil
}

func (p *Pool) Current() *x509.CertPool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Since(p.checked) >= interval {
		p.checked = time.Now()
		if fi, err := os.Stat(p.file); err == nil && !fi.ModTime().Equal(p.mod) {
			old := p.pool
			if p.load() != nil {
				p.pool = old
			}
		}
	}
	return p.pool
}

// ServerConfig builds a TLS config that reloads its certificate and, when
// clientCAs is set, verifies optional client certificates against a reloading pool.
func ServerConfig(kp *KeyPair, clientCAs *Pool) *tls.Config {
	base := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: kp.GetCertificate}
	if clientCAs == nil {
		return base
	}
	base.ClientAuth = tls.VerifyClientCertIfGiven
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		c.GetConfigForClient = nil
		c.ClientCAs = clientCAs.Current()
		return c, nil
	}
	return base
}
