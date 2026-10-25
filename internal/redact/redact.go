// Package redact scrubs secrets from run logs before they leave the runner.
package redact

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

var patterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`), // AWS access key IDs
	regexp.MustCompile(`(?i)(aws_secret_access_key|secret_key|client_secret|password|passphrase|token)(["'\s:=]+)[^\s"',]{8,}`), // key = value
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`), // JWTs
	regexp.MustCompile(`\bpvh_[a-z]+_[A-Za-z0-9_-]{20,}\b`),                                 // platform tokens
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),                                    // GitHub tokens
	regexp.MustCompile(`(?i)\bAccountKey=[A-Za-z0-9+/=]{20,}`),                              // Azure storage keys
}

// Redactor replaces known secret values and secret-shaped strings with [REDACTED].
type Redactor struct {
	mu     sync.RWMutex
	values []string
}

func New(secrets ...string) *Redactor {
	r := &Redactor{}
	r.Add(secrets...)
	return r
}

func (r *Redactor) Add(secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range secrets {
		if len(s) >= 6 {
			r.values = append(r.values, s)
		}
	}
	// Longest first so a secret containing another is fully replaced.
	sort.Slice(r.values, func(i, j int) bool { return len(r.values[i]) > len(r.values[j]) })
}

func (r *Redactor) String(s string) string {
	r.mu.RLock()
	for _, v := range r.values {
		s = strings.ReplaceAll(s, v, "[REDACTED]")
	}
	r.mu.RUnlock()
	for i, re := range patterns {
		if i == 1 {
			s = re.ReplaceAllString(s, "${1}${2}[REDACTED]")
			continue
		}
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

// LooksLikeSecret reports whether a value has the shape of a credential: cloud
// access keys, private keys, JWTs, platform or GitHub tokens, storage keys.
func LooksLikeSecret(s string) bool {
	for i, re := range patterns {
		if i == 1 { // "password = x" style: too loose for values (descriptions, names)
			continue
		}
		if re.MatchString(s) {
			return true
		}
	}
	return false
}
