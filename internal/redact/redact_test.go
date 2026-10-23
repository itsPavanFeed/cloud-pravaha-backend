package redact

import (
	"strings"
	"testing"
)

func TestRedacts(t *testing.T) {
	r := New("super-secret-run-token")
	in := strings.Join([]string{
		"token is super-secret-run-token here",
		"AKIAABCDEFGHIJKLMNOP",
		`password = "hunter2hunter2"`,
		"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcmF2YWhhIn0.c2lnbmF0dXJlc2lnbmF0dXJl",
		"pvh_t_abcdefghijklmnopqrstuvwxyz0123",
		"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
	}, "\n")
	out := r.String(in)
	for _, leak := range []string{"super-secret-run-token", "AKIAABCDEFGHIJKLMNOP", "hunter2", "eyJhbGci", "pvh_t_abc", "MIIB"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q in:\n%s", leak, out)
		}
	}
	if !strings.Contains(r.String("Plan: 1 to add"), "Plan: 1 to add") {
		t.Fatal("normal output must pass through")
	}
}
