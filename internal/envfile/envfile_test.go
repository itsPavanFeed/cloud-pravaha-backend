package envfile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	m := Parse([]byte(`# comment
POSTGRES_PASSWORD=abc   # inline comment
export A_B="quoted value"
SINGLE='x y'
bad-key=1
EMPTY=
`))
	want := map[string]string{"POSTGRES_PASSWORD": "abc", "A_B": "quoted value", "SINGLE": "x y", "EMPTY": ""}
	if len(m) != len(want) {
		t.Fatalf("%v", m)
	}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("%s = %q, want %q", k, m[k], v)
		}
	}
}

func TestUpdateKeepsOtherLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(p, []byte("# keep me\nPOSTGRES_PASSWORD=abc # note\nSECRET=old\nGONE=x\n"), 0o644)
	if err := Update(p, map[string]string{"SECRET": "new value", "ADDED": "1", "GONE": ""}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	for _, want := range []string{"# keep me\n", "POSTGRES_PASSWORD=abc # note\n", `SECRET="new value"`, "ADDED=1\n"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "GONE") || strings.Contains(s, "old") {
		t.Fatalf("stale entries left:\n%s", s)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if m, _ := Read(p); m["SECRET"] != "new value" || m["POSTGRES_PASSWORD"] != "abc" {
		t.Fatalf("%v", m)
	}
	if err := Update(p, map[string]string{"X": "a\nB=b"}); err == nil {
		t.Fatal("newline injection accepted")
	}
}

func TestWatch(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(p, []byte("A=1\n"), 0o600)
	var n atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Watch(ctx, 10*time.Millisecond, func() { n.Add(1) }, func() []string { return []string{p} })
	time.Sleep(30 * time.Millisecond)
	os.WriteFile(p, []byte("A=22\n"), 0o600)
	deadline := time.Now().Add(2 * time.Second)
	for n.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n.Load() == 0 {
		t.Fatal("change not noticed")
	}
}
