package bundlecache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestCacheLayers(t *testing.T) {
	data := map[string][]byte{}
	for _, s := range []string{"one", "two", "three"} {
		data[sum([]byte(s))] = []byte(s)
	}
	var loads atomic.Int64
	load := func(ctx context.Context, sha string) ([]byte, error) {
		loads.Add(1)
		time.Sleep(20 * time.Millisecond)
		return data[sha], nil
	}
	dir := t.TempDir()
	c, err := New(load, dir, 8, 1<<20) // memory holds at most 8 bytes
	if err != nil {
		t.Fatal(err)
	}
	one := sum([]byte("one"))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b, err := c.Get(context.Background(), one); err != nil || string(b) != "one" {
				t.Errorf("get: %q %v", b, err)
			}
		}()
	}
	wg.Wait()
	if loads.Load() != 1 {
		t.Fatalf("20 concurrent misses made %d origin reads, want 1", loads.Load())
	}
	c.Get(context.Background(), sum([]byte("two")))
	c.Get(context.Background(), sum([]byte("three"))) // evicts "one" from memory
	if _, err := c.Get(context.Background(), one); err != nil || loads.Load() != 3 {
		t.Fatalf("evicted bundle should come from disk, origin reads = %d", loads.Load())
	}
	if c.Stats()["disk_hits"] != 1 {
		t.Fatalf("stats = %v", c.Stats())
	}

	// A tampered disk copy is dropped and reloaded from the origin.
	fresh, _ := New(load, dir, 1<<20, 1<<20)
	os.WriteFile(filepath.Join(dir, one), []byte("evil"), 0o600)
	if b, err := fresh.Get(context.Background(), one); err != nil || string(b) != "one" || loads.Load() != 4 {
		t.Fatalf("tampered copy: %q %v loads %d", b, err, loads.Load())
	}

	// An origin returning the wrong bytes is refused.
	bad, _ := New(func(context.Context, string) ([]byte, error) { return []byte("nope"), nil }, "", 1<<20, 0)
	if _, err := bad.Get(context.Background(), sum([]byte("x"))); err != ErrBadChecksum {
		t.Fatalf("bad origin: %v", err)
	}
	if _, err := bad.Get(context.Background(), "../../etc/passwd"); err == nil {
		t.Fatal("non-checksum key accepted")
	}
}
