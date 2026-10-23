package blob

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

// TestLiveS3 runs against a live S3-compatible endpoint when PRAVAHA_TEST_S3_URL
// is set (CI and the e2e use SeaweedFS with signature checking on).
func TestLiveS3(t *testing.T) {
	raw := os.Getenv("PRAVAHA_TEST_S3_URL")
	if raw == "" {
		t.Skip("PRAVAHA_TEST_S3_URL not set")
	}
	cfg, err := ParseURL(raw, os.Getenv("PRAVAHA_TEST_S3_ACCESS"), os.Getenv("PRAVAHA_TEST_S3_SECRET"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, nil)
	ctx := context.Background()
	if err := s.EnsureBucket(ctx); err != nil {
		t.Fatal(err)
	}
	key := "state/stack id/1 with spaces+symbols.tfstate"
	data := bytes.Repeat([]byte("encrypted-state "), 1000)
	if err := s.Put(ctx, key, data); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, key)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("get: %v (%d bytes)", err, len(got))
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted object still readable: %v", err)
	}
	bad, _ := ParseURL(raw, os.Getenv("PRAVAHA_TEST_S3_ACCESS"), "wrong-secret")
	if err := New(bad, nil).Put(ctx, "x", []byte("x")); err == nil {
		t.Fatal("a wrong secret must be rejected by the server")
	}
}

func TestParseURL(t *testing.T) {
	if _, err := ParseURL("s3://b?endpoint=http://evil.example.com", "a", "b"); err == nil {
		t.Fatal("plain http to a remote endpoint must be refused")
	}
	c, err := ParseURL("s3://tenant-acme/pravaha?region=eu-west-1", "a", "b")
	if err != nil || c.Endpoint != "https://s3.eu-west-1.amazonaws.com" || c.Prefix != "pravaha/" {
		t.Fatalf("%+v %v", c, err)
	}
}
