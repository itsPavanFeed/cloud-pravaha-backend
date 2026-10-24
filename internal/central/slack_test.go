package central

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

func TestVerifySlack(t *testing.T) {
	secret, body := []byte("8f742231b10e8888abcd99yyyzzz85a5"), []byte("payload=%7B%7D")
	now := time.Unix(1_800_000_000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("v0:" + ts + ":" + string(body)))
	sig := "v0=" + hex.EncodeToString(m.Sum(nil))
	if !verifySlack(secret, body, ts, sig, now) {
		t.Fatal("valid request rejected")
	}
	if verifySlack(secret, []byte("payload=tampered"), ts, sig, now) {
		t.Fatal("tampered body accepted")
	}
	if verifySlack([]byte("other-secret-other-secret"), body, ts, sig, now) {
		t.Fatal("wrong secret accepted")
	}
	if verifySlack(secret, body, ts, sig, now.Add(6*time.Minute)) {
		t.Fatal("replayed (stale) request accepted")
	}
	if verifySlack(secret, body, "nope", sig, now) {
		t.Fatal("bad timestamp accepted")
	}
}
