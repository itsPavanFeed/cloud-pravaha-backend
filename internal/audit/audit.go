// Package audit implements the tamper-evident audit chain.
//
// Each event's hash covers its content and the previous event's hash, so
// editing or deleting any past row breaks every hash after it. Verify walks
// the chain and reports the first break.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type Event struct {
	ID       int64           `json:"id"`
	TS       time.Time       `json:"ts"`
	Actor    string          `json:"actor"`
	Action   string          `json:"action"`
	Target   string          `json:"target"`
	Entity   string          `json:"entity,omitempty"`
	Payload  json.RawMessage `json:"payload"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
}

// Genesis is the prev_hash of the first event.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Normalize fixes the representation that is hashed: UTC, microsecond precision
// (what PostgreSQL stores) and compact JSON.
func Normalize(e *Event) {
	e.TS = e.TS.UTC().Truncate(time.Microsecond)
	if len(e.Payload) == 0 {
		e.Payload = json.RawMessage(`{}`)
	}
	var buf bytes.Buffer
	if json.Compact(&buf, e.Payload) == nil {
		e.Payload = buf.Bytes()
	}
}

func Hash(prev string, e Event) string {
	Normalize(&e)
	h := sha256.New()
	for _, part := range []string{prev, e.TS.Format(time.RFC3339Nano), e.Actor, e.Action, e.Target, e.Entity, string(e.Payload)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Verify checks events in id order. It returns the id of the first broken
// event, or 0 when the whole chain is intact.
func Verify(events []Event, prev string) int64 {
	for _, e := range events {
		if e.PrevHash != prev || Hash(prev, e) != e.Hash {
			return e.ID
		}
		prev = e.Hash
	}
	return 0
}
