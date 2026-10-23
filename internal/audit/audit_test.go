package audit

import (
	"encoding/json"
	"testing"
	"time"
)

func chain(n int) []Event {
	prev := Genesis
	var out []Event
	for i := 1; i <= n; i++ {
		e := Event{ID: int64(i), TS: time.Now(), Actor: "alice", Action: "run.approve", Target: "run/x", Payload: json.RawMessage(`{"a": 1}`), PrevHash: prev}
		Normalize(&e)
		e.Hash = Hash(prev, e)
		prev = e.Hash
		out = append(out, e)
	}
	return out
}

func TestChainDetectsTampering(t *testing.T) {
	evs := chain(5)
	if b := Verify(evs, Genesis); b != 0 {
		t.Fatalf("intact chain reported broken at %d", b)
	}
	evs[2].Actor = "mallory"
	if b := Verify(evs, Genesis); b != 3 {
		t.Fatalf("edit not detected at event 3, got %d", b)
	}
	evs = chain(5)
	evs = append(evs[:1], evs[2:]...) // delete event 2
	if b := Verify(evs, Genesis); b != 3 {
		t.Fatalf("deletion not detected, got %d", b)
	}
}
