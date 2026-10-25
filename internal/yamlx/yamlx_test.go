package yamlx

import (
	"strings"
	"testing"
)

func TestDocuments(t *testing.T) {
	docs, err := Documents([]byte("a: 1\nb: [true, 2.5, x]\nc: null\nd: \"007\"\ne: 2026-10-25\n---\n---\nz: yes\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 {
		t.Fatalf("want 2 documents, got %d", len(docs))
	}
	if got := string(docs[0]); got != `{"a":1,"b":[true,2.5,"x"],"c":null,"d":"007","e":"2026-10-25"}` {
		t.Fatalf("doc 0: %s", got)
	}
	if got := string(docs[1]); got != `{"z":"yes"}` { // YAML 1.2: yes is a string
		t.Fatalf("doc 1: %s", got)
	}
}

func TestRejects(t *testing.T) {
	for name, in := range map[string]string{
		"anchor":    "a: &x 1\nb: *x\n",
		"merge":     "base: {a: 1}\nc:\n  <<: {a: 2}\n",
		"custom":    "a: !secret x\n",
		"binary":    "a: !!binary aGk=\n",
		"duplicate": "a: 1\na: 2\n",
		"inf":       "a: .inf\n",
		"bigint":    "a: 99999999999999999999999\n",
		"complex":   "? [a, b]\n: c\n",
	} {
		if _, err := Documents([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	deep := strings.Repeat("- ", 40) + "x\n"
	if _, err := Documents([]byte(deep)); err == nil {
		t.Error("deep nesting accepted")
	}
}

func TestDecodeStrict(t *testing.T) {
	var v struct {
		A string `json:"a"`
	}
	if err := Decode([]byte("a: x\nb: y\n"), &v); err == nil {
		t.Fatal("unknown field accepted")
	}
	if err := Decode([]byte("a: x\n"), &v); err != nil || v.A != "x" {
		t.Fatalf("decode: %v %q", err, v.A)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	b, err := Marshal(Map{{"name", "orders"}, {"count", "3"}, {"on", "true"}, {"spec", map[string]any{"z": 1, "a": []any{"x"}}}})
	if err != nil {
		t.Fatal(err)
	}
	docs, err := Documents(b)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(docs[0]); got != `{"count":"3","name":"orders","on":"true","spec":{"a":["x"],"z":1}}` {
		t.Fatalf("round trip lost types or order:\n%s\n%s", b, got)
	}
	if !strings.HasPrefix(string(b), "name: orders\n") {
		t.Fatalf("order not kept:\n%s", b)
	}
}
