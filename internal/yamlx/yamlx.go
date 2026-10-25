// Package yamlx reads and writes the YAML the platform accepts from Git:
// contracts, kind definitions and tenant defaults.
//
// Reading is deliberately strict. Anchors, aliases and merge keys are refused
// (they enable "billion laughs" expansion and make reviews misleading), as are
// custom tags, binary scalars, duplicate keys and non-finite numbers. Each
// document becomes plain JSON, so the rest of the platform decodes it with the
// same strict JSON rules it already uses for API requests.
package yamlx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

var intRe = regexp.MustCompile(`^[-+]?[0-9_]+$`)

const (
	maxDepth = 32
	maxNodes = 20000
	maxDocs  = 50
)

// Documents converts every YAML document in b to JSON. Empty documents are skipped.
func Documents(b []byte) ([][]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var out [][]byte
	nodes := 0
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("invalid YAML: %w", err)
		}
		if len(doc.Content) == 0 || doc.Content[0].Kind == yaml.ScalarNode && doc.Content[0].ShortTag() == "!!null" && doc.Content[0].Value == "" {
			continue // an empty document, e.g. between two "---" lines
		}
		if len(out) == maxDocs {
			return nil, fmt.Errorf("a file may hold at most %d YAML documents", maxDocs)
		}
		v, err := convert(doc.Content[0], 0, &nodes)
		if err != nil {
			return nil, err
		}
		j, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
}

// Decode reads exactly one YAML document into v, rejecting unknown fields.
func Decode(b []byte, v any) error {
	docs, err := Documents(b)
	if err != nil {
		return err
	}
	if len(docs) != 1 {
		return fmt.Errorf("expected one YAML document, found %d", len(docs))
	}
	return DecodeJSON(docs[0], v)
}

// DecodeJSON is a strict JSON decode: unknown fields and trailing data are errors.
func DecodeJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "json: "))
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func convert(n *yaml.Node, depth int, nodes *int) (any, error) {
	*nodes++
	if *nodes > maxNodes {
		return nil, errors.New("YAML is too large")
	}
	if depth > maxDepth {
		return nil, errors.New("YAML is nested too deeply")
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return nil, fmt.Errorf("line %d: anchors and aliases are not allowed", n.Line)
	}
	if n.Tag != "" && !strings.HasPrefix(n.Tag, "!!") {
		return nil, fmt.Errorf("line %d: custom tag %s is not allowed", n.Line, n.Tag)
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return scalar(n)
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := convert(c, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Anchor != "" {
				return nil, fmt.Errorf("line %d: keys must be plain strings", k.Line)
			}
			if k.ShortTag() == "!!merge" {
				return nil, fmt.Errorf("line %d: merge keys (<<) are not allowed", k.Line)
			}
			if _, dup := out[k.Value]; dup {
				return nil, fmt.Errorf("line %d: key %q is defined twice", k.Line, k.Value)
			}
			v, err := convert(n.Content[i+1], depth+1, nodes)
			if err != nil {
				return nil, err
			}
			out[k.Value] = v
		}
		return out, nil
	}
	return nil, fmt.Errorf("line %d: unsupported YAML node", n.Line)
}

func scalar(n *yaml.Node) (any, error) {
	switch n.ShortTag() {
	case "!!str", "!!timestamp":
		return n.Value, nil // dates stay strings: modules expect them that way
	case "!!null":
		return nil, nil
	case "!!bool":
		var b bool
		if err := n.Decode(&b); err != nil {
			return nil, fmt.Errorf("line %d: %w", n.Line, err)
		}
		return b, nil
	case "!!int":
		var i int64
		if err := n.Decode(&i); err != nil {
			return nil, fmt.Errorf("line %d: integer out of range", n.Line)
		}
		return json.Number(strconv.FormatInt(i, 10)), nil
	case "!!float":
		if intRe.MatchString(n.Value) {
			return nil, fmt.Errorf("line %d: integer out of range", n.Line)
		}
		var f float64
		if err := n.Decode(&f); err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, fmt.Errorf("line %d: numbers must be finite", n.Line)
		}
		return json.Number(strconv.FormatFloat(f, 'g', -1, 64)), nil
	}
	return nil, fmt.Errorf("line %d: %s values are not allowed", n.Line, n.ShortTag())
}

// ---- writing ----

// KV is one entry of an ordered mapping.
type KV struct {
	Key   string
	Value any
}

// Map is a mapping that keeps its key order when written.
type Map []KV

// Marshal writes v as YAML. Map keeps its order; plain maps are written with
// sorted keys. Strings that would read back as another type are quoted.
func Marshal(v any) ([]byte, error) {
	n, err := node(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	enc.Close()
	return buf.Bytes(), nil
}

func node(v any) (*yaml.Node, error) {
	switch t := v.(type) {
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	case string:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: t}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(t)}, nil
	case json.Number:
		tag := "!!int"
		if strings.ContainsAny(string(t), ".eE") {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: string(t)}, nil
	case float64:
		return node(json.Number(strconv.FormatFloat(t, 'g', -1, 64)))
	case int:
		return node(json.Number(strconv.Itoa(t)))
	case json.RawMessage:
		dec := json.NewDecoder(bytes.NewReader(t))
		dec.UseNumber()
		var x any
		if err := dec.Decode(&x); err != nil {
			return nil, err
		}
		return node(x)
	case Map:
		m := &yaml.Node{Kind: yaml.MappingNode}
		for _, kv := range t {
			vn, err := node(kv.Value)
			if err != nil {
				return nil, err
			}
			m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: kv.Key}, vn)
		}
		return m, nil
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		om := make(Map, 0, len(keys))
		for _, k := range keys {
			om = append(om, KV{k, t[k]})
		}
		return node(om)
	case []any:
		s := &yaml.Node{Kind: yaml.SequenceNode}
		for _, x := range t {
			xn, err := node(x)
			if err != nil {
				return nil, err
			}
			s.Content = append(s.Content, xn)
		}
		return s, nil
	}
	return nil, fmt.Errorf("cannot write %T as YAML", v)
}
