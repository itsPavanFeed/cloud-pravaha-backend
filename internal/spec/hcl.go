package spec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// The generator builds configuration as a small tree of blocks and renders it
// with hclwrite. Every value from a contract or a default is written as a
// literal: hclwrite escapes "${" and "%{" in strings, so data can never become
// an expression. The only expressions are references the platform builds
// itself from validated names (expr).

type hblock struct {
	typ     string
	labels  []string
	comment string // written above the block, one "# " line per line
	attrs   []hattr
	blocks  []*hblock
}

type hattr struct {
	name string
	val  any // JSON-like value, json.RawMessage, or expr
}

// expr is an HCL expression assembled by the platform from validated parts,
// e.g. module.network.vpc_id. Never built from free text.
type expr hclwrite.Tokens

func (b *hblock) set(name string, v any) *hblock {
	for i := range b.attrs {
		if b.attrs[i].name == name {
			b.attrs[i].val = v
			return b
		}
	}
	b.attrs = append(b.attrs, hattr{name, v})
	return b
}

func (b *hblock) block(typ string, labels ...string) *hblock {
	c := &hblock{typ: typ, labels: labels}
	b.blocks = append(b.blocks, c)
	return c
}

// traversal builds a reference like module.network.vpc_id or
// data.vault_kv_secret_v2.s1.data["password"] from validated parts.
func traversal(parts ...string) expr {
	var t hclwrite.Tokens
	for i, p := range parts {
		if strings.HasPrefix(p, "[") { // index: written as a quoted key
			t = append(t, &hclwrite.Token{Type: hclsyntax.TokenOBrack, Bytes: []byte("[")})
			t = append(t, hclwrite.TokensForValue(cty.StringVal(strings.TrimSuffix(strings.TrimPrefix(p, "["), "]")))...)
			t = append(t, &hclwrite.Token{Type: hclsyntax.TokenCBrack, Bytes: []byte("]")})
			continue
		}
		if i > 0 {
			t = append(t, &hclwrite.Token{Type: hclsyntax.TokenDot, Bytes: []byte(".")})
		}
		t = append(t, &hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(p)})
	}
	return expr(t)
}

// call builds fn(arg, ...) from already-built tokens.
func call(fn string, args ...hclwrite.Tokens) expr {
	t := hclwrite.Tokens{{Type: hclsyntax.TokenIdent, Bytes: []byte(fn)}, {Type: hclsyntax.TokenOParen, Bytes: []byte("(")}}
	for i, a := range args {
		if i > 0 {
			t = append(t, &hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(",")})
		}
		t = append(t, a...)
	}
	return expr(append(t, &hclwrite.Token{Type: hclsyntax.TokenCParen, Bytes: []byte(")")}))
}

// renderHCL writes blocks as a formatted HCL file.
func renderHCL(header string, blocks []*hblock) ([]byte, error) {
	f := hclwrite.NewEmptyFile()
	body := f.Body()
	if header != "" {
		body.AppendUnstructuredTokens(commentTokens(header))
		body.AppendNewline()
	}
	for i, b := range blocks {
		if i > 0 {
			body.AppendNewline()
		}
		if err := writeBlock(body, b); err != nil {
			return nil, err
		}
	}
	return hclwrite.Format(f.Bytes()), nil
}

func writeBlock(parent *hclwrite.Body, b *hblock) error {
	if b.comment != "" {
		parent.AppendUnstructuredTokens(commentTokens(b.comment))
	}
	nb := parent.AppendNewBlock(b.typ, b.labels).Body()
	for _, a := range b.attrs {
		t, err := valueTokens(a.val, 0)
		if err != nil {
			return fmt.Errorf("%s.%s: %w", b.typ, a.name, err)
		}
		nb.SetAttributeRaw(a.name, t)
	}
	for _, c := range b.blocks {
		if err := writeBlock(nb, c); err != nil {
			return err
		}
	}
	return nil
}

func commentTokens(text string) hclwrite.Tokens {
	var t hclwrite.Tokens
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		t = append(t, &hclwrite.Token{Type: hclsyntax.TokenComment, Bytes: []byte(strings.TrimRight("# "+line, " ") + "\n")})
	}
	return t
}

func valueTokens(v any, depth int) (hclwrite.Tokens, error) {
	if depth > 32 {
		return nil, fmt.Errorf("value nested too deeply")
	}
	switch t := v.(type) {
	case expr:
		return hclwrite.Tokens(t), nil
	case nil:
		return hclwrite.TokensForValue(cty.NullVal(cty.DynamicPseudoType)), nil
	case string:
		return hclwrite.TokensForValue(cty.StringVal(t)), nil
	case bool:
		return hclwrite.TokensForValue(cty.BoolVal(t)), nil
	case int:
		return hclwrite.TokensForValue(cty.NumberIntVal(int64(t))), nil
	case float64:
		return hclwrite.TokensForValue(cty.NumberFloatVal(t)), nil
	case json.Number:
		n, err := cty.ParseNumberVal(string(t))
		if err != nil {
			return nil, err
		}
		return hclwrite.TokensForValue(n), nil
	case json.RawMessage:
		dec := json.NewDecoder(bytes.NewReader(t))
		dec.UseNumber()
		var x any
		if err := dec.Decode(&x); err != nil {
			return nil, err
		}
		return valueTokens(x, depth)
	case map[string]string:
		m := make(map[string]any, len(t))
		for k, v := range t {
			m[k] = v
		}
		return valueTokens(m, depth)
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		items := make([]hclwrite.ObjectAttrTokens, 0, len(keys))
		for _, k := range keys {
			vt, err := valueTokens(t[k], depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, hclwrite.ObjectAttrTokens{Name: keyTokens(k), Value: vt})
		}
		return hclwrite.TokensForObject(items), nil
	case []any:
		items := make([]hclwrite.Tokens, 0, len(t))
		for _, x := range t {
			xt, err := valueTokens(x, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, xt)
		}
		return hclwrite.TokensForTuple(items), nil
	case []string:
		items := make([]any, len(t))
		for i, s := range t {
			items[i] = s
		}
		return valueTokens(items, depth)
	}
	return nil, fmt.Errorf("cannot write %T", v)
}

// keyTokens writes an object key bare when it is a plain identifier and
// quoted otherwise (keys such as "kubernetes.io/role" or "managed-by").
func keyTokens(k string) hclwrite.Tokens {
	if hclsyntax.ValidIdentifier(k) && !strings.Contains(k, "-") {
		return hclwrite.Tokens{{Type: hclsyntax.TokenIdent, Bytes: []byte(k)}}
	}
	return hclwrite.TokensForValue(cty.StringVal(k))
}

func hclTokenType(s string) hclsyntax.TokenType {
	switch s {
	case ".":
		return hclsyntax.TokenDot
	case "[":
		return hclsyntax.TokenOBrack
	case "]":
		return hclsyntax.TokenCBrack
	}
	return hclsyntax.TokenIdent
}
