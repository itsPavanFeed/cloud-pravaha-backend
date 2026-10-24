package assistant

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
)

// Doc is one retrievable passage. IDs are stable and cited in answers as [id].
type Doc struct {
	ID    string `json:"id"`   // e.g. catalog:aws-eks, doc:security#state-encryption, stack:payments-api
	Kind  string `json:"kind"` // catalog | doc | policy | stack | environment | settings
	Title string `json:"title"`
	Text  string `json:"-"`
}

// Index is an in-memory BM25 index. Corpora here are small (a catalog, a few
// documents, one tenant's stacks), so it is rebuilt per request with the
// caller's own documents rather than kept per user.
type Index struct {
	docs []Doc
	tf   []map[string]int
	lens []int
	df   map[string]int
	avg  float64
}

const (
	bm25K1 = 1.2
	bm25B  = 0.75
)

func NewIndex(docs ...[]Doc) *Index {
	ix := &Index{df: map[string]int{}}
	total := 0
	for _, set := range docs {
		for _, d := range set {
			// The title and ID count twice: a module named in the question should win.
			toks := tokenize(d.Title + " " + d.ID + " " + d.Title + " " + d.ID + " " + d.Text)
			tf := map[string]int{}
			for _, t := range toks {
				tf[t]++
			}
			for t := range tf {
				ix.df[t]++
			}
			ix.docs = append(ix.docs, d)
			ix.tf = append(ix.tf, tf)
			ix.lens = append(ix.lens, len(toks))
			total += len(toks)
		}
	}
	if len(ix.docs) > 0 {
		ix.avg = float64(total) / float64(len(ix.docs))
	}
	return ix
}

func (ix *Index) Len() int { return len(ix.docs) }

// Get returns the document with the given ID.
func (ix *Index) Get(id string) (Doc, bool) {
	for _, d := range ix.docs {
		if d.ID == id {
			return d, true
		}
	}
	return Doc{}, false
}

// Search returns up to k documents ranked by BM25, optionally limited to one kind.
func (ix *Index) Search(query, kind string, k int) []Doc {
	q := map[string]bool{}
	for _, t := range tokenize(query) {
		q[t] = true
	}
	type hit struct {
		i     int
		score float64
	}
	var hits []hit
	n := float64(len(ix.docs))
	for i, tf := range ix.tf {
		if kind != "" && ix.docs[i].Kind != kind {
			continue
		}
		var score float64
		for t := range q {
			f := float64(tf[t])
			if f == 0 {
				continue
			}
			df := float64(ix.df[t])
			idf := math.Log(1 + (n-df+0.5)/(df+0.5))
			score += idf * f * (bm25K1 + 1) / (f + bm25K1*(1-bm25B+bm25B*float64(ix.lens[i])/ix.avg))
		}
		if score > 0 {
			hits = append(hits, hit{i, score})
		}
	}
	sort.SliceStable(hits, func(a, b int) bool { return hits[a].score > hits[b].score })
	var out []Doc
	for _, h := range hits {
		if len(out) == k {
			break
		}
		out = append(out, ix.docs[h.i])
	}
	return out
}

var stop = map[string]bool{"the": true, "and": true, "for": true, "with": true, "that": true, "this": true, "are": true,
	"can": true, "how": true, "what": true, "use": true, "not": true, "from": true, "you": true, "need": true, "into": true}

// tokenize lowercases and splits on anything that is not a letter or digit, so
// snake_case and kebab-case names also match their parts. Whole identifiers
// (eks_managed_node_groups, aws-eks) are kept as tokens too.
func tokenize(s string) []string {
	var out []string
	for _, word := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.')
	}) {
		word = strings.Trim(word, "-_.")
		parts := strings.FieldsFunc(word, func(r rune) bool { return r == '_' || r == '-' || r == '.' })
		if len(parts) > 1 && len(word) <= 64 {
			out = append(out, word)
		}
		for _, p := range parts {
			if len(p) >= 2 && !stop[p] {
				out = append(out, stem(p))
			}
		}
	}
	return out
}

// stem folds simple English plurals so "buckets" finds "bucket".
func stem(w string) string {
	switch {
	case len(w) > 4 && strings.HasSuffix(w, "ies"):
		return w[:len(w)-3] + "y"
	case len(w) > 3 && strings.HasSuffix(w, "s") && !strings.HasSuffix(w, "ss") && !strings.HasSuffix(w, "us") && !strings.HasSuffix(w, "is"):
		return w[:len(w)-1]
	}
	return w
}

// CatalogDocs describes every approved module: what it is for, which inputs a
// stack may set, the baseline the platform enforces and the outputs it exposes.
func CatalogDocs(cat *catalog.Catalog) []Doc {
	var docs []Doc
	for _, m := range cat.Modules {
		var b strings.Builder
		fmt.Fprintf(&b, "Catalog module %q (%s). Cloud: %s. Registry source: %s. Approved versions: %s (default %s).\n%s\n",
			m.ID, m.Title, cloudName(m.Cloud), m.Source, strings.Join(m.Versions, ", "), m.LatestVersion(), m.Description)
		b.WriteString("Inputs a stack may set:\n")
		for _, in := range m.Inputs {
			fmt.Fprintf(&b, "- %s (%s", in.Name, in.Type)
			if in.Required {
				b.WriteString(", required")
			}
			if in.Default != nil {
				d, _ := json.Marshal(in.Default)
				fmt.Fprintf(&b, ", default %s", d)
			}
			if len(in.Allowed) > 0 {
				a, _ := json.Marshal(in.Allowed)
				fmt.Fprintf(&b, ", one of %s", a)
			}
			if in.Pattern != "" {
				fmt.Fprintf(&b, ", must match %s", in.Pattern)
			}
			if in.ItemPattern != "" {
				fmt.Fprintf(&b, ", items must match %s", in.ItemPattern)
			}
			if in.Min != nil || in.Max != nil {
				fmt.Fprintf(&b, ", range %v..%v", fmtNum(in.Min), fmtNum(in.Max))
			}
			if in.MaxItems > 0 {
				fmt.Fprintf(&b, ", at most %d items", in.MaxItems)
			}
			fmt.Fprintf(&b, "): %s\n", in.Description)
		}
		if len(m.Enforced) > 0 {
			e, _ := json.Marshal(m.Enforced)
			fmt.Fprintf(&b, "Enforced baseline (set by the platform, stacks cannot change these): %s\n", e)
		}
		fmt.Fprintf(&b, "Outputs: %s\n", strings.Join(m.Outputs, ", "))
		docs = append(docs, Doc{ID: "catalog:" + m.ID, Kind: "catalog", Title: m.Title, Text: b.String()})
	}
	return docs
}

func cloudName(c string) string {
	if c == "" {
		return "any (no cloud credentials)"
	}
	return c
}

func fmtNum(f *float64) string {
	if f == nil {
		return "-"
	}
	return fmt.Sprint(*f)
}

// MarkdownDocs splits a Markdown document into one passage per ## section.
func MarkdownDocs(name string, md []byte) []Doc {
	var docs []Doc
	title, body := name, &bytes.Buffer{}
	flush := func() {
		if t := strings.TrimSpace(body.String()); t != "" {
			docs = append(docs, Doc{ID: "doc:" + name + "#" + slug(title), Kind: "doc", Title: name + ": " + title, Text: t})
		}
		body.Reset()
	}
	for _, line := range strings.Split(string(md), "\n") {
		if strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "# ") {
			flush()
			title = strings.TrimSpace(strings.TrimLeft(line, "# "))
			continue
		}
		body.WriteString(line + "\n")
	}
	flush()
	return docs
}

func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}

// DirDocs indexes the Markdown files in dir (not recursive).
func DirDocs(dir string) ([]Doc, error) {
	if dir == "" {
		return nil, nil
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		return nil, err
	}
	var docs []Doc
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if len(b) > 1<<20 {
			continue
		}
		docs = append(docs, MarkdownDocs(strings.ToLower(strings.TrimSuffix(filepath.Base(f), ".md")), b)...)
	}
	return docs, nil
}
