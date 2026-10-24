// Package envfile reads, updates and watches a dotenv file (KEY=value lines).
//
// The planes use it for settings an operator may keep in .env next to the
// deployment (for example the GitHub App's webhook secret): values are held in
// memory and reloaded when the file changes, so request paths never read the
// file or the database.
package envfile

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var keyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

// Parse reads KEY=value lines. Blank lines and # comments are skipped, an
// optional "export " prefix is allowed, and values may be single- or
// double-quoted. Inline comments after unquoted values are removed.
func Parse(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		k, v, ok := parseLine(sc.Text())
		if ok {
			out[k] = v
		}
	}
	return out
}

func parseLine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	line = strings.TrimPrefix(line, "export ")
	k, v, ok := strings.Cut(line, "=")
	k = strings.TrimSpace(k)
	if !ok || !keyRe.MatchString(k) {
		return "", "", false
	}
	v = strings.TrimSpace(v)
	switch {
	case len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"':
		if u, err := strconv.Unquote(v); err == nil {
			v = u
		} else {
			v = v[1 : len(v)-1]
		}
	case len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'':
		v = v[1 : len(v)-1]
	default:
		if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
	}
	return k, v, true
}

func Read(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(b), nil
}

var writeMu sync.Mutex

// Update sets (or, for an empty value, removes) keys in the file, keeping
// every other line and comment as it is. The file is replaced atomically and
// kept private (0600).
func Update(path string, set map[string]string) error {
	for k, v := range set {
		if !keyRe.MatchString(k) || strings.ContainsAny(v, "\n\r") {
			return fmt.Errorf("invalid entry %q", k)
		}
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	done := map[string]bool{}
	var out bytes.Buffer
	if len(old) > 0 {
		for _, line := range strings.Split(strings.TrimRight(string(old), "\n"), "\n") {
			if k, _, ok := parseLine(line); ok {
				if v, change := set[k]; change {
					if !done[k] && v != "" {
						out.WriteString(k + "=" + quote(v) + "\n")
					}
					done[k] = true
					continue
				}
			}
			out.WriteString(line + "\n")
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !done[k] && set[k] != "" {
			out.WriteString(k + "=" + quote(set[k]) + "\n")
		}
	}
	return WriteFile(path, out.Bytes())
}

// WriteFile writes data atomically with mode 0600.
func WriteFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func quote(v string) string {
	if v == "" || strings.ContainsAny(v, " #\"'\\$`") {
		return strconv.Quote(v)
	}
	return v
}

// Watch calls onChange whenever any of the files' size or modification time
// changes (checked every interval), until ctx ends.
func Watch(ctx context.Context, interval time.Duration, onChange func(), files func() []string) {
	stamp := func() string {
		var b strings.Builder
		for _, f := range files() {
			if fi, err := os.Stat(f); err == nil {
				fmt.Fprintf(&b, "%s:%d:%d;", f, fi.Size(), fi.ModTime().UnixNano())
			} else {
				fmt.Fprintf(&b, "%s:-;", f)
			}
		}
		return b.String()
	}
	last := stamp()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if s := stamp(); s != last {
			last = s
			onChange()
		}
	}
}
