// Package bundlecache keeps release bundles close to where they are used, so
// the database or bucket holding them is read once per bundle rather than
// once per run.
//
// Bundles are content-addressed and immutable, which makes caching safe:
// a bundle is found by its SHA-256 and verified against it on every load
// from disk or from the origin. Lookups go memory, then disk, then origin,
// and concurrent misses for the same bundle share one origin read.
package bundlecache

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"

	"golang.org/x/sync/singleflight"
)

// Loader reads a bundle from its origin (the database, a bucket, or the
// tenant plane, for runners).
type Loader func(ctx context.Context, sha string) ([]byte, error)

type Cache struct {
	load    Loader
	dir     string // "" = no disk cache
	maxMem  int64
	maxDisk int64

	mu    sync.Mutex
	lru   *list.List // of *entry, most recent first
	byKey map[string]*list.Element
	used  int64

	group                          singleflight.Group
	memHits, diskHits, originLoads atomic.Int64
}

type entry struct {
	sha string
	b   []byte
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrBadChecksum means the origin returned bytes that are not the bundle asked for.
var ErrBadChecksum = errors.New("bundle does not match its checksum")

// New builds a cache. dir may be empty to cache in memory only.
func New(load Loader, dir string, maxMem, maxDisk int64) (*Cache, error) {
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	return &Cache{load: load, dir: dir, maxMem: maxMem, maxDisk: maxDisk, lru: list.New(), byKey: map[string]*list.Element{}}, nil
}

// Get returns the bundle with this checksum.
func (c *Cache) Get(ctx context.Context, sha string) ([]byte, error) {
	if !shaRe.MatchString(sha) {
		return nil, errors.New("invalid bundle checksum")
	}
	if b := c.fromMemory(sha); b != nil {
		c.memHits.Add(1)
		return b, nil
	}
	v, err, _ := c.group.Do(sha, func() (any, error) {
		if b := c.fromMemory(sha); b != nil {
			return b, nil
		}
		if b := c.fromDisk(sha); b != nil {
			c.diskHits.Add(1)
			c.remember(sha, b)
			return b, nil
		}
		b, err := c.load(ctx, sha)
		if err != nil {
			return nil, err
		}
		if !matches(b, sha) {
			return nil, ErrBadChecksum
		}
		c.originLoads.Add(1)
		c.toDisk(sha, b)
		c.remember(sha, b)
		return b, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]byte), nil
}

// Stats reports how bundles were served, for operators.
func (c *Cache) Stats() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]int64{"memory_hits": c.memHits.Load(), "disk_hits": c.diskHits.Load(), "origin_loads": c.originLoads.Load(),
		"memory_bytes": c.used, "memory_bundles": int64(c.lru.Len())}
}

func matches(b []byte, sha string) bool {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]) == sha
}

func (c *Cache) fromMemory(sha string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byKey[sha]; ok {
		c.lru.MoveToFront(el)
		return el.Value.(*entry).b
	}
	return nil
}

func (c *Cache) remember(sha string, b []byte) {
	if int64(len(b)) > c.maxMem {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.byKey[sha]; ok {
		return
	}
	c.byKey[sha] = c.lru.PushFront(&entry{sha, b})
	c.used += int64(len(b))
	for c.used > c.maxMem {
		last := c.lru.Back()
		e := last.Value.(*entry)
		c.lru.Remove(last)
		delete(c.byKey, e.sha)
		c.used -= int64(len(e.b))
	}
}

func (c *Cache) fromDisk(sha string) []byte {
	if c.dir == "" {
		return nil
	}
	p := filepath.Join(c.dir, sha)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	if !matches(b, sha) { // corrupted or tampered with: drop it and reload
		os.Remove(p)
		return nil
	}
	now := fileTimeNow()
	os.Chtimes(p, now, now) // recently used: kept longest
	return b
}

func (c *Cache) toDisk(sha string, b []byte) {
	if c.dir == "" || int64(len(b)) > c.maxDisk {
		return
	}
	tmp, err := os.CreateTemp(c.dir, ".tmp-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), filepath.Join(c.dir, sha)) != nil {
		os.Remove(tmp.Name())
		return
	}
	c.trimDisk()
}

// trimDisk removes the least recently used bundles beyond the size limit.
func (c *Cache) trimDisk() {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return
	}
	type f struct {
		path string
		size int64
		mod  int64
	}
	var files []f
	var total int64
	for _, e := range entries {
		if !shaRe.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, f{filepath.Join(c.dir, e.Name()), info.Size(), info.ModTime().UnixNano()})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod < files[j].mod })
	for _, x := range files {
		if total <= c.maxDisk {
			break
		}
		if os.Remove(x.path) == nil {
			total -= x.size
		}
	}
}
