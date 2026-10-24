// Package httpx holds HTTP helpers shared by the central and tenant planes.
package httpx

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func WriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func WriteErr(w http.ResponseWriter, code int, msg string, details ...string) {
	body := map[string]any{"error": msg}
	if len(details) > 0 {
		body["details"] = details
	}
	WriteJSON(w, code, body)
}

// Decode reads a size-limited JSON body, rejecting unknown fields.
func Decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		WriteErr(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return false
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		WriteErr(w, http.StatusBadRequest, "invalid request body: trailing data")
		return false
	}
	return true
}

// ErrLines splits a joined validation error into one message per problem.
func ErrLines(err error) []string {
	var out []string
	for _, l := range strings.Split(err.Error(), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func Bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Limiter locks out client IPs after repeated authentication failures.
type Limiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	lockout  time.Duration
	failures map[string][]time.Time
	until    map[string]time.Time
}

func NewLimiter(max int, window, lockout time.Duration) *Limiter {
	return &Limiter{max: max, window: window, lockout: lockout, failures: map[string][]time.Time{}, until: map[string]time.Time{}}
}

func (l *Limiter) Blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Now().Before(l.until[ip])
}

// Fail records a failure and reports whether the client just got locked out.
func (l *Limiter) Fail(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var recent []time.Time
	for _, t := range l.failures[ip] {
		if now.Sub(t) < l.window {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	l.failures[ip] = recent
	if len(recent) >= l.max {
		l.until[ip] = now.Add(l.lockout)
		delete(l.failures, ip)
		return true
	}
	if len(l.failures) > 100000 { // bound memory under a distributed attack
		l.failures = map[string][]time.Time{}
	}
	return false
}

// SecurityHeaders sets hardening headers on every response.
func SecurityHeaders(hsts bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/state/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// SPA serves a single-page app, falling back to index.html.
func SPA(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		p := filepath.Join(dir, clean)
		st, err := os.Stat(p)
		switch {
		case strings.HasPrefix(clean, "/assets/") && (err != nil || st.IsDir()):
			// A missing build file (e.g. a chunk of an older release) is a 404,
			// never the app's HTML, so the browser can tell and reload.
			http.NotFound(w, r)
		case err != nil || st.IsDir():
			w.Header().Set("Cache-Control", "no-cache") // always pick up a new release
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
		case strings.HasPrefix(clean, "/assets/"):
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable") // fingerprinted file names
			fs.ServeHTTP(w, r)
		default:
			fs.ServeHTTP(w, r)
		}
	})
}

// Serve runs an HTTP(S) server until ctx is cancelled.
func Serve(ctx context.Context, log *slog.Logger, addr string, h http.Handler, tlsCfg *tls.Config, cert, key string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		TLSConfig:         tlsCfg,
	}
	errc := make(chan error, 1)
	go func() {
		if tlsCfg == nil {
			errc <- srv.ListenAndServe()
		} else {
			errc <- srv.ListenAndServeTLS(cert, key)
		}
	}()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		return err
	}
}
