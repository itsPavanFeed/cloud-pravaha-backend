// Package blob stores large objects (state versions, saved plans) in a
// tenant's own S3-compatible bucket: AWS S3, MinIO, Ceph, or Google Cloud
// Storage's XML API with HMAC keys. It is a small AWS Signature V4 client with
// path-style addressing and no third-party dependencies.
package blob

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ErrNotFound is returned for missing objects.
var ErrNotFound = errors.New("object not found")

const maxObject = 256 << 20

type Config struct {
	Endpoint  string // e.g. https://s3.eu-west-1.amazonaws.com or https://minio.internal:9000
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	Prefix    string // optional key prefix, e.g. "acme/"
}

type S3 struct {
	cfg Config
	hc  *http.Client
	now func() time.Time
}

// ParseURL reads s3://bucket/prefix?endpoint=https://...&region=eu-west-1.
func ParseURL(raw, accessKey, secretKey string) (Config, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "s3" || u.Host == "" {
		return Config{}, errors.New("bucket URL must look like s3://bucket[/prefix]?endpoint=https://host&region=REGION")
	}
	q := u.Query()
	c := Config{Bucket: u.Host, Prefix: strings.Trim(u.Path, "/"), Region: q.Get("region"), Endpoint: strings.TrimRight(q.Get("endpoint"), "/"), AccessKey: accessKey, SecretKey: secretKey}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	if c.Endpoint == "" {
		c.Endpoint = "https://s3." + c.Region + ".amazonaws.com"
	}
	if c.Prefix != "" {
		c.Prefix += "/"
	}
	ep, err := url.Parse(c.Endpoint)
	if err != nil || ep.Host == "" || (ep.Scheme != "https" && !(ep.Scheme == "http" && isLoopback(ep.Hostname()))) {
		return Config{}, errors.New("bucket endpoint must be https (plain http only on loopback for development)")
	}
	if c.AccessKey == "" || c.SecretKey == "" {
		return Config{}, errors.New("bucket credentials are required (PRAVAHA_BUCKET_ACCESS_KEY[_FILE], PRAVAHA_BUCKET_SECRET_KEY[_FILE])")
	}
	return c, nil
}

func isLoopback(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

func New(c Config, hc *http.Client) *S3 {
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Minute}
	}
	return &S3{cfg: c, hc: hc, now: time.Now}
}

func (s *S3) Put(ctx context.Context, key string, data []byte) error {
	resp, err := s.do(ctx, http.MethodPut, s.cfg.Prefix+key, data)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	resp, err := s.do(ctx, http.MethodGet, s.cfg.Prefix+key, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, maxObject))
}

func (s *S3) Delete(ctx context.Context, key string) error {
	resp, err := s.do(ctx, http.MethodDelete, s.cfg.Prefix+key, nil)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if resp != nil {
		resp.Body.Close()
	}
	return nil
}

// EnsureBucket creates the bucket if it does not exist (development setups).
func (s *S3) EnsureBucket(ctx context.Context) error {
	resp, err := s.do(ctx, http.MethodHead, "", nil)
	if err == nil {
		resp.Body.Close()
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	resp, err = s.do(ctx, http.MethodPut, "", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (s *S3) do(ctx context.Context, method, key string, body []byte) (*http.Response, error) {
	path := "/" + s.cfg.Bucket
	if key != "" {
		path += "/" + encodePath(key)
	}
	u := s.cfg.Endpoint + path
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	s.sign(req, path, payload)
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, ErrNotFound
	}
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("object store %s %s: %s %s", method, key, resp.Status, strings.TrimSpace(string(msg)))
	}
	return resp, nil
}

// sign adds AWS Signature Version 4 headers.
func (s *S3) sign(req *http.Request, path, payload string) {
	t := s.now().UTC()
	amzDate := t.Format("20060102T150405Z")
	day := t.Format("20060102")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payload)
	host := req.URL.Host

	headers := map[string]string{"host": host, "x-amz-content-sha256": payload, "x-amz-date": amzDate}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + headers[k] + "\n")
	}
	signed := strings.Join(names, ";")
	canonical := strings.Join([]string{req.Method, path, "", canonHeaders.String(), signed, payload}, "\n")
	scope := day + "/" + s.cfg.Region + "/s3/aws4_request"
	h := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(h[:])
	k := hmacSHA256([]byte("AWS4"+s.cfg.SecretKey), day)
	k = hmacSHA256(k, s.cfg.Region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.cfg.AccessKey+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// encodePath URI-encodes each segment as SigV4 requires (RFC 3986 unreserved).
func encodePath(key string) string {
	segs := strings.Split(key, "/")
	for i, seg := range segs {
		var b strings.Builder
		for _, c := range []byte(seg) {
			if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "%%%02X", c)
			}
		}
		segs[i] = b.String()
	}
	return strings.Join(segs, "/")
}
