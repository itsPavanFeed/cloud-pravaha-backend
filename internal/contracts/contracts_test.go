package contracts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sha = "0123456789abcdef0123456789abcdef01234567"

func tarball(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		tw.WriteHeader(&tar.Header{Name: "acme-contracts-" + sha[:7] + "/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.WriteHeader(&tar.Header{Name: "acme-contracts-" + sha[:7] + "/../escape.json", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	tw.Write([]byte("{}"))
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

var repoFiles = map[string]string{
	"stacks/payments-net.json": `{"name":"payments-net","environment":"payments-dev","spec":{"modules":[{"name":"n","module":"azure-naming"}]}}`,
	"stacks/wrong-name.json":   `{"name":"other","environment":"payments-dev","spec":{"modules":[]}}`,
	"stacks/bad.json":          `{"name":"bad","environment":"x","spec":{},"terraform":{}}`,
	"README.md":                "# contracts",
}

func TestGitHub(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/repos/acme/contracts/commits/main" && r.Header.Get("Accept") == "application/vnd.github.sha":
			w.Write([]byte(sha))
		case r.URL.Path == "/repos/acme/contracts/tarball/"+sha:
			w.Write(tarball(t, repoFiles))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	src, _ := New(Config{Provider: "github", Repo: "acme/contracts", Branch: "main", APIURL: srv.URL}, "tok", srv.Client())
	rev, err := src.Revision(context.Background())
	if err != nil || rev != sha {
		t.Fatalf("revision %q %v", rev, err)
	}
	files, err := src.Files(context.Background(), rev)
	if err != nil {
		t.Fatal(err)
	}
	if _, escaped := files["../escape.json"]; escaped || len(files) != 4 {
		t.Fatalf("unexpected files: %v", keys(files))
	}
	cs, problems := Parse(files, "stacks")
	if len(cs) != 1 || cs[0].Name != "payments-net" || len(problems) != 2 {
		t.Fatalf("contracts %+v problems %v", cs, problems)
	}
}

func TestGitLab(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "tok" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.EscapedPath() == "/projects/acme%2Finfra%2Fcontracts/repository/branches/main":
			w.Write([]byte(`{"commit":{"id":"` + sha + `"}}`))
		case r.URL.EscapedPath() == "/projects/acme%2Finfra%2Fcontracts/repository/archive.tar.gz" && r.URL.Query().Get("sha") == sha:
			w.Write(tarball(t, repoFiles))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	src, _ := New(Config{Provider: "gitlab", Repo: "acme/infra/contracts", Branch: "main", APIURL: srv.URL}, "tok", srv.Client())
	rev, err := src.Revision(context.Background())
	if err != nil || rev != sha {
		t.Fatalf("revision %q %v", rev, err)
	}
	if files, err := src.Files(context.Background(), rev); err != nil || len(files) != 4 {
		t.Fatalf("files %v %v", keys(files), err)
	}
}

func TestConfigValidation(t *testing.T) {
	good := Config{Provider: "github", Repo: "acme/contracts", Branch: "main", Path: "stacks", PollSeconds: 60}
	if err := good.Validate(false); err != nil {
		t.Fatal(err)
	}
	bad := []Config{
		{Provider: "local", Repo: "/tmp/x", Branch: "main", PollSeconds: 60},
		{Provider: "github", Repo: "acme", Branch: "main", PollSeconds: 60},
		{Provider: "github", Repo: "acme/c", Branch: "../x", PollSeconds: 60},
		{Provider: "github", Repo: "acme/c", Branch: "main", Path: "../etc", PollSeconds: 60},
		{Provider: "github", Repo: "acme/c", Branch: "main", PollSeconds: 5},
		{Provider: "github", Repo: "acme/c", Branch: "main", PollSeconds: 60, APIURL: "http://insecure"},
		{Provider: "svn", Repo: "acme/c", Branch: "main", PollSeconds: 60},
	}
	for i, c := range bad {
		if c.Validate(false) == nil {
			t.Errorf("bad config %d accepted", i)
		}
	}
}

func keys(m map[string][]byte) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return strings.Join(ks, ",")
}
