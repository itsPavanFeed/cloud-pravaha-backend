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
	"stacks/payments-net/naming.yaml": "apiVersion: pravaha/v1\nkind: AzureNaming\nmetadata:\n  environment: payments-dev\n  bu: payments\nspec:\n  suffix: [pay]\n",
	"stacks/loose.yaml":               "apiVersion: pravaha/v1\nkind: AzureNaming\n",
	"stacks/bad/x.yaml":               "apiVersion: pravaha/v1\nkind: AzureNaming\nterraform: {}\n",
	"README.md":                       "# contracts",
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

func TestNestedLayout(t *testing.T) {
	r := func(kind, extra string) []byte {
		return []byte("apiVersion: pravaha/v1\nkind: " + kind + "\n" + extra)
	}
	files := map[string][]byte{
		"stacks/retail/prod/payments/api/bucket.yaml": r("S3Bucket", "spec:\n  bucket: acme-api\n"),
		"stacks/retail/prod/payments/api/key.yml":     r("KMSKey", "metadata:\n  name: api-key\n"),
		"stacks/retail/dev/checkout/web/naming.yaml":  r("AzureNaming", "metadata:\n  environment: dev\n  bu: checkout\n"),
		"stacks/retail/dev/checkout/bad/naming.yaml":  r("AzureNaming", "metadata:\n  environment: prod\n"),
		"stacks/retail/dev/checkout/dupe/a.yaml":      r("AzureNaming", "metadata:\n  name: n\n"),
		"stacks/retail/dev/checkout/dupe/b.yaml":      r("AzureNaming", "metadata:\n  name: n\n"),
		"stacks/retail/dev/shallow/naming.yaml":       r("AzureNaming", ""),
		"stacks/retail/dev/checkout/web/README.md":    []byte("# not a contract"),
		"docs/x.yaml": r("AzureNaming", ""),
	}
	cs, probs := ParseLayout(files, "stacks", "nested")
	if len(cs) != 2 {
		t.Fatalf("contracts = %+v problems = %v", cs, probs)
	}
	web, api := cs[0], cs[1] // folders sort: retail/dev before retail/prod
	if api.Name != "api" || api.Environment != "prod" || api.BU != "payments" || api.Entity != "retail" || len(api.Files) != 2 {
		t.Fatalf("api = %+v", api)
	}
	if !strings.Contains(string(api.Spec), `"name":"api_key","kind":"KMSKey"`) || !strings.Contains(string(api.Spec), `"bucket":"acme-api"`) {
		t.Fatalf("api spec = %s", api.Spec)
	}
	if web.Name != "web" || web.BU != "checkout" {
		t.Fatalf("web = %+v", web)
	}
	for _, f := range []string{"stacks/retail/dev/checkout/bad/naming.yaml", "stacks/retail/dev/checkout/dupe/b.yaml", "stacks/retail/dev/shallow/naming.yaml"} {
		if probs[f] == "" {
			t.Errorf("no problem for %s: %v", f, probs)
		}
	}
	if err := (&Config{Provider: "github", Repo: "a/b", Branch: "main", Path: "stacks", PollSeconds: 60, Layout: "deep"}).Validate(false); err == nil {
		t.Fatal("unknown layout accepted")
	}
}

func TestReferencesSecretsImportsOutputs(t *testing.T) {
	files := map[string][]byte{
		"s/orders/key.yaml": []byte("apiVersion: pravaha/v1\nkind: KMSKey\nmetadata:\n  name: orders-key\n  environment: dev\n  bu: payments\noutputs:\n  - name: key-arn\n    value: key_arn\n"),
		"s/orders/db.yaml": []byte(`apiVersion: pravaha/v1
kind: RDSDatabase
metadata:
  name: orders-db
  version: 7.0.0
spec:
  kms_key_id:
    ref: orders-key.key_arn
  password:
    secretRef: vault://kv/orders/db#password
  tags:
    ref: just-a-tag-map
imports:
  - to: aws_db_instance.this[0]
    id: orders
`),
	}
	cs, probs := Parse(files, "s")
	if len(probs) != 1 || probs["s/orders/db.yaml"] == "" {
		t.Fatalf("a malformed ref must be reported: %v", probs)
	}
	files["s/orders/db.yaml"] = []byte(strings.Replace(string(files["s/orders/db.yaml"]), "  tags:\n    ref: just-a-tag-map\n", "", 1))
	cs, probs = Parse(files, "s")
	if len(probs) != 0 || len(cs) != 1 {
		t.Fatalf("contracts %+v problems %v", cs, probs)
	}
	spec := string(cs[0].Spec)
	for _, want := range []string{`"$ref":"orders_key.key_arn"`, `"$secret":"vault://kv/orders/db#password"`, `"to":"module.orders_db.aws_db_instance.this[0]"`,
		`"name":"key_arn","module":"orders_key","output":"key_arn"`, `"version":"7.0.0"`} {
		if !strings.Contains(spec, want) {
			t.Errorf("spec is missing %s:\n%s", want, spec)
		}
	}
	// Render writes the same resources back as contract files.
	out, err := Render(cs[0].Spec, "dev", "payments", true)
	if err != nil {
		t.Fatal(err)
	}
	again := map[string][]byte{}
	for f, b := range out {
		again["s/orders/"+f] = b
	}
	cs2, probs := Parse(again, "s")
	if len(probs) != 0 || len(cs2) != 1 || string(cs2[0].Spec) != string(cs[0].Spec) {
		t.Fatalf("render round trip:\n%s\n%v\n%s", out["orders_db.yaml"], probs, cs2[0].Spec)
	}
	if !strings.Contains(string(out["orders_db.yaml"]), "secretRef: vault://kv/orders/db#password") {
		t.Fatalf("rendered contract:\n%s", out["orders_db.yaml"])
	}
}

func TestRejectsUnsafeYAML(t *testing.T) {
	for name, body := range map[string]string{
		"alias":   "apiVersion: pravaha/v1\nkind: S3Bucket\nmetadata: &m {environment: dev, bu: p}\nspec: {bucket: *m}\n",
		"version": "apiVersion: v2\nkind: S3Bucket\nmetadata: {environment: dev, bu: p}\n",
		"unknown": "apiVersion: pravaha/v1\nkind: S3Bucket\nmetadata: {environment: dev, bu: p}\nprovisioner: {}\n",
		"name":    "apiVersion: pravaha/v1\nkind: S3Bucket\nmetadata: {name: \"Bad Name\", environment: dev, bu: p}\n",
	} {
		_, probs := Parse(map[string][]byte{"s/x/r.yaml": []byte(body)}, "s")
		if len(probs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
}
