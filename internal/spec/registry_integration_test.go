package spec_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/depcheck"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/spec"
)

// TestFixtureStacksAgainstRegistry renders each fixture stack with the real
// catalog, downloads its modules and providers, runs the post-init dependency
// check and `tofu validate`. It needs network access and tofu on PATH:
//
//	PRAVAHA_TOFU_INTEGRATION=1 go test ./internal/spec -run Registry -v
func TestFixtureStacksAgainstRegistry(t *testing.T) {
	if os.Getenv("PRAVAHA_TOFU_INTEGRATION") == "" {
		t.Skip("set PRAVAHA_TOFU_INTEGRATION=1 to run against the OpenTofu registry")
	}
	tofu, err := exec.LookPath("tofu")
	if err != nil {
		t.Skip("tofu is not on PATH")
	}
	res := filepath.Join("..", "..", "..", "cloud-pravaha-test-resources")
	cat, err := catalog.Load(filepath.Join("..", "..", "..", "cloud-pravaha-modules", "catalog"))
	if err != nil {
		t.Fatal(err)
	}
	read := func(t *testing.T, p string, v any) {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatal(p, err)
		}
	}
	cache := t.TempDir()
	for _, name := range []string{"aws-network", "aws-bucket", "aws-platform", "gcp-network", "gcp-platform", "azure-storage", "azure-platform"} {
		t.Run(name, func(t *testing.T) {
			var fx struct {
				Environment string          `json:"environment"`
				Spec        json.RawMessage `json:"spec"`
			}
			read(t, filepath.Join(res, "stacks", name+".json"), &fx)
			var env struct {
				Connection string `json:"connection"`
			}
			read(t, filepath.Join(res, "environments", fx.Environment+".json"), &env)
			var conn struct {
				Cloud json.RawMessage `json:"cloud"`
			}
			read(t, filepath.Join(res, "connections", env.Connection+".json"), &conn)
			cloud, err := spec.DecodeCloud(conn.Cloud)
			if err != nil {
				t.Fatal(err)
			}
			st, err := spec.Decode(fx.Spec)
			if err != nil {
				t.Fatal(err)
			}
			gen, err := st.Generate(cat, spec.GenerateInput{StackName: name, Environment: fx.Environment, Cloud: cloud, TofuVersion: "1.13.2"})
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			for f, b := range gen.Files {
				p := filepath.Join(dir, filepath.FromSlash(f))
				os.MkdirAll(filepath.Dir(p), 0o700)
				if err := os.WriteFile(p, b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if cloud.Provider == "gcp" { // the runner writes this per phase
				os.MkdirAll(filepath.Join(dir, ".pravaha"), 0o700)
				os.WriteFile(filepath.Join(dir, filepath.FromSlash(spec.GCPExternalFile)), []byte(`{"type":"external_account","audience":"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/p","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"https://sts.googleapis.com/v1/token","credential_source":{"file":"/dev/null"}}`), 0o600)
			}
			run := func(args ...string) {
				t.Helper()
				cmd := exec.Command(tofu, args...)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "TF_PLUGIN_CACHE_DIR="+cache, "TF_IN_AUTOMATION=1")
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("tofu %v: %v\n%s", args, err, out)
				}
			}
			run("init", "-input=false", "-no-color", "-backend=false")
			if err := depcheck.Check(dir, cat); err != nil {
				t.Fatalf("depcheck: %v", err)
			}
			run("validate", "-no-color")
		})
	}
}
