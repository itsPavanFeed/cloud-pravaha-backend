package api

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/config"
)

func TestGitHubSettingsInEnvFile(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	os.WriteFile(env, []byte("POSTGRES_PASSWORD=keep\nPRAVAHA_GITHUB_WEBHOOK_SECRET=from-file-1234567890\n"), 0o600)
	s := &Server{cfg: &config.Server{EnvFile: env}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()
	if err := s.ghReload(ctx); err != nil {
		t.Fatal(err)
	}
	if g := s.ghState(); g.OK || string(g.Secret) != "from-file-1234567890" || g.Source != "env_file" {
		t.Fatalf("%+v", g)
	}
	pem := []byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")
	if err := s.ghSave(ctx, githubAppConfig{AppID: 5450441, InstallationID: 7}, pem, nil, "test"); err != nil {
		t.Fatal(err)
	}
	g := s.ghState()
	if !g.OK || g.Cfg.AppID != 5450441 || g.Cfg.InstallationID != 7 || string(g.Key) != string(pem) || string(g.Secret) != "from-file-1234567890" {
		t.Fatalf("after save: %+v", g)
	}
	b, _ := os.ReadFile(env)
	for _, want := range []string{"POSTGRES_PASSWORD=keep", "PRAVAHA_GITHUB_APP_ID=5450441", "PRAVAHA_GITHUB_APP_INSTALLATION_ID=7", "PRAVAHA_GITHUB_APP_PRIVATE_KEY_FILE=" + defaultKeyFile} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing %q in:\n%s", want, b)
		}
	}
	if fi, _ := os.Stat(filepath.Join(dir, defaultKeyFile)); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("key file missing or not private")
	}
	if err := s.ghClear(ctx); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(env)
	if strings.Contains(string(b), "PRAVAHA_GITHUB") || !strings.Contains(string(b), "POSTGRES_PASSWORD=keep") || s.ghState().OK {
		t.Fatalf("after clear:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(dir, defaultKeyFile)); !os.IsNotExist(err) {
		t.Fatal("key file not removed")
	}
}
