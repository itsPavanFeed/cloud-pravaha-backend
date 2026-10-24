package api

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/envfile"
)

// Where the GitHub App settings live:
//
//   - PRAVAHA_ENV_FILE set (a writable .env, e.g. a self-hosted install or
//     development): the PRAVAHA_GITHUB_* keys in that file, with the private key
//     in a separate PEM file next to it. Saving in the console writes the file;
//     editing the file by hand is picked up within seconds.
//   - otherwise: sealed with the tenant master key in the database.
//
// Either way the settings are held in memory and swapped atomically on change,
// so webhook deliveries and token minting never read the file or the database.

const (
	envGitHubAppID   = "PRAVAHA_GITHUB_APP_ID"
	envGitHubInst    = "PRAVAHA_GITHUB_APP_INSTALLATION_ID"
	envGitHubAPI     = "PRAVAHA_GITHUB_API_URL"
	envGitHubKeyFile = "PRAVAHA_GITHUB_APP_PRIVATE_KEY_FILE"
	envGitHubSecret  = "PRAVAHA_GITHUB_WEBHOOK_SECRET"
	envGitHubSlug    = "PRAVAHA_GITHUB_APP_SLUG"
	defaultKeyFile   = "github-app-private-key.pem"
)

type ghSettings struct {
	Cfg     githubAppConfig
	OK      bool // an app ID is configured
	Key     []byte
	Secret  []byte
	Source  string // env_file | database
	KeyFile string // env_file source: the PEM file
}

func (s *Server) ghState() *ghSettings {
	if g := s.ghSnap.Load(); g != nil {
		return g
	}
	return &ghSettings{Source: s.ghSource()}
}

func (s *Server) ghSource() string {
	if s.cfg.EnvFile != "" {
		return "env_file"
	}
	return "database"
}

func (s *Server) githubAppConfig(context.Context) (*githubAppConfig, bool) {
	g := s.ghState()
	c := g.Cfg
	return &c, g.OK
}

func (s *Server) ghReload(ctx context.Context) error {
	var g *ghSettings
	var err error
	if s.cfg.EnvFile != "" {
		g, err = s.ghFromEnvFile()
	} else {
		g, err = s.ghFromDatabase(ctx)
	}
	if err != nil {
		return err
	}
	s.ghSnap.Store(g)
	return nil
}

func (s *Server) ghFromEnvFile() (*ghSettings, error) {
	m, err := envfile.Read(s.cfg.EnvFile)
	if err != nil {
		return nil, err
	}
	g := &ghSettings{Source: "env_file"}
	g.Cfg.AppID, _ = strconv.ParseInt(m[envGitHubAppID], 10, 64)
	g.Cfg.InstallationID, _ = strconv.ParseInt(m[envGitHubInst], 10, 64)
	g.Cfg.APIURL, g.Cfg.AppSlug = m[envGitHubAPI], m[envGitHubSlug]
	g.OK = g.Cfg.AppID > 0
	if v := m[envGitHubSecret]; v != "" {
		g.Secret = []byte(v)
	}
	if kf := m[envGitHubKeyFile]; kf != "" {
		if !filepath.IsAbs(kf) {
			kf = filepath.Join(filepath.Dir(s.cfg.EnvFile), kf)
		}
		g.KeyFile = kf
		if b, err := os.ReadFile(kf); err == nil {
			g.Key = b
		} else {
			s.log.Warn("GitHub App private key file unreadable", "file", kf, "err", err)
		}
	}
	return g, nil
}

func (s *Server) ghFromDatabase(ctx context.Context) (*ghSettings, error) {
	g := &ghSettings{Source: "database"}
	ok, err := s.store.Setting(ctx, githubAppSetting, &g.Cfg)
	if err != nil {
		return nil, err
	}
	g.OK = ok && g.Cfg.AppID > 0
	g.Key, _ = s.openSetting(ctx, githubKeySetting, githubKeyAAD)
	g.Secret, _ = s.openSetting(ctx, githubSecretSetting, githubSecretAAD)
	return g, nil
}

// ghSave stores the configuration; a nil key or secret keeps the current one.
func (s *Server) ghSave(ctx context.Context, cfg githubAppConfig, key, secret []byte, by string) error {
	if s.cfg.EnvFile != "" {
		set := map[string]string{envGitHubAppID: strconv.FormatInt(cfg.AppID, 10), envGitHubAPI: cfg.APIURL, envGitHubSlug: cfg.AppSlug, envGitHubInst: ""}
		if cfg.InstallationID > 0 {
			set[envGitHubInst] = strconv.FormatInt(cfg.InstallationID, 10)
		}
		if key != nil {
			kf := s.ghState().KeyFile
			if kf == "" {
				kf = filepath.Join(filepath.Dir(s.cfg.EnvFile), defaultKeyFile)
			}
			if err := envfile.WriteFile(kf, key); err != nil {
				return err
			}
			set[envGitHubKeyFile] = kf
			if rel, err := filepath.Rel(filepath.Dir(s.cfg.EnvFile), kf); err == nil && !strings.HasPrefix(rel, "..") {
				set[envGitHubKeyFile] = rel
			}
		}
		if secret != nil {
			set[envGitHubSecret] = string(secret)
		}
		if err := envfile.Update(s.cfg.EnvFile, set); err != nil {
			return err
		}
	} else {
		if key != nil {
			if err := s.sealSetting(ctx, githubKeySetting, githubKeyAAD, key, by); err != nil {
				return err
			}
		}
		if secret != nil {
			if err := s.sealSetting(ctx, githubSecretSetting, githubSecretAAD, secret, by); err != nil {
				return err
			}
		}
		if err := s.store.PutSetting(ctx, githubAppSetting, cfg, by); err != nil {
			return err
		}
	}
	return s.ghReload(ctx)
}

func (s *Server) ghClear(ctx context.Context) error {
	if s.cfg.EnvFile != "" {
		if kf := s.ghState().KeyFile; kf != "" {
			if err := os.Remove(kf); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if err := envfile.Update(s.cfg.EnvFile, map[string]string{envGitHubAppID: "", envGitHubInst: "", envGitHubAPI: "",
			envGitHubKeyFile: "", envGitHubSecret: "", envGitHubSlug: ""}); err != nil {
			return err
		}
	} else {
		for _, k := range []string{githubAppSetting, githubKeySetting, githubSecretSetting} {
			if err := s.store.DeleteSetting(ctx, k); err != nil {
				return err
			}
		}
	}
	return s.ghReload(ctx)
}

// ghWatch keeps the in-memory settings current: file changes are picked up
// within two seconds; database settings (changed by another replica) within a minute.
func (s *Server) ghWatch(ctx context.Context) {
	reload := func() {
		s.loadSlack(ctx)
		if err := s.ghReload(ctx); err != nil {
			s.log.Warn("reloading GitHub App settings failed", "err", err)
			return
		}
		if s.cfg.EnvFile != "" {
			s.log.Info("GitHub App settings reloaded", "file", s.cfg.EnvFile)
		}
	}
	if s.cfg.EnvFile != "" {
		envfile.Watch(ctx, 2*time.Second, reload, func() []string { return []string{s.cfg.EnvFile, s.ghState().KeyFile} })
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.loadSlack(ctx)
			if err := s.ghReload(ctx); err != nil {
				s.log.Warn("reloading GitHub App settings failed", "err", err)
			}
		}
	}
}
