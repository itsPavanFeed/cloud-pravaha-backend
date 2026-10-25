package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/spec"
)

// The tenant's secret store (OpenBao or HashiCorp Vault). It holds no
// credentials: contracts reference secrets (vault://mount/path#key) and runs
// read them with their own short-lived token through Vault's JWT auth method.
const secretStoreKey = "secret_store"

func (s *Server) secretStore(ctx context.Context) *spec.Vault {
	var v spec.Vault
	if ok, err := s.store.Setting(ctx, secretStoreKey, &v); err != nil || !ok || v.Validate() != nil {
		return nil
	}
	return &v
}

func (s *Server) getSecretStore(w http.ResponseWriter, r *http.Request) {
	v := s.secretStore(r.Context())
	resp := map[string]any{"configured": v != nil, "issuer": s.cfg.PublicURL, "jwks_url": strings.TrimRight(s.cfg.PublicURL, "/") + "/.well-known/jwks.json",
		"public_key_pem": s.issuer.PublicKeyPEM(), "audience": (&spec.Vault{}).TokenAudience()}
	if v != nil {
		resp["config"] = v
		resp["audience"] = v.TokenAudience()
	}
	writeJSON(w, 200, resp)
}

func (s *Server) putSecretStore(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var v spec.Vault
	if !decode(w, r, &v) {
		return
	}
	v.Address = strings.TrimRight(v.Address, "/")
	if err := v.Validate(); err != nil {
		writeErr(w, 422, "invalid secret store", errLines(err)...)
		return
	}
	if err := s.store.PutSetting(r.Context(), secretStoreKey, v, user(r).Subject); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "secret_store.configure", "integrations/secret-store", "", v)
	writeJSON(w, 200, v)
}

func (s *Server) deleteSecretStore(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	if err := s.store.DeleteSetting(r.Context(), secretStoreKey); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "secret_store.remove", "integrations/secret-store", "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// testSecretStore checks the store answers its unauthenticated health
// endpoint. It cannot test a login: only runs hold tokens Vault accepts.
func (s *Server) testSecretStore(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	v := s.secretStore(r.Context())
	if v == nil {
		writeErr(w, http.StatusConflict, "no secret store is configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, v.Address+"/v1/sys/health?standbyok=true&perfstandbyok=true", nil)
	if v.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.Namespace)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "cannot reach " + v.Address + ": " + err.Error()})
		return
	}
	defer resp.Body.Close()
	var h struct {
		Initialized bool   `json:"initialized"`
		Sealed      bool   `json:"sealed"`
		Version     string `json:"version"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&h)
	out := map[string]any{"ok": resp.StatusCode == 200 && h.Initialized && !h.Sealed, "status": resp.StatusCode, "version": h.Version, "sealed": h.Sealed, "initialized": h.Initialized}
	if out["ok"] == false {
		out["error"] = fmt.Sprintf("the store answered %d (initialized %v, sealed %v)", resp.StatusCode, h.Initialized, h.Sealed)
	}
	writeJSON(w, 200, out)
}
