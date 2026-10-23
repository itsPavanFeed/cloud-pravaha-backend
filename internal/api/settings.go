package api

import (
	"context"
	"net/http"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/risk"
)

const riskKey = "risk"

// riskSettings returns the tenant's risk policy, or the defaults.
func (s *Server) riskSettings(ctx context.Context) risk.Settings {
	cfg := risk.Default()
	if ok, err := s.store.Setting(ctx, riskKey, &cfg); err != nil || !ok || cfg.Validate() != nil {
		if err != nil {
			s.log.Error("loading risk settings; using defaults", "err", err)
		}
		return risk.Default()
	}
	return cfg
}

func (s *Server) getRiskSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.riskSettings(r.Context()))
}

// putRiskSettings: tenant admins and security may change the risk policy.
func (s *Server) putRiskSettings(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !p.HasTenantRole(identity.TenantAdmin, identity.Security) {
		writeErr(w, http.StatusForbidden, "changing the risk policy needs tenant_admin or security")
		return
	}
	var cfg risk.Settings
	if !decode(w, r, &cfg) {
		return
	}
	if err := cfg.Validate(); err != nil {
		writeErr(w, 422, "invalid risk settings", errLines(err)...)
		return
	}
	before := s.riskSettings(r.Context())
	if err := s.store.PutSetting(r.Context(), riskKey, cfg, p.Subject); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "settings.risk", "settings/risk", "", map[string]any{"before": before, "after": cfg})
	writeJSON(w, 200, cfg)
}
