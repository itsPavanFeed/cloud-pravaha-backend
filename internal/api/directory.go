package api

import (
	"context"
	"maps"
)

// The tenant plane learns its business units from central: every user request
// carries the tenant's full BU → entity map in the assertion. The latest map is
// kept in memory and persisted, so work without a user (contracts sync) can
// check that a business unit exists and which entity it belongs to.

const directorySetting = "directory"

type directory struct {
	BUEntity map[string]string `json:"bu_entity"`
}

func (s *Server) loadDirectory(ctx context.Context) {
	var d directory
	if ok, _ := s.store.Setting(ctx, directorySetting, &d); ok && d.BUEntity != nil {
		s.dirSnap.Store(&d.BUEntity)
	}
}

// noteDirectory records the map from a verified assertion when it changed.
func (s *Server) noteDirectory(ctx context.Context, m map[string]string) {
	if m == nil {
		return
	}
	if cur := s.dirSnap.Load(); cur != nil && maps.Equal(*cur, m) {
		return
	}
	cp := maps.Clone(m)
	s.dirSnap.Store(&cp)
	go func() {
		if err := s.store.PutSetting(context.WithoutCancel(ctx), directorySetting, directory{BUEntity: cp}, "system:directory"); err != nil {
			s.log.Warn("saving the business unit directory failed", "err", err)
		}
	}()
}

// buEntity returns the entity a business unit belongs to.
func (s *Server) buEntity(bu string) (string, bool) {
	cur := s.dirSnap.Load()
	if cur == nil {
		return "", false
	}
	e, ok := (*cur)[bu]
	return e, ok
}
