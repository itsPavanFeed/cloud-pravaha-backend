package api

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/spec"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

var connNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)

type connBody struct {
	Name     string          `json:"name"`
	Cloud    json.RawMessage `json:"cloud"`
	Entities []string        `json:"entities"` // [] = every entity
}

// Everyone in the tenant may read connections: they hold identifiers only.
func (s *Server) listConnections(w http.ResponseWriter, r *http.Request) {
	cs, err := s.store.ListConnections(r.Context())
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, cs)
}

func (s *Server) getConnection(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetConnection(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	resp := map[string]any{"connection": c}
	if cl, err := spec.DecodeCloud(c.Cloud); err == nil && cl.NeedsOIDCToken() {
		resp["oidc"] = map[string]string{
			"issuer":          s.issuer.URL,
			"audience":        cl.Audience(),
			"subject_pattern": "pravaha:env:*:stack:*",
		}
	}
	writeJSON(w, 200, resp)
}

func (s *Server) validConnection(w http.ResponseWriter, b *connBody, create bool) (json.RawMessage, bool) {
	var probs []string
	if create && !connNameRe.MatchString(b.Name) {
		probs = append(probs, "name must be lowercase letters, digits and dashes (2-48)")
	}
	if b.Entities == nil {
		b.Entities = []string{}
	}
	for _, e := range b.Entities {
		if !identity.SlugRe.MatchString(e) {
			probs = append(probs, "entities must be entity slugs")
		}
	}
	c, err := spec.DecodeCloud(b.Cloud)
	if err != nil {
		probs = append(probs, errLines(err)...)
	} else if c.Provider == "none" {
		probs = append(probs, `a connection needs a cloud provider; environments without a cloud simply have no connection`)
	}
	if len(probs) > 0 {
		writeErr(w, 422, "invalid cloud connection", probs...)
		return nil, false
	}
	cloud, _ := json.Marshal(c)
	return cloud, true
}

func (s *Server) createConnection(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b connBody
	if !decode(w, r, &b) {
		return
	}
	cloud, ok := s.validConnection(w, &b, true)
	if !ok {
		return
	}
	c, err := s.store.CreateConnection(r.Context(), &store.Connection{Name: b.Name, Cloud: cloud, Entities: b.Entities, CreatedBy: user(r).Subject})
	if err != nil {
		s.writeStoreErr(w, err, "a connection with that name exists")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "connection.create", "connection/"+c.Name, "", c)
	writeJSON(w, 201, c)
}

// updateConnection changes identifiers or scope. Every environment using it
// gets a new config hash, so plans made against the old values go stale.
func (s *Server) updateConnection(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	cur, err := s.store.GetConnection(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	var b connBody
	if !decode(w, r, &b) {
		return
	}
	cloud, ok := s.validConnection(w, &b, false)
	if !ok {
		return
	}
	c, err := s.store.UpdateConnection(r.Context(), &store.Connection{ID: cur.ID, Cloud: cloud, Entities: b.Entities})
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "connection.update", "connection/"+c.Name, "", map[string]any{"before": cur, "after": c})
	writeJSON(w, 200, c)
}
