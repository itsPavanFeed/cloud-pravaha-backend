package central

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/httpx"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/secure"
)

// SCIM 2.0 (RFC 7643/7644) for identity providers: Users are provisioned and
// deactivated (deactivation revokes every token), and Groups named
//
//	pravaha:<tenant>:<tenant-role>
//	pravaha:<tenant>:entity:<slug>:<role>
//	pravaha:<tenant>:bu:<slug>:<role>
//
// grant that role to their members. Memberships created this way are tagged
// with the group, so removing someone from the group removes only that grant.

const (
	scimUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimError = "urn:ietf:params:scim:api:messages:2.0:Error"
)

var groupRe = regexp.MustCompile(`^pravaha:([a-z][a-z0-9-]{1,31}):(?:(entity|bu):([a-z][a-z0-9-]{1,31}):)?([a-z_]{3,20})$`)

func scimErr(w http.ResponseWriter, code int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"schemas": []string{scimError}, "status": http.StatusText(code), "detail": detail})
}

func scimJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) scimAuth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := httpx.ClientIP(r)
		if s.limiter.Blocked(ip) {
			scimErr(w, http.StatusTooManyRequests, "too many failed attempts")
			return
		}
		tok := httpx.Bearer(r)
		if !strings.HasPrefix(tok, "pvh_s_") || !s.store.SCIMTokenValid(r.Context(), secure.HashToken(tok)) {
			s.limiter.Fail(ip)
			scimErr(w, http.StatusUnauthorized, "invalid SCIM token")
			return
		}
		h(w, r)
	})
}

func readSCIM(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil || json.Unmarshal(b, v) != nil {
		scimErr(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}

func userResource(u *User) map[string]any {
	return map[string]any{
		"schemas": []string{scimUser}, "id": u.ID, "userName": u.Email, "displayName": u.Name,
		"name": map[string]string{"formatted": u.Name}, "active": u.DisabledAt == nil,
		"emails": []map[string]any{{"value": u.Email, "primary": true}},
		"meta":   map[string]any{"resourceType": "User", "created": u.CreatedAt.Format(time.RFC3339)},
	}
}

// filterValue extracts V from `attr eq "V"`, the only filter IdPs need here.
func filterValue(filter, attr string) (string, bool) {
	f := strings.TrimSpace(filter)
	prefix := attr + " eq "
	if !strings.HasPrefix(strings.ToLower(f), strings.ToLower(prefix)) {
		return "", false
	}
	v := strings.TrimSpace(f[len(prefix):])
	return strings.Trim(v, `"`), true
}

func (s *Server) scimConfig(w http.ResponseWriter, r *http.Request) {
	scimJSON(w, 200, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":   map[string]bool{"supported": true}, "bulk": map[string]bool{"supported": false},
		"filter": map[string]any{"supported": true, "maxResults": 100}, "changePassword": map[string]bool{"supported": false},
		"sort": map[string]bool{"supported": false}, "etag": map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]string{{"type": "oauthbearertoken", "name": "Bearer token"}},
	})
}

func (s *Server) scimListUsers(w http.ResponseWriter, r *http.Request) {
	var users []*User
	if v, ok := filterValue(r.URL.Query().Get("filter"), "userName"); ok {
		if u, err := s.store.UserByEmail(r.Context(), strings.ToLower(v)); err == nil {
			users = append(users, u)
		}
	} else {
		var err error
		if users, err = s.store.ListUsers(r.Context(), 200); err != nil {
			scimErr(w, 500, "internal error")
			return
		}
	}
	res := []map[string]any{}
	for _, u := range users {
		res = append(res, userResource(u))
	}
	scimJSON(w, 200, map[string]any{"schemas": []string{scimList}, "totalResults": len(res), "startIndex": 1, "itemsPerPage": len(res), "Resources": res})
}

type scimUserBody struct {
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	Name        struct {
		Formatted, GivenName, FamilyName string
	} `json:"name"`
	Active *bool `json:"active"`
}

func (b *scimUserBody) displayName() string {
	if b.DisplayName != "" {
		return b.DisplayName
	}
	if b.Name.Formatted != "" {
		return b.Name.Formatted
	}
	return strings.TrimSpace(b.Name.GivenName + " " + b.Name.FamilyName)
}

func (s *Server) scimCreateUser(w http.ResponseWriter, r *http.Request) {
	var b scimUserBody
	if !readSCIM(w, r, &b) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(b.UserName))
	if !emailRe.MatchString(email) {
		scimErr(w, 400, "userName must be an email address")
		return
	}
	if _, err := s.store.UserByEmail(r.Context(), email); err == nil {
		scimErr(w, http.StatusConflict, "user exists")
		return
	}
	u, err := s.store.EnsureUser(r.Context(), email, trim(b.displayName(), 80), false, "scim")
	if err != nil {
		scimErr(w, 500, "internal error")
		return
	}
	if b.Active != nil && !*b.Active {
		s.store.SetUserActive(r.Context(), u.ID, false)
		u, _ = s.store.UserByEmail(r.Context(), email)
	}
	s.audit(r.Context(), "scim", "scim.user_create", "user/"+email, "", nil)
	scimJSON(w, 201, userResource(u))
}

func (s *Server) scimGetUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.UserByID(r.Context(), r.PathValue("id"))
	if err != nil {
		scimErr(w, 404, "no such user")
		return
	}
	scimJSON(w, 200, userResource(u))
}

// scimUpdateUser handles PUT and PATCH. The useful change is "active": false,
// which disables the user and revokes every token they hold.
func (s *Server) scimUpdateUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.UserByID(r.Context(), r.PathValue("id"))
	if err != nil {
		scimErr(w, 404, "no such user")
		return
	}
	var active *bool
	var name string
	if r.Method == http.MethodPatch {
		var p struct {
			Operations []struct {
				Op    string          `json:"op"`
				Path  string          `json:"path"`
				Value json.RawMessage `json:"value"`
			} `json:"Operations"`
		}
		if !readSCIM(w, r, &p) {
			return
		}
		for _, op := range p.Operations {
			switch strings.ToLower(op.Path) {
			case "active":
				var v bool
				if json.Unmarshal(op.Value, &v) == nil {
					active = &v
				} else {
					var sv string // some IdPs send "False"
					if json.Unmarshal(op.Value, &sv) == nil {
						v = strings.EqualFold(sv, "true")
						active = &v
					}
				}
			case "displayname", "name.formatted":
				json.Unmarshal(op.Value, &name)
			case "":
				var m map[string]json.RawMessage
				if json.Unmarshal(op.Value, &m) == nil {
					if a, ok := m["active"]; ok {
						var v bool
						if json.Unmarshal(a, &v) == nil {
							active = &v
						}
					}
				}
			}
		}
	} else {
		var b scimUserBody
		if !readSCIM(w, r, &b) {
			return
		}
		active, name = b.Active, b.displayName()
	}
	if name != "" {
		s.store.SetUserName(r.Context(), u.ID, trim(name, 80))
	}
	if active != nil && *active != (u.DisabledAt == nil) {
		if err := s.store.SetUserActive(r.Context(), u.ID, *active); err != nil {
			scimErr(w, 500, "internal error")
			return
		}
		s.audit(r.Context(), "scim", map[bool]string{true: "scim.user_activate", false: "scim.user_deactivate"}[*active], "user/"+u.Email, "", nil)
	}
	u, _ = s.store.UserByID(r.Context(), u.ID)
	scimJSON(w, 200, userResource(u))
}

func (s *Server) scimDeleteUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.UserByID(r.Context(), r.PathValue("id"))
	if err != nil {
		scimErr(w, 404, "no such user")
		return
	}
	// Users are deactivated, not deleted, so the audit trail keeps its subject.
	s.store.SetUserActive(r.Context(), u.ID, false)
	s.audit(r.Context(), "scim", "scim.user_deactivate", "user/"+u.Email, "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- groups ----

type grant struct{ tenant, kind, scope, role string }

func parseGroup(name string) (grant, error) {
	m := groupRe.FindStringSubmatch(name)
	if m == nil {
		return grant{}, errors.New(`group names must be pravaha:<tenant>:<role>, pravaha:<tenant>:entity:<slug>:<role> or pravaha:<tenant>:bu:<slug>:<role>`)
	}
	g := grant{tenant: m[1], kind: m[2], scope: m[3], role: m[4]}
	if g.kind == "" && !identity.IsTenantRole(g.role) || g.kind != "" && !identity.IsScopedRole(g.role) {
		return grant{}, errors.New("unknown role " + g.role + " for that scope")
	}
	return g, nil
}

func (s *Server) groupResource(ctx context.Context, g *SCIMGroup) map[string]any {
	members := []map[string]string{}
	for _, m := range s.store.SCIMGroupMembers(ctx, g.ID) {
		members = append(members, map[string]string{"value": m.ID, "display": m.Email})
	}
	return map[string]any{"schemas": []string{scimGroup}, "id": g.ID, "displayName": g.DisplayName, "members": members,
		"meta": map[string]any{"resourceType": "Group"}}
}

func (s *Server) scimListGroups(w http.ResponseWriter, r *http.Request) {
	var gs []*SCIMGroup
	if v, ok := filterValue(r.URL.Query().Get("filter"), "displayName"); ok {
		if g, err := s.store.SCIMGroupByName(r.Context(), v); err == nil {
			gs = append(gs, g)
		}
	} else {
		gs = s.store.SCIMGroups(r.Context())
	}
	res := []map[string]any{}
	for _, g := range gs {
		res = append(res, s.groupResource(r.Context(), g))
	}
	scimJSON(w, 200, map[string]any{"schemas": []string{scimList}, "totalResults": len(res), "startIndex": 1, "itemsPerPage": len(res), "Resources": res})
}

type memberRef struct {
	Value string `json:"value"`
}

func (s *Server) scimCreateGroup(w http.ResponseWriter, r *http.Request) {
	var b struct {
		DisplayName string      `json:"displayName"`
		ExternalID  string      `json:"externalId"`
		Members     []memberRef `json:"members"`
	}
	if !readSCIM(w, r, &b) {
		return
	}
	gr, err := parseGroup(b.DisplayName)
	if err != nil {
		scimErr(w, 400, err.Error())
		return
	}
	if _, err := s.store.Tenant(r.Context(), gr.tenant); err != nil {
		scimErr(w, 400, "unknown tenant "+gr.tenant)
		return
	}
	g, err := s.store.CreateSCIMGroup(r.Context(), b.DisplayName, trim(b.ExternalID, 200))
	if err != nil {
		scimErr(w, http.StatusConflict, "group exists")
		return
	}
	for _, m := range b.Members {
		s.grantGroup(r.Context(), g, gr, m.Value, true)
	}
	s.audit(r.Context(), "scim", "scim.group_create", "group/"+g.DisplayName, gr.tenant, nil)
	scimJSON(w, 201, s.groupResource(r.Context(), g))
}

func (s *Server) scimGetGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.store.SCIMGroupByID(r.Context(), r.PathValue("id"))
	if err != nil {
		scimErr(w, 404, "no such group")
		return
	}
	scimJSON(w, 200, s.groupResource(r.Context(), g))
}

// scimPatchGroup adds or removes members (the operations IdPs send).
func (s *Server) scimPatchGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.store.SCIMGroupByID(r.Context(), r.PathValue("id"))
	if err != nil {
		scimErr(w, 404, "no such group")
		return
	}
	gr, err := parseGroup(g.DisplayName)
	if err != nil {
		scimErr(w, 400, err.Error())
		return
	}
	var p struct {
		Operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		} `json:"Operations"`
	}
	if !readSCIM(w, r, &p) {
		return
	}
	for _, op := range p.Operations {
		add := strings.EqualFold(op.Op, "add")
		var refs []memberRef
		json.Unmarshal(op.Value, &refs)
		// Removes are often expressed as path=members[value eq "id"].
		if m := regexp.MustCompile(`members\[value eq "([^"]+)"\]`).FindStringSubmatch(op.Path); m != nil {
			refs = append(refs, memberRef{Value: m[1]})
		}
		if !add && !strings.EqualFold(op.Op, "remove") {
			continue
		}
		for _, ref := range refs {
			s.grantGroup(r.Context(), g, gr, ref.Value, add)
		}
	}
	scimJSON(w, 200, s.groupResource(r.Context(), g))
}

func (s *Server) scimDeleteGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.store.SCIMGroupByID(r.Context(), r.PathValue("id"))
	if err != nil {
		scimErr(w, 404, "no such group")
		return
	}
	if gr, err := parseGroup(g.DisplayName); err == nil {
		for _, m := range s.store.SCIMGroupMembers(r.Context(), g.ID) {
			s.grantGroup(r.Context(), g, gr, m.ID, false)
		}
	}
	s.store.DeleteSCIMGroup(r.Context(), g.ID)
	s.audit(r.Context(), "scim", "scim.group_delete", "group/"+g.DisplayName, "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// grantGroup adds or removes the group's role for one user.
func (s *Server) grantGroup(ctx context.Context, g *SCIMGroup, gr grant, userID string, add bool) {
	u, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return
	}
	t, err := s.store.Tenant(ctx, gr.tenant)
	if err != nil {
		return
	}
	var entityID, buID *string
	switch gr.kind {
	case "entity":
		e, err := s.store.Entity(ctx, t.ID, gr.scope)
		if err != nil {
			return
		}
		entityID = &e.ID
	case "bu":
		b, err := s.store.BUBySlug(ctx, t.ID, gr.scope)
		if err != nil {
			return
		}
		buID = &b.ID
	}
	by := "scim:" + g.ID
	if add {
		if _, err := s.store.AddMembership(ctx, u.ID, t.ID, entityID, buID, gr.role, by); err == nil {
			s.audit(ctx, "scim", "member.add", "user/"+u.Email, t.Slug, map[string]string{"group": g.DisplayName, "role": gr.role})
		}
		return
	}
	if s.store.RemoveMembershipBy(ctx, u.ID, t.ID, entityID, buID, gr.role, by) {
		s.audit(ctx, "scim", "member.remove", "user/"+u.Email, t.Slug, map[string]string{"group": g.DisplayName, "role": gr.role})
	}
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
