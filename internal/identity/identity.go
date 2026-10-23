// Package identity defines who a caller is and what they may do, shared by the
// central plane (which authenticates users and signs assertions) and tenant
// planes (which verify assertions and enforce permissions).
//
// Roles are scoped three ways:
//
//	platform  platform_admin                         onboard tenants (central only)
//	tenant    tenant_admin, finops, security, auditor  whole tenant
//	entity    admin, manager, developer, viewer        one business unit / team
//
// A platform admin holds, in every tenant, everything a tenant admin has plus
// read access to all entities and the right to author stacks and runs in any
// of them. Approval steps are the exception: a platform admin signs manager,
// finops or security only with an explicit membership for that role, so
// separation of duties holds for everyone.
package identity

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/oidc"
)

const (
	TenantAdmin = "tenant_admin"
	FinOps      = "finops"
	Security    = "security"
	Auditor     = "auditor"

	EntityAdmin = "admin"
	Manager     = "manager"
	Developer   = "developer"
	Viewer      = "viewer"
)

var (
	TenantRoles = []string{TenantAdmin, FinOps, Security, Auditor}
	EntityRoles = []string{EntityAdmin, Manager, Developer, Viewer}
	SlugRe      = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
)

func IsTenantRole(r string) bool { return contains(TenantRoles, r) }
func IsEntityRole(r string) bool { return contains(EntityRoles, r) }

// Principal is a user acting inside one tenant.
type Principal struct {
	Subject     string              `json:"sub"`
	Tenant      string              `json:"tenant"`
	TenantRoles []string            `json:"tenant_roles"`
	EntityRoles map[string][]string `json:"entity_roles"`
	// PlatformAdmin is set by central for platform admins acting in any tenant.
	PlatformAdmin bool `json:"platform_admin,omitempty"`
}

// platformImplied are the tenant roles a platform admin holds everywhere.
var platformImplied = []string{TenantAdmin, Auditor}

func (p *Principal) HasTenantRole(roles ...string) bool {
	for _, r := range roles {
		if contains(p.TenantRoles, r) || p.PlatformAdmin && contains(platformImplied, r) {
			return true
		}
	}
	return false
}

func (p *Principal) HasEntityRole(entity string, roles ...string) bool {
	for _, r := range roles {
		if contains(p.EntityRoles[entity], r) {
			return true
		}
	}
	return false
}

// SeesAllEntities: tenant-wide roles read every business unit.
func (p *Principal) SeesAllEntities() bool {
	return p.HasTenantRole(TenantAdmin, FinOps, Security, Auditor)
}

// CanView reports whether p may read an entity's stacks, runs and environments.
func (p *Principal) CanView(entity string) bool {
	return p.SeesAllEntities() || len(p.EntityRoles[entity]) > 0
}

// VisibleEntities returns the entities p can read, or nil meaning "all".
func (p *Principal) VisibleEntities() []string {
	if p.SeesAllEntities() {
		return nil
	}
	out := []string{}
	for e, rs := range p.EntityRoles {
		if len(rs) > 0 {
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}

// CanChange: create or edit stacks and queue or discard runs.
func (p *Principal) CanChange(entity string) bool {
	return p.PlatformAdmin || p.HasEntityRole(entity, EntityAdmin, Developer)
}

// CanManageEnvironments: cloud integrations for an entity.
func (p *Principal) CanManageEnvironments(entity string) bool {
	return p.HasTenantRole(TenantAdmin) || p.HasEntityRole(entity, EntityAdmin)
}

// Actor is how audit records name the caller; platform admins are marked so
// their actions inside tenants stand out.
func (p *Principal) Actor() string {
	if p.PlatformAdmin {
		return "platform-admin:" + p.Subject
	}
	return p.Subject
}

// Approval steps and who may sign each one.
const (
	StepManager  = "manager"
	StepFinOps   = "finops"
	StepSecurity = "security"
)

var Steps = []string{StepManager, StepFinOps, StepSecurity}

func (p *Principal) CanApprove(step, entity string) bool {
	switch step {
	case StepManager:
		return p.HasEntityRole(entity, Manager)
	case StepFinOps:
		return p.HasTenantRole(FinOps)
	case StepSecurity:
		return p.HasTenantRole(Security)
	}
	return false
}

// ---- assertions: central -> tenant ----

// Audience is the aud claim for assertions meant for one tenant plane.
func Audience(tenant string) string { return "pravaha-tenant:" + tenant }

// AssertionTTL is short: an assertion authorises one proxied request.
const AssertionTTL = 60 * time.Second

// SignAssertion creates the per-request assertion the central wrapper attaches.
// It is bound to the HTTP method and path so it cannot be replayed elsewhere.
func SignAssertion(iss *oidc.Issuer, p *Principal, method, path string, now time.Time) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	er := map[string]any{}
	for e, rs := range p.EntityRoles {
		er[e] = rs
	}
	return iss.SignJWT(map[string]any{
		"aud":            Audience(p.Tenant),
		"sub":            p.Subject,
		"iat":            now.Unix(),
		"nbf":            now.Unix(),
		"exp":            now.Add(AssertionTTL).Unix(),
		"jti":            base64.RawURLEncoding.EncodeToString(jti),
		"tenant":         p.Tenant,
		"tenant_roles":   p.TenantRoles,
		"entity_roles":   er,
		"platform_admin": p.PlatformAdmin,
		"req":            method + " " + path,
	})
}

// AssertionVerifier runs on tenant planes.
type AssertionVerifier struct {
	Tenant   string
	verifier *oidc.Verifier
	mu       sync.Mutex
	seen     map[string]time.Time // jti replay cache
}

func NewAssertionVerifier(tenant string, v *oidc.Verifier) *AssertionVerifier {
	return &AssertionVerifier{Tenant: tenant, verifier: v, seen: map[string]time.Time{}}
}

// Verify checks an assertion for this tenant and this exact request, once.
func (a *AssertionVerifier) Verify(tok, method, path string, now time.Time) (*Principal, error) {
	a.mu.Lock()
	v := a.verifier
	a.mu.Unlock()
	c, err := v.Verify(tok, Audience(a.Tenant), now)
	if err != nil {
		return nil, err
	}
	if c["tenant"] != a.Tenant {
		return nil, errors.New("assertion is for another tenant")
	}
	if c["req"] != method+" "+path {
		return nil, fmt.Errorf("assertion is bound to a different request")
	}
	jti, _ := c["jti"].(string)
	if jti == "" {
		return nil, errors.New("assertion has no jti")
	}
	a.mu.Lock()
	for k, t := range a.seen {
		if now.Sub(t) > 2*AssertionTTL {
			delete(a.seen, k)
		}
	}
	if _, dup := a.seen[jti]; dup {
		a.mu.Unlock()
		return nil, errors.New("assertion replayed")
	}
	a.seen[jti] = now
	a.mu.Unlock()

	p := &Principal{Tenant: a.Tenant, EntityRoles: map[string][]string{}}
	p.PlatformAdmin, _ = c["platform_admin"].(bool)
	p.Subject, _ = c["sub"].(string)
	if p.Subject == "" {
		return nil, errors.New("assertion has no subject")
	}
	for _, r := range strs(c["tenant_roles"]) {
		if IsTenantRole(r) {
			p.TenantRoles = append(p.TenantRoles, r)
		}
	}
	if m, ok := c["entity_roles"].(map[string]any); ok {
		for e, rs := range m {
			if !SlugRe.MatchString(e) {
				continue
			}
			for _, r := range strs(rs) {
				if IsEntityRole(r) {
					p.EntityRoles[e] = append(p.EntityRoles[e], r)
				}
			}
		}
	}
	return p, nil
}

func strs(v any) []string {
	xs, _ := v.([]any)
	var out []string
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// SetVerifier swaps in refreshed central keys, keeping the replay cache.
func (a *AssertionVerifier) SetVerifier(v *oidc.Verifier) {
	a.mu.Lock()
	a.verifier = v
	a.mu.Unlock()
}
