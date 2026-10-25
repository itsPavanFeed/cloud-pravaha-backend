// Package identity defines who a caller is and what they may do, shared by the
// central plane (which authenticates users and signs assertions) and tenant
// planes (which verify assertions and enforce permissions).
//
// Hierarchy: tenant > entity (a company) > business unit (a product). Roles:
//
//	platform  platform_admin                           every tenant (see below)
//	tenant    tenant_admin, finops, security, devops,   whole tenant
//	          auditor
//	entity    admin, manager, developer, viewer         every BU of that entity
//	bu        admin, manager, developer, viewer         one business unit
//
// Entity roles are inherited by the entity's business units. Central computes
// each user's effective roles per BU and sends them in the assertion, so tenant
// planes only ever check BU roles.
//
// A platform admin holds, in every tenant, everything a tenant admin has plus
// read access to all BUs and the right to author stacks and runs in any of
// them. Approval steps are the exception: a platform admin signs manager,
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
	// DevOps approves activating module and policy releases. Platform admins
	// do not hold it implicitly: approvals always need an explicit grant.
	DevOps = "devops"

	Admin     = "admin"
	Manager   = "manager"
	Developer = "developer"
	Viewer    = "viewer"
)

var (
	TenantRoles = []string{TenantAdmin, FinOps, Security, DevOps, Auditor}
	// ScopedRoles are granted on an entity (inherited by its BUs) or on one BU.
	ScopedRoles = []string{Admin, Manager, Developer, Viewer}
	SlugRe      = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
)

func IsTenantRole(r string) bool { return contains(TenantRoles, r) }
func IsScopedRole(r string) bool { return contains(ScopedRoles, r) }

// Principal is a user acting inside one tenant.
type Principal struct {
	Subject     string              `json:"sub"`
	Tenant      string              `json:"tenant"`
	TenantRoles []string            `json:"tenant_roles"`
	EntityRoles map[string][]string `json:"entity_roles"` // as granted, for display
	BURoles     map[string][]string `json:"bu_roles"`     // effective (entity roles included)
	BUEntity    map[string]string   `json:"bu_entity"`    // every BU of the tenant -> its entity
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

// HasBURole checks effective roles in a business unit.
func (p *Principal) HasBURole(bu string, roles ...string) bool {
	for _, r := range roles {
		if contains(p.BURoles[bu], r) {
			return true
		}
	}
	return false
}

// EntityOf returns the entity a business unit belongs to ("" if unknown).
func (p *Principal) EntityOf(bu string) string { return p.BUEntity[bu] }

// KnownBU reports whether the business unit exists in this tenant.
func (p *Principal) KnownBU(bu string) bool { _, ok := p.BUEntity[bu]; return ok }

// SeesAllBUs: tenant-wide roles read every business unit.
func (p *Principal) SeesAllBUs() bool {
	return p.HasTenantRole(TenantAdmin, FinOps, Security, DevOps, Auditor)
}

// CanView reports whether p may read a BU's stacks, runs and environments.
func (p *Principal) CanView(bu string) bool {
	return p.SeesAllBUs() || len(p.BURoles[bu]) > 0
}

// VisibleBUs returns the business units p can read, or nil meaning "all".
func (p *Principal) VisibleBUs() []string {
	if p.SeesAllBUs() {
		return nil
	}
	out := []string{}
	for bu, rs := range p.BURoles {
		if len(rs) > 0 {
			out = append(out, bu)
		}
	}
	sort.Strings(out)
	return out
}

// CanChange: create or edit stacks and queue or discard runs.
func (p *Principal) CanChange(bu string) bool {
	return p.PlatformAdmin || p.HasBURole(bu, Admin, Developer)
}

// CanManageEnvironments: an entity's environments, which all of its business
// units share — tenant admins or admins of the entity.
func (p *Principal) CanManageEnvironments(entity string) bool {
	if p.HasTenantRole(TenantAdmin) {
		return true
	}
	for _, r := range p.EntityRoles[entity] {
		if r == Admin {
			return true
		}
	}
	return false
}

// VisibleEntities returns the entities p can see environments of (those of its
// visible business units), or nil meaning "all".
func (p *Principal) VisibleEntities() []string {
	bus := p.VisibleBUs()
	if bus == nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, bu := range bus {
		if e := p.BUEntity[bu]; e != "" && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	for e, rs := range p.EntityRoles {
		if len(rs) > 0 && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}

// CanViewEntity: p sees at least one business unit of the entity.
func (p *Principal) CanViewEntity(entity string) bool {
	vs := p.VisibleEntities()
	if vs == nil {
		return true
	}
	for _, e := range vs {
		if e == entity {
			return true
		}
	}
	return false
}

// WritableBUs lists the entity's business units p may create stacks in.
func (p *Principal) WritableBUs(entity string) []string {
	out := []string{}
	for bu, e := range p.BUEntity {
		if e == entity && p.CanChange(bu) {
			out = append(out, bu)
		}
	}
	sort.Strings(out)
	return out
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

func (p *Principal) CanApprove(step, bu string) bool {
	switch step {
	case StepManager:
		return p.HasBURole(bu, Manager)
	case StepFinOps:
		return contains(p.TenantRoles, FinOps)
	case StepSecurity:
		return contains(p.TenantRoles, Security)
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
	return iss.SignJWT(map[string]any{
		"aud":            Audience(p.Tenant),
		"sub":            p.Subject,
		"iat":            now.Unix(),
		"nbf":            now.Unix(),
		"exp":            now.Add(AssertionTTL).Unix(),
		"jti":            base64.RawURLEncoding.EncodeToString(jti),
		"tenant":         p.Tenant,
		"tenant_roles":   p.TenantRoles,
		"entity_roles":   p.EntityRoles,
		"bu_roles":       p.BURoles,
		"bu_entity":      p.BUEntity,
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

// SetVerifier swaps in refreshed central keys, keeping the replay cache.
func (a *AssertionVerifier) SetVerifier(v *oidc.Verifier) {
	a.mu.Lock()
	a.verifier = v
	a.mu.Unlock()
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

	p := &Principal{Tenant: a.Tenant, EntityRoles: map[string][]string{}, BURoles: map[string][]string{}, BUEntity: map[string]string{}}
	p.Subject, _ = c["sub"].(string)
	if p.Subject == "" {
		return nil, errors.New("assertion has no subject")
	}
	p.PlatformAdmin, _ = c["platform_admin"].(bool)
	for _, r := range strs(c["tenant_roles"]) {
		if IsTenantRole(r) {
			p.TenantRoles = append(p.TenantRoles, r)
		}
	}
	scoped := func(claim string, into map[string][]string) {
		m, _ := c[claim].(map[string]any)
		for k, rs := range m {
			if !SlugRe.MatchString(k) {
				continue
			}
			for _, r := range strs(rs) {
				if IsScopedRole(r) {
					into[k] = append(into[k], r)
				}
			}
		}
	}
	scoped("entity_roles", p.EntityRoles)
	scoped("bu_roles", p.BURoles)
	if m, ok := c["bu_entity"].(map[string]any); ok {
		for bu, e := range m {
			if es, ok := e.(string); ok && SlugRe.MatchString(bu) && SlugRe.MatchString(es) {
				p.BUEntity[bu] = es
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
