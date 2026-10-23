package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/oidc"
)

func setup(t *testing.T) (*oidc.Issuer, *AssertionVerifier) {
	k, _ := oidc.GenerateKey()
	iss, err := oidc.New("https://central.example.com", k)
	if err != nil {
		t.Fatal(err)
	}
	v, err := oidc.NewVerifier("https://central.example.com", iss.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	return iss, NewAssertionVerifier("acme", v)
}

func TestAssertion(t *testing.T) {
	iss, av := setup(t)
	now := time.Now()
	p := &Principal{Subject: "alice@acme", Tenant: "acme", TenantRoles: []string{"finops", "bogus"},
		EntityRoles: map[string][]string{"payments": {"developer", "root"}, "Bad Slug": {"admin"}}}
	tok, _ := SignAssertion(iss, p, "GET", "/api/v1/stacks", now)

	got, err := av.Verify(tok, "GET", "/api/v1/stacks", now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "alice@acme" || !got.HasTenantRole("finops") || got.HasTenantRole("bogus") ||
		!got.HasEntityRole("payments", "developer") || got.HasEntityRole("payments", "root") || len(got.EntityRoles["Bad Slug"]) > 0 {
		t.Fatalf("unexpected principal: %+v", got)
	}
	if _, err := av.Verify(tok, "GET", "/api/v1/stacks", now); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replay must be rejected, got %v", err)
	}

	tok2, _ := SignAssertion(iss, p, "GET", "/api/v1/stacks", now)
	if _, err := av.Verify(tok2, "POST", "/api/v1/runs/x/approve", now); err == nil {
		t.Fatal("an assertion must not authorise a different request")
	}
	tok3, _ := SignAssertion(iss, p, "GET", "/api/v1/stacks", now)
	if _, err := av.Verify(tok3, "GET", "/api/v1/stacks", now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired assertion accepted")
	}
	other := &Principal{Subject: "x", Tenant: "globex"}
	tok4, _ := SignAssertion(iss, other, "GET", "/api/v1/stacks", now)
	if _, err := av.Verify(tok4, "GET", "/api/v1/stacks", now); err == nil {
		t.Fatal("assertion for another tenant accepted")
	}
	forger, _ := setup(t)
	tok5, _ := SignAssertion(forger, p, "GET", "/api/v1/stacks", now)
	if _, err := av.Verify(tok5, "GET", "/api/v1/stacks", now); err == nil {
		t.Fatal("assertion signed by another key accepted")
	}
}

func TestPermissions(t *testing.T) {
	dev := &Principal{EntityRoles: map[string][]string{"payments": {"developer"}}}
	mgr := &Principal{EntityRoles: map[string][]string{"payments": {"manager"}}}
	fin := &Principal{TenantRoles: []string{"finops"}}
	if !dev.CanChange("payments") || dev.CanChange("data") || dev.CanView("data") {
		t.Error("developer must be confined to their entity")
	}
	if mgr.CanChange("payments") || !mgr.CanApprove("manager", "payments") || mgr.CanApprove("manager", "data") || mgr.CanApprove("finops", "payments") {
		t.Error("manager approves only their entity's manager step")
	}
	if !fin.CanView("anything") || fin.CanChange("payments") || !fin.CanApprove("finops", "data") || fin.CanApprove("security", "data") {
		t.Error("finops sees all entities and approves only the finops step")
	}
	if dev.VisibleEntities()[0] != "payments" || fin.VisibleEntities() != nil {
		t.Error("visible entities")
	}
}

func TestPlatformAdmin(t *testing.T) {
	iss, av := setup(t)
	now := time.Now()
	tok, _ := SignAssertion(iss, &Principal{Subject: "root@platform", Tenant: "acme", PlatformAdmin: true}, "GET", "/api/v1/stacks", now)
	p, err := av.Verify(tok, "GET", "/api/v1/stacks", now)
	if err != nil {
		t.Fatal(err)
	}
	if !p.PlatformAdmin || !p.HasTenantRole(TenantAdmin) || !p.HasTenantRole(Auditor) || !p.SeesAllEntities() ||
		!p.CanChange("any") || !p.CanManageEnvironments("any") || p.Actor() != "platform-admin:root@platform" {
		t.Fatalf("platform admin must hold tenant admin powers and more everywhere: %+v", p)
	}
	for _, step := range Steps {
		if p.CanApprove(step, "any") {
			t.Errorf("platform admin must not sign %s without an explicit role", step)
		}
	}
	p.TenantRoles = []string{FinOps}
	if !p.CanApprove(StepFinOps, "any") {
		t.Error("an explicit finops membership lets a platform admin sign finops")
	}
}
