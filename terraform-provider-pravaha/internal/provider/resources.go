package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---- shared plumbing ----

type base struct{ c *Client }

func (b *base) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("%T", req.ProviderData))
		return
	}
	b.c = c
}

func idAttr() schema.StringAttribute {
	return schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}}
}

func replace() []planmodifier.String {
	return []planmodifier.String{stringplanmodifier.RequiresReplace()}
}

func apiErr(d *diag.Diagnostics, what string, err error) {
	d.AddError("Cloud Pravaha: "+what, err.Error())
}

func stringList(ctx context.Context, l types.List, d *diag.Diagnostics) []string {
	out := []string{}
	if !l.IsNull() && !l.IsUnknown() {
		d.Append(l.ElementsAs(ctx, &out, false)...)
	}
	return out
}

func list(ctx context.Context, v []string, d *diag.Diagnostics) types.List {
	if v == nil {
		v = []string{}
	}
	l, diags := types.ListValueFrom(ctx, types.StringType, v)
	d.Append(diags...)
	return l
}

func optString(v string) types.String {
	if v == "" {
		return types.StringNull()
	}
	return types.StringValue(v)
}

// ---- pravaha_entity ----

type entityRes struct{ base }

type entityModel struct {
	ID   types.String `tfsdk:"id"`
	Slug types.String `tfsdk:"slug"`
	Name types.String `tfsdk:"name"`
}

func NewEntity() resource.Resource { return &entityRes{} }

func (r *entityRes) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_entity"
}

func (r *entityRes) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An entity (a company or product line) in the tenant. Entities hold business units. They are never deleted by the provider: destroying one is refused, so remove it from state with `tofu state rm` if you stop managing it.",
		Attributes: map[string]schema.Attribute{
			"id":   idAttr(),
			"slug": schema.StringAttribute{Required: true, PlanModifiers: replace(), Description: "Lowercase slug, unique in the tenant."},
			"name": schema.StringAttribute{Required: true, PlanModifiers: replace(), Description: "Display name."},
		},
	}
}

func (r *entityRes) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m entityModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var e Entity
	if err := r.c.do(ctx, http.MethodPost, r.c.central("/entities"), map[string]string{"slug": m.Slug.ValueString(), "name": m.Name.ValueString()}, &e); err != nil {
		apiErr(&resp.Diagnostics, "creating entity", err)
		return
	}
	m.ID = types.StringValue(e.ID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *entityRes) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m entityModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	e, err := findBy(ctx, r.c, r.c.central("/entities"), func(e Entity) bool { return e.Slug == m.Slug.ValueString() || e.ID == m.ID.ValueString() })
	if IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiErr(&resp.Diagnostics, "reading entity", err)
		return
	}
	m.ID, m.Slug, m.Name = types.StringValue(e.ID), types.StringValue(e.Slug), types.StringValue(e.Name)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *entityRes) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {}

func (r *entityRes) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddError("Entities are not deleted",
		"Cloud Pravaha keeps entities so the history of their stacks and audit events stays attributable. Remove the resource from state with `tofu state rm` to stop managing it.")
}

func (r *entityRes) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("slug"), req, resp)
}

// ---- pravaha_business_unit ----

type buRes struct{ base }

type buModel struct {
	ID     types.String `tfsdk:"id"`
	Slug   types.String `tfsdk:"slug"`
	Name   types.String `tfsdk:"name"`
	Entity types.String `tfsdk:"entity"`
}

func NewBusinessUnit() resource.Resource { return &buRes{} }

func (r *buRes) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_business_unit"
}

func (r *buRes) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A business unit (team or product) under an entity. Stacks and environments belong to business units. Like entities, they are never deleted by the provider.",
		Attributes: map[string]schema.Attribute{
			"id":     idAttr(),
			"slug":   schema.StringAttribute{Required: true, PlanModifiers: replace(), Description: "Lowercase slug, unique in the tenant."},
			"name":   schema.StringAttribute{Required: true, PlanModifiers: replace()},
			"entity": schema.StringAttribute{Required: true, PlanModifiers: replace(), Description: "Slug of the parent entity."},
		},
	}
}

func (r *buRes) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m buModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var b BU
	if err := r.c.do(ctx, http.MethodPost, r.c.central("/bus"), map[string]string{"slug": m.Slug.ValueString(), "name": m.Name.ValueString(), "entity": m.Entity.ValueString()}, &b); err != nil {
		apiErr(&resp.Diagnostics, "creating business unit", err)
		return
	}
	m.ID = types.StringValue(b.ID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *buRes) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m buModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	b, err := findBy(ctx, r.c, r.c.central("/bus"), func(b BU) bool { return b.Slug == m.Slug.ValueString() || b.ID == m.ID.ValueString() })
	if IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiErr(&resp.Diagnostics, "reading business unit", err)
		return
	}
	m.ID, m.Slug, m.Name, m.Entity = types.StringValue(b.ID), types.StringValue(b.Slug), types.StringValue(b.Name), types.StringValue(b.Entity)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *buRes) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {}

func (r *buRes) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddError("Business units are not deleted",
		"Cloud Pravaha keeps business units so their stacks, runs and audit events stay attributable. Remove the resource from state with `tofu state rm` to stop managing it.")
}

func (r *buRes) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("slug"), req, resp)
}

// ---- pravaha_member ----

type memberRes struct{ base }

type memberModel struct {
	ID     types.String `tfsdk:"id"`
	Email  types.String `tfsdk:"email"`
	Role   types.String `tfsdk:"role"`
	Entity types.String `tfsdk:"entity"`
	BU     types.String `tfsdk:"bu"`
}

func NewMember() resource.Resource { return &memberRes{} }

func (r *memberRes) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_member"
}

func (r *memberRes) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A role grant. Tenant-wide roles (tenant_admin, finops, security, auditor) take neither entity nor bu. Scoped roles (admin, manager, developer, viewer) take an entity, which its business units inherit, or a bu.",
		Attributes: map[string]schema.Attribute{
			"id":     idAttr(),
			"email":  schema.StringAttribute{Required: true, PlanModifiers: replace()},
			"role":   schema.StringAttribute{Required: true, PlanModifiers: replace()},
			"entity": schema.StringAttribute{Optional: true, PlanModifiers: replace(), Description: "Entity slug for an entity-scoped role."},
			"bu":     schema.StringAttribute{Optional: true, PlanModifiers: replace(), Description: "Business unit slug for a BU-scoped role."},
		},
	}
}

func (r *memberRes) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m memberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out Member
	body := map[string]string{"email": m.Email.ValueString(), "role": m.Role.ValueString(), "entity": m.Entity.ValueString(), "bu": m.BU.ValueString()}
	if err := r.c.do(ctx, http.MethodPost, r.c.central("/members"), body, &out); err != nil {
		apiErr(&resp.Diagnostics, "granting role", err)
		return
	}
	m.ID = types.StringValue(out.ID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *memberRes) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m memberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	g, err := findBy(ctx, r.c, r.c.central("/members"), func(g Member) bool { return g.ID == m.ID.ValueString() })
	if IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiErr(&resp.Diagnostics, "reading role grant", err)
		return
	}
	m.Email, m.Role, m.Entity, m.BU = types.StringValue(g.Email), types.StringValue(g.Role), optString(g.Entity), optString(g.BU)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *memberRes) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {}

func (r *memberRes) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m memberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if err := r.c.do(ctx, http.MethodDelete, r.c.central("/members/"+url.PathEscape(m.ID.ValueString())), nil, nil); err != nil && !IsNotFound(err) {
		apiErr(&resp.Diagnostics, "revoking role", err)
	}
}

func (r *memberRes) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ---- pravaha_cloud_connection ----

type connRes struct{ base }

type connModel struct {
	ID       types.String         `tfsdk:"id"`
	Name     types.String         `tfsdk:"name"`
	Cloud    jsontypes.Normalized `tfsdk:"cloud"`
	Entities types.List           `tfsdk:"entities"`
}

func NewConnection() resource.Resource { return &connRes{} }

func (r *connRes) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloud_connection"
}

func (r *connRes) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A tenant-level cloud integration (AWS account, GCP project or Azure subscription) through keyless federation, scoped to entities. It holds identifiers only, never secrets.",
		Attributes: map[string]schema.Attribute{
			"id":   idAttr(),
			"name": schema.StringAttribute{Required: true, PlanModifiers: replace()},
			"cloud": schema.StringAttribute{Required: true, CustomType: jsontypes.NormalizedType{},
				Description: "The cloud integration as JSON (use jsonencode), e.g. {provider = \"aws\", auth = \"oidc\", aws = {region = \"eu-west-1\", role_arn = \"...\", plan_role_arn = \"...\"}}. Leave out empty fields."},
			"entities": schema.ListAttribute{ElementType: types.StringType, Optional: true, Computed: true,
				Default:     listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
				Description: "Entity slugs allowed to use the connection. Empty means every entity."},
		},
	}
}

func (r *connRes) put(ctx context.Context, m *connModel, d *diag.Diagnostics, create bool) {
	body := Connection{Name: m.Name.ValueString(), Cloud: json.RawMessage(m.Cloud.ValueString()), Entities: stringList(ctx, m.Entities, d)}
	var out Connection
	var err error
	if create {
		err = r.c.do(ctx, http.MethodPost, r.c.inTenant("/connections"), body, &out)
	} else {
		err = r.c.do(ctx, http.MethodPut, r.c.inTenant("/connections/"+url.PathEscape(m.ID.ValueString())), body, &out)
	}
	if err != nil {
		apiErr(d, "saving cloud connection", err)
		return
	}
	m.ID = types.StringValue(out.ID)
}

func (r *connRes) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m connModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, &m, &resp.Diagnostics, true); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	}
}

func (r *connRes) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m connModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, &m, &resp.Diagnostics, false); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	}
}

func (r *connRes) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m connModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	var out struct {
		Connection Connection `json:"connection"`
	}
	err := r.c.do(ctx, http.MethodGet, r.c.inTenant("/connections/"+url.PathEscape(m.ID.ValueString())), nil, &out)
	if IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiErr(&resp.Diagnostics, "reading cloud connection", err)
		return
	}
	c := out.Connection
	m.ID, m.Name, m.Cloud, m.Entities = types.StringValue(c.ID), types.StringValue(c.Name), jsontypes.NewNormalizedValue(string(c.Cloud)), list(ctx, c.Entities, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *connRes) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m connModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if err := r.c.do(ctx, http.MethodDelete, r.c.inTenant("/connections/"+url.PathEscape(m.ID.ValueString())), nil, nil); err != nil && !IsNotFound(err) {
		apiErr(&resp.Diagnostics, "deleting cloud connection", err)
	}
}

func (r *connRes) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp) // the connection name works too
}

// ---- pravaha_environment ----

type envRes struct{ base }

type envModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	BU           types.String `tfsdk:"bu"`
	Tier         types.String `tfsdk:"tier"`
	Connection   types.String `tfsdk:"cloud_connection"`
	RunnerPool   types.String `tfsdk:"runner_pool"`
	MaxDestroys  types.Int64  `tfsdk:"max_destroys"`
	AllowDestroy types.Bool   `tfsdk:"allow_destroy"`
}

func NewEnvironment() resource.Resource { return &envRes{} }

func (r *envRes) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_environment"
}

func (r *envRes) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An environment binds a business unit to a cloud connection and a tier. It can be deleted only when it has no stacks.",
		Attributes: map[string]schema.Attribute{
			"id":               idAttr(),
			"name":             schema.StringAttribute{Required: true, PlanModifiers: replace()},
			"bu":               schema.StringAttribute{Required: true, PlanModifiers: replace(), Description: "Business unit slug."},
			"tier":             schema.StringAttribute{Required: true, Description: "prod or nonprod."},
			"cloud_connection": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Cloud connection name. Empty means no cloud."},
			"runner_pool":      schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("default")},
			"max_destroys":     schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(0), Description: "Maximum resources a run may delete or replace."},
			"allow_destroy":    schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), Description: "Allow destroy runs."},
		},
	}
}

func (r *envRes) save(ctx context.Context, m *envModel, d *diag.Diagnostics, create bool) {
	md := m.MaxDestroys.ValueInt64()
	body := Environment{Name: m.Name.ValueString(), BU: m.BU.ValueString(), Tier: m.Tier.ValueString(), Connection: m.Connection.ValueString(),
		RunnerPool: m.RunnerPool.ValueString(), MaxDestroys: &md, AllowDestroy: m.AllowDestroy.ValueBool()}
	var out Environment
	var err error
	if create {
		err = r.c.do(ctx, http.MethodPost, r.c.inTenant("/environments"), body, &out)
	} else {
		err = r.c.do(ctx, http.MethodPut, r.c.inTenant("/environments/"+url.PathEscape(m.ID.ValueString())), body, &out)
	}
	if err != nil {
		apiErr(d, "saving environment", err)
		return
	}
	m.ID = types.StringValue(out.ID)
}

func (r *envRes) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m envModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.save(ctx, &m, &resp.Diagnostics, true); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	}
}

func (r *envRes) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m envModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.save(ctx, &m, &resp.Diagnostics, false); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	}
}

func (r *envRes) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m envModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	var out struct {
		Environment Environment `json:"environment"`
	}
	err := r.c.do(ctx, http.MethodGet, r.c.inTenant("/environments/"+url.PathEscape(m.ID.ValueString())), nil, &out)
	if IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiErr(&resp.Diagnostics, "reading environment", err)
		return
	}
	e := out.Environment
	m.ID, m.Name, m.BU, m.Tier = types.StringValue(e.ID), types.StringValue(e.Name), types.StringValue(e.BU), types.StringValue(e.Tier)
	m.Connection, m.RunnerPool, m.AllowDestroy = types.StringValue(e.Connection), types.StringValue(e.RunnerPool), types.BoolValue(e.AllowDestroy)
	if e.MaxDestroys != nil {
		m.MaxDestroys = types.Int64Value(*e.MaxDestroys)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *envRes) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m envModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if err := r.c.do(ctx, http.MethodDelete, r.c.inTenant("/environments/"+url.PathEscape(m.ID.ValueString())), nil, nil); err != nil && !IsNotFound(err) {
		apiErr(&resp.Diagnostics, "deleting environment", err)
	}
}

func (r *envRes) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp) // the environment name works too
}

// ---- pravaha_policy_set ----

type policyRes struct{ base }

type policyModel struct {
	ID      types.String `tfsdk:"id"`
	Name    types.String `tfsdk:"name"`
	Scope   types.String `tfsdk:"scope"`
	Level   types.String `tfsdk:"level"`
	Module  types.String `tfsdk:"module"`
	Enabled types.Bool   `tfsdk:"enabled"`
}

func NewPolicySet() resource.Resource { return &policyRes{} }

func (r *policyRes) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_set"
}

func (r *policyRes) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An OPA (Rego) policy set, evaluated on every plan in its scope. The module must declare `package pravaha.policy` and emit `deny` messages. Writing policy sets needs tenant_admin or security.",
		Attributes: map[string]schema.Attribute{
			"id":      idAttr(),
			"name":    schema.StringAttribute{Required: true, PlanModifiers: replace()},
			"scope":   schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("tenant"), Description: "tenant, entity:<slug> or bu:<slug>."},
			"level":   schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("hard"), Description: "hard blocks runs; advisory only warns approvers."},
			"module":  schema.StringAttribute{Required: true, Description: "Rego source, e.g. file(\"policies/tags.rego\")."},
			"enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
		},
	}
}

func (r *policyRes) save(ctx context.Context, m *policyModel, d *diag.Diagnostics, create bool) {
	en := m.Enabled.ValueBool()
	body := PolicySet{Name: m.Name.ValueString(), Scope: m.Scope.ValueString(), Level: m.Level.ValueString(), Module: m.Module.ValueString(), Enabled: &en}
	var out PolicySet
	var err error
	if create {
		err = r.c.do(ctx, http.MethodPost, r.c.inTenant("/policies"), body, &out)
	} else {
		err = r.c.do(ctx, http.MethodPut, r.c.inTenant("/policies/"+url.PathEscape(m.ID.ValueString())), body, &out)
	}
	if err != nil {
		apiErr(d, "saving policy set", err)
		return
	}
	m.ID = types.StringValue(out.ID)
}

func (r *policyRes) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.save(ctx, &m, &resp.Diagnostics, true); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	}
}

func (r *policyRes) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.save(ctx, &m, &resp.Diagnostics, false); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	}
}

func (r *policyRes) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	p, err := findBy(ctx, r.c, r.c.inTenant("/policies"), func(p PolicySet) bool { return p.ID == m.ID.ValueString() || p.Name == m.ID.ValueString() })
	if IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiErr(&resp.Diagnostics, "reading policy set", err)
		return
	}
	m.ID, m.Name, m.Scope, m.Level, m.Module = types.StringValue(p.ID), types.StringValue(p.Name), types.StringValue(p.Scope), types.StringValue(p.Level), types.StringValue(p.Module)
	m.Enabled = types.BoolValue(p.Enabled != nil && *p.Enabled)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *policyRes) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if err := r.c.do(ctx, http.MethodDelete, r.c.inTenant("/policies/"+url.PathEscape(m.ID.ValueString())), nil, nil); err != nil && !IsNotFound(err) {
		apiErr(&resp.Diagnostics, "deleting policy set", err)
	}
}

func (r *policyRes) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp) // the policy set name works too
}

// ---- pravaha_risk_policy ----

type riskRes struct{ base }

type riskModel struct {
	ID       types.String         `tfsdk:"id"`
	Settings jsontypes.Normalized `tfsdk:"settings"`
}

func NewRiskSettings() resource.Resource { return &riskRes{} }

func (r *riskRes) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_risk_policy"
}

func (r *riskRes) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The tenant's risk policy: approval steps per risk level, the risk of production changes and cost thresholds. There is one per tenant. Destroying this resource restores the defaults. Needs tenant_admin or security.",
		Attributes: map[string]schema.Attribute{
			"id": idAttr(),
			"settings": schema.StringAttribute{Required: true, CustomType: jsontypes.NormalizedType{},
				Description: "JSON (use jsonencode) with large_change, prod_level, cost_medium_usd, cost_high_usd and approvals {low, medium, high}."},
		},
	}
}

var defaultRisk = `{"large_change":25,"prod_level":"medium","cost_medium_usd":100,"cost_high_usd":1000,"approvals":{"low":["manager"],"medium":["manager","finops"],"high":["manager","finops","security"]}}`

func (r *riskRes) put(ctx context.Context, settings string, d *diag.Diagnostics) string {
	var out json.RawMessage
	if err := r.c.do(ctx, http.MethodPut, r.c.inTenant("/settings/risk"), json.RawMessage(settings), &out); err != nil {
		apiErr(d, "saving risk policy", err)
	}
	return string(out)
}

func (r *riskRes) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m riskModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, m.Settings.ValueString(), &resp.Diagnostics); !resp.Diagnostics.HasError() {
		m.ID = types.StringValue(r.c.tenant + "/risk")
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	}
}

func (r *riskRes) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m riskModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.put(ctx, m.Settings.ValueString(), &resp.Diagnostics); !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	}
}

func (r *riskRes) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m riskModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	var out json.RawMessage
	if err := r.c.do(ctx, http.MethodGet, r.c.inTenant("/settings/risk"), nil, &out); err != nil {
		apiErr(&resp.Diagnostics, "reading risk policy", err)
		return
	}
	m.Settings = jsontypes.NewNormalizedValue(string(out))
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *riskRes) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.put(ctx, defaultRisk, &resp.Diagnostics)
}
