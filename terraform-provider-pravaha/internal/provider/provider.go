// Package provider is the OpenTofu/Terraform provider for Cloud Pravaha.
//
// It manages a tenant's platform configuration as code: entities, business
// units, role grants, cloud connections, environments, OPA policy sets and the
// risk policy. Stacks themselves are managed through the tenant's contracts
// repository (Git) or the console, so every change still flows through plans,
// risk classification and approvals.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type pravahaProvider struct{ version string }

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &pravahaProvider{version: version} }
}

func (p *pravahaProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pravaha"
	resp.Version = p.version
}

func (p *pravahaProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage a Cloud Pravaha tenant's configuration: entities, business units, role grants, cloud connections, environments, policy sets and the risk policy.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{Optional: true, Description: "Central plane URL, e.g. https://pravaha.example.com. Defaults to PRAVAHA_ENDPOINT."},
			"token":    schema.StringAttribute{Optional: true, Sensitive: true, Description: "API token of a tenant admin (or platform admin). Defaults to PRAVAHA_TOKEN."},
			"tenant":   schema.StringAttribute{Optional: true, Description: "Tenant slug. Defaults to PRAVAHA_TENANT. Use provider aliases for several tenants."},
			"ca_file":  schema.StringAttribute{Optional: true, Description: "PEM file with the CA for the central plane's TLS certificate. Defaults to PRAVAHA_CA_FILE, then the system roots."},
		},
	}
}

type providerModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Token    types.String `tfsdk:"token"`
	Tenant   types.String `tfsdk:"tenant"`
	CAFile   types.String `tfsdk:"ca_file"`
}

func pick(v types.String, env string) string {
	if !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
		return v.ValueString()
	}
	return os.Getenv(env)
}

func (p *pravahaProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var m providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	endpoint, token, tenant := pick(m.Endpoint, "PRAVAHA_ENDPOINT"), pick(m.Token, "PRAVAHA_TOKEN"), pick(m.Tenant, "PRAVAHA_TENANT")
	if endpoint == "" || token == "" || tenant == "" {
		resp.Diagnostics.AddError("Missing provider configuration", "Set endpoint, token and tenant (or PRAVAHA_ENDPOINT, PRAVAHA_TOKEN and PRAVAHA_TENANT).")
		return
	}
	c, err := NewClient(endpoint, token, tenant, pick(m.CAFile, "PRAVAHA_CA_FILE"))
	if err != nil {
		resp.Diagnostics.AddError("Invalid provider configuration", err.Error())
		return
	}
	resp.ResourceData, resp.DataSourceData = c, c
}

func (p *pravahaProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewEntity, NewBusinessUnit, NewMember, NewConnection, NewEnvironment, NewPolicySet, NewRiskSettings,
	}
}

func (p *pravahaProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{NewCatalogModule}
}
