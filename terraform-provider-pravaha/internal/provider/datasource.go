package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// pravaha_catalog_module looks up an approved module, e.g. to pin stacks in a
// contracts repository to the catalog's current default version.
type catalogModuleDS struct{ c *Client }

type catalogModuleModel struct {
	ID            types.String `tfsdk:"id"`
	Title         types.String `tfsdk:"title"`
	Cloud         types.String `tfsdk:"cloud"`
	Source        types.String `tfsdk:"source"`
	Versions      types.List   `tfsdk:"versions"`
	LatestVersion types.String `tfsdk:"latest_version"`
	Outputs       types.List   `tfsdk:"outputs"`
}

func NewCatalogModule() datasource.DataSource { return &catalogModuleDS{} }

func (d *catalogModuleDS) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_catalog_module"
}

func (d *catalogModuleDS) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An approved module from the tenant's catalog.",
		Attributes: map[string]schema.Attribute{
			"id":             schema.StringAttribute{Required: true, Description: "Catalog module ID, e.g. aws-eks."},
			"title":          schema.StringAttribute{Computed: true},
			"cloud":          schema.StringAttribute{Computed: true},
			"source":         schema.StringAttribute{Computed: true},
			"versions":       schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"latest_version": schema.StringAttribute{Computed: true},
			"outputs":        schema.ListAttribute{Computed: true, ElementType: types.StringType},
		},
	}
}

func (d *catalogModuleDS) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if c, ok := req.ProviderData.(*Client); ok {
		d.c = c
	} else if req.ProviderData != nil {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("%T", req.ProviderData))
	}
}

func (d *catalogModuleDS) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m catalogModuleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var cat struct {
		Modules []CatalogModule `json:"modules"`
	}
	if err := d.c.do(ctx, http.MethodGet, d.c.inTenant("/catalog"), nil, &cat); err != nil {
		apiErr(&resp.Diagnostics, "reading catalog", err)
		return
	}
	for _, mod := range cat.Modules {
		if mod.ID != m.ID.ValueString() {
			continue
		}
		m.Title, m.Cloud, m.Source = types.StringValue(mod.Title), types.StringValue(mod.Cloud), types.StringValue(mod.Source)
		m.Versions, m.Outputs = list(ctx, mod.Versions, &resp.Diagnostics), list(ctx, mod.Outputs, &resp.Diagnostics)
		if len(mod.Versions) > 0 {
			m.LatestVersion = types.StringValue(mod.Versions[len(mod.Versions)-1])
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
		return
	}
	resp.Diagnostics.AddError("Unknown catalog module", fmt.Sprintf("%q is not in the approved catalog", m.ID.ValueString()))
}
