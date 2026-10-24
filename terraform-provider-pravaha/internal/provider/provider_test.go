package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// The framework validates schemas (reserved names, conflicting settings) only
// when a client asks for them, so ask here.
func TestSchemasAreValid(t *testing.T) {
	srv, err := providerserver.NewProtocol6WithError(New("test")())()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range resp.Diagnostics {
		t.Errorf("%s: %s", d.Summary, d.Detail)
	}
	for _, want := range []string{"pravaha_entity", "pravaha_business_unit", "pravaha_member", "pravaha_cloud_connection", "pravaha_environment", "pravaha_policy_set", "pravaha_risk_policy"} {
		if _, ok := resp.ResourceSchemas[want]; !ok {
			t.Errorf("missing resource %s", want)
		}
	}
	if _, ok := resp.DataSourceSchemas["pravaha_catalog_module"]; !ok {
		t.Error("missing data source pravaha_catalog_module")
	}
}

func TestClientRejectsPlainHTTP(t *testing.T) {
	if _, err := NewClient("http://pravaha.example.com", "t", "acme", ""); err == nil {
		t.Fatal("plain http to a remote host accepted")
	}
	if _, err := NewClient("https://pravaha.example.com", "t", "acme", ""); err != nil {
		t.Fatal(err)
	}
}
