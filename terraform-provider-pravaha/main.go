// terraform-provider-pravaha manages a Cloud Pravaha tenant's configuration
// as code from OpenTofu or Terraform.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/itsPavanFeed/cloud-pravaha-backend/terraform-provider-pravaha/internal/provider"
)

var version = "dev" // set with -ldflags "-X main.version=..."

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.opentofu.org/itspavanfeed/pravaha",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
