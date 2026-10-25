package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/release"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/spec"
)

// platform is what stacks are validated and generated against: the catalog of
// kinds, this tenant's defaults and, once one is deployed, the module release
// whose vendored modules runs use. It is swapped atomically when a release is
// deployed, so every request sees one consistent version.
type platform struct {
	cat      *catalog.Catalog
	defaults *catalog.Overlay
	release  *releaseInfo // nil: the catalog bundled with the binary (PRAVAHA_CATALOG_DIR)
}

// releaseInfo identifies the deployed module release and its vendored modules.
type releaseInfo struct {
	ID       string
	Number   int
	SHA256   string // of the bundle runs download
	manifest *release.Manifest
}

func (r *releaseInfo) Resolve(source, version string) (string, map[string]string, bool) {
	d, ok := r.manifest.Modules[source+"@"+version]
	if !ok {
		return "", nil, false
	}
	return d, r.manifest.Closure(d), true
}

func (s *Server) plat() *platform { return s.platSnap.Load() }

// bundledPlatform loads the catalog shipped with the binary plus this
// tenant's defaults from the modules checkout next to it
// (<catalog>/../tenants/<tenant>/defaults). It is used until a module release
// is deployed.
func bundledPlatform(cat *catalog.Catalog, catalogDir, tenant string) (*platform, error) {
	root := filepath.Dir(filepath.Clean(catalogDir))
	ov := &catalog.Overlay{Tenant: tenant, Kinds: map[string]*catalog.Defaults{}}
	if _, err := os.Stat(filepath.Join(root, "tenants", tenant)); err == nil {
		var err error
		if ov, err = catalog.LoadOverlay(os.DirFS(root), "tenants/"+tenant, tenant, cat); err != nil {
			return nil, fmt.Errorf("tenant defaults: %w", err)
		}
		if err := spec.ValidateOverlay(cat, ov); err != nil {
			return nil, fmt.Errorf("tenant defaults: %w", err)
		}
	}
	return &platform{cat: cat, defaults: ov}, nil
}

// generateInput fills in what every generation needs from the platform and
// the tenant's settings.
func (s *Server) generateInput(ctx context.Context, p *platform, in spec.GenerateInput) spec.GenerateInput {
	in.TofuVersion, in.Tenant, in.Defaults = s.cfg.TofuVersion, s.cfg.Tenant, p.defaults
	in.Vault = s.secretStore(ctx)
	if p.release != nil {
		in.Modules = p.release
	}
	return in
}
