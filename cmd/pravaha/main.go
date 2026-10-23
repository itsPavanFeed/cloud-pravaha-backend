// Command pravaha is Cloud Pravaha in one binary: the central plane, tenant
// planes and runners.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/api"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/central"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/config"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/oidc"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/runner"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/secure"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

var version = "dev"

const usage = `pravaha — multi-tenant OpenTofu orchestration with pinned public modules only

Usage:
  pravaha central                        run the central plane (frontend, identity, tenant routing)
  pravaha central bootstrap -email E     create a platform admin and print a token (first start)
  pravaha central scim-token -name N     create a SCIM provisioning token for an identity provider
  pravaha tenant                         run a tenant plane (one client's backend, state and runs)
  pravaha runner                         run an agent that executes OpenTofu for a tenant plane
  pravaha audit verify [-central]        verify a database's audit hash chain
  pravaha catalog verify [-dir D] [-online]  validate the module catalog (and check pins on the registry)
  pravaha dev-cert -dir D -name N [-host H] [-client]  issue a development certificate from a local CA
  pravaha version

Configuration is read from PRAVAHA_* environment variables; see README.md.
`

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "central":
		if len(os.Args) > 2 && os.Args[2] == "bootstrap" {
			err = runBootstrap(ctx, os.Args[3:])
		} else if len(os.Args) > 2 && os.Args[2] == "scim-token" {
			err = runSCIMToken(ctx, os.Args[3:])
		} else {
			err = runCentral(ctx, log)
		}
	case "tenant":
		err = runTenant(ctx, log)
	case "runner":
		err = runRunner(ctx, log)
	case "audit":
		err = runAuditVerify(ctx, os.Args[2:])
	case "catalog":
		err = runCatalog(ctx, os.Args[2:])
	case "dev-cert":
		err = runDevCert(os.Args[2:])
	case "version":
		fmt.Println("pravaha", version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func sealerFrom(key string) (*secure.Sealer, error) {
	k, err := secure.ParseKey(key)
	if err != nil {
		return nil, fmt.Errorf("PRAVAHA_MASTER_KEY: %w", err)
	}
	return secure.NewSealer(k)
}

type metaStore interface {
	GetMeta(ctx context.Context, key string) ([]byte, error)
	PutMetaIfAbsent(ctx context.Context, key string, v []byte) ([]byte, error)
}

// loadIssuer reads a signing key (sealed with the master key), creating it on first start.
func loadIssuer(ctx context.Context, st metaStore, sealer *secure.Sealer, name, url string) (*oidc.Issuer, error) {
	aad := []byte(name)
	sealed, err := st.GetMeta(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		k, err := oidc.GenerateKey()
		if err != nil {
			return nil, err
		}
		s, err := sealer.Seal(k, aad)
		if err != nil {
			return nil, err
		}
		if sealed, err = st.PutMetaIfAbsent(ctx, name, s); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	k, err := sealer.Open(sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt %s; is PRAVAHA_MASTER_KEY the key this database was created with? %w", name, err)
	}
	return oidc.New(url, k)
}

func runCentral(ctx context.Context, log *slog.Logger) error {
	cfg, err := config.LoadCentral()
	if err != nil {
		return err
	}
	sealer, err := sealerFrom(cfg.MasterKey)
	if err != nil {
		return err
	}
	st, err := central.OpenStore(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	iss, err := loadIssuer(ctx, st, sealer, "assertion_signing_key", cfg.PublicURL)
	if err != nil {
		return err
	}
	srv, err := central.New(cfg, st, iss, log)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

func runTenant(ctx context.Context, log *slog.Logger) error {
	cfg, err := config.LoadServer()
	if err != nil {
		return err
	}
	sealer, err := sealerFrom(cfg.MasterKey)
	if err != nil {
		return err
	}
	cat, err := catalog.Load(cfg.CatalogDir)
	if err != nil {
		return fmt.Errorf("loading catalog from %s: %w", cfg.CatalogDir, err)
	}
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	iss, err := loadIssuer(ctx, st, sealer, "oidc_signing_key", cfg.PublicURL)
	if err != nil {
		return err
	}
	log.Info("tenant plane starting", "tenant", cfg.Tenant, "version", version, "modules", len(cat.Modules), "tofu", cfg.TofuVersion)
	srv, err := api.New(cfg, st, cat, sealer, iss, log)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

func runRunner(ctx context.Context, log *slog.Logger) error {
	cfg, err := config.LoadRunner()
	if err != nil {
		return err
	}
	r, err := runner.New(cfg, log)
	if err != nil {
		return err
	}
	return r.Run(ctx)
}

// runBootstrap creates a platform admin directly in the central database.
func runBootstrap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("central bootstrap", flag.ExitOnError)
	email := fs.String("email", "", "platform admin's email")
	ttl := fs.Int("ttl-days", 7, "token lifetime in days (max 90)")
	fs.Parse(args)
	if *email == "" || *ttl < 1 || *ttl > 90 {
		return errors.New("usage: pravaha central bootstrap -email admin@example.com [-ttl-days 7]")
	}
	db, err := databaseURL()
	if err != nil {
		return err
	}
	st, err := central.OpenStore(ctx, db)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	by := "cli:" + currentUser()
	u, err := st.EnsureUser(ctx, *email, "", true, by)
	if err != nil {
		return err
	}
	plain, err := secure.NewToken("u")
	if err != nil {
		return err
	}
	t, err := st.CreateToken(ctx, u.ID, "bootstrap", by, secure.HashToken(plain), time.Now().Add(time.Duration(*ttl)*24*time.Hour))
	if err != nil {
		return err
	}
	if err := st.AppendAudit(ctx, by, "platform_admin.bootstrap", "user/"+u.Email, "", map[string]any{"token": t.ID}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s is a platform admin. Token expires %s; it is shown once.\n", u.Email, t.ExpiresAt.Format(time.RFC3339))
	fmt.Println(plain)
	return nil
}

// runSCIMToken creates a bearer token an identity provider uses for SCIM.
func runSCIMToken(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("central scim-token", flag.ExitOnError)
	name := fs.String("name", "", "identity provider name, e.g. okta")
	fs.Parse(args)
	if *name == "" {
		return errors.New("usage: pravaha central scim-token -name okta")
	}
	db, err := databaseURL()
	if err != nil {
		return err
	}
	st, err := central.OpenStore(ctx, db)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	plain, err := secure.NewToken("s")
	if err != nil {
		return err
	}
	by := "cli:" + currentUser()
	if err := st.CreateSCIMToken(ctx, *name, by, secure.HashToken(plain)); err != nil {
		return err
	}
	if err := st.AppendAudit(ctx, by, "scim.token_create", "scim/"+*name, "", nil); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "SCIM token for %s (base URL <central>/scim/v2). It is shown once.\n", *name)
	fmt.Println(plain)
	return nil
}

func runAuditVerify(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New("usage: pravaha audit verify [-central]")
	}
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	fs.Bool("central", false, "the database is a central plane database (same check)")
	fs.Parse(args[1:])
	db, err := databaseURL()
	if err != nil {
		return err
	}
	pool, err := store.Connect(ctx, db)
	if err != nil {
		return err
	}
	defer pool.Close()
	base := store.NewBase(pool)
	n, broken, err := base.VerifyAudit(ctx)
	if err != nil {
		return err
	}
	if broken != 0 {
		return fmt.Errorf("audit chain is BROKEN at event %d (after %d intact events)", broken, n)
	}
	fmt.Printf("audit chain intact: %d events verified\n", n)
	return nil
}

func runCatalog(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New("usage: pravaha catalog verify [-dir DIR] [-online]")
	}
	fs := flag.NewFlagSet("catalog verify", flag.ExitOnError)
	dir := fs.String("dir", envOr("PRAVAHA_CATALOG_DIR", "../cloud-pravaha-modules/catalog"), "catalog directory")
	online := fs.Bool("online", false, "check every pinned version exists on registry.opentofu.org")
	fs.Parse(args[1:])
	cat, err := catalog.Load(*dir)
	if err != nil {
		return err
	}
	fmt.Printf("catalog valid: %d modules, %d providers\n", len(cat.Modules), len(cat.Providers))
	if *online {
		if err := cat.VerifyOnline(ctx); err != nil {
			return err
		}
		fmt.Println("all pinned module, dependency and provider versions exist on registry.opentofu.org")
	}
	out, _ := json.MarshalIndent(summary(cat), "", "  ")
	fmt.Println(string(out))
	return nil
}

// summary groups the catalog by cloud folder for the CLI output.
func summary(c *catalog.Catalog) map[string]map[string]any {
	out := map[string]map[string]any{}
	group := func(cloud string) map[string]any {
		if cloud == "" {
			cloud = catalog.CommonFolder
		}
		if out[cloud] == nil {
			out[cloud] = map[string]any{"providers": []string{}, "modules": []string{}}
		}
		return out[cloud]
	}
	for _, p := range c.Providers {
		g := group(p.Cloud)
		g["providers"] = append(g["providers"].([]string), p.Source+"@"+p.Version)
	}
	for _, m := range c.Modules {
		g := group(m.Cloud)
		g["modules"] = append(g["modules"].([]string), m.ID+" ("+m.Source+"@"+strings.Join(m.Versions, ",")+")")
	}
	return out
}

// runDevCert issues development certificates from a local CA kept in -dir
// (created on first use). Server certificates get -host names; -client issues
// a client-authentication certificate (central's mTLS identity).
func runDevCert(args []string) error {
	fs := flag.NewFlagSet("dev-cert", flag.ExitOnError)
	dir := fs.String("dir", ".dev-certs", "output directory (also holds the dev CA)")
	name := fs.String("name", "server", "certificate file name: <name>.pem and <name>-key.pem")
	hosts := fs.String("host", "localhost,127.0.0.1", "comma-separated DNS names and IPs (server certificates)")
	client := fs.Bool("client", false, "issue a client certificate instead of a server certificate")
	force := fs.Bool("force", false, "replace an existing certificate")
	fs.Parse(args)
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	out := filepath.Join(*dir, *name+".pem")
	if _, err := os.Stat(out); err == nil && !*force {
		fmt.Printf("%s exists; keeping it (use -force to replace)\n", out)
		return nil
	}
	ca, caKey, err := devCA(*dir)
	if err != nil {
		return err
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: *name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 6, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if *client {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		for _, h := range strings.Split(*hosts, ",") {
			h = strings.TrimSpace(h)
			if ip := net.ParseIP(h); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else if h != "" {
				tmpl.DNSNames = append(tmpl.DNSNames, h)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := writePEM(out, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(*dir, *name+"-key.pem"), "PRIVATE KEY", keyDER, 0o600); err != nil {
		return err
	}
	kind := "server"
	if *client {
		kind = "client"
	}
	fmt.Printf("wrote %s certificate %s (CA %s)\n", kind, out, filepath.Join(*dir, "ca.pem"))
	return nil
}

// devCA loads or creates the development CA. Its key is kept for issuing more
// development certificates; never use this for production.
func devCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if cb, err := os.ReadFile(certPath); err == nil {
		kb, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("%s exists without %s", certPath, keyPath)
		}
		cblk, _ := pem.Decode(cb)
		kblk, _ := pem.Decode(kb)
		if cblk == nil || kblk == nil {
			return nil, nil, errors.New("dev CA files are not PEM")
		}
		ca, err := x509.ParseCertificate(cblk.Bytes)
		if err != nil {
			return nil, nil, err
		}
		k, err := x509.ParsePKCS8PrivateKey(kblk.Bytes)
		if err != nil {
			return nil, nil, err
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("dev CA key is not ECDSA")
		}
		return ca, ek, nil
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "Cloud Pravaha development CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return nil, nil, err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, nil, err
	}
	ca, _ := x509.ParseCertificate(der)
	return ca, key, nil
}

func writePEM(path, typ string, b []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), mode)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func databaseURL() (string, error) {
	url := os.Getenv("PRAVAHA_DATABASE_URL")
	if f := os.Getenv("PRAVAHA_DATABASE_URL_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		url = strings.TrimSpace(string(b))
	}
	if url == "" {
		return "", errors.New("PRAVAHA_DATABASE_URL is required")
	}
	return url, nil
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
