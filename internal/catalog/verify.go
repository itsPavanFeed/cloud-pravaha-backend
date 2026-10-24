package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// VerifyOnline checks every pinned module, dependency and provider version
// against registry.opentofu.org, so a typo or a yanked release fails CI.
func (c *Catalog) VerifyOnline(ctx context.Context) error {
	hc := &http.Client{Timeout: 20 * time.Second}
	base := "https://" + Registry + "/v1"
	var errs []error
	check := func(kind, url string, want []string, extract func([]byte) ([]string, error)) {
		got, err := fetchVersions(ctx, hc, url, extract)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", kind, err))
			return
		}
		for _, v := range want {
			if !contains(got, v) {
				errs = append(errs, fmt.Errorf("%s: version %s not found on %s", kind, v, Registry))
			}
		}
	}
	for _, m := range c.Modules {
		check("module "+m.Source, base+"/modules/"+BaseSource(m.Source)+"/versions", m.Versions, moduleVersions)
		for _, d := range m.Dependencies {
			check("dependency "+d.Source, base+"/modules/"+d.Source+"/versions", d.Versions, moduleVersions)
		}
	}
	for _, p := range c.Providers {
		check("provider "+p.Source, base+"/providers/"+p.Source+"/versions", []string{p.Version}, providerVersions)
	}
	return errors.Join(errs...)
}

func fetchVersions(ctx context.Context, hc *http.Client, url string, extract func([]byte) ([]string, error)) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned %s", resp.Status)
	}
	var buf json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&buf); err != nil {
		return nil, err
	}
	return extract(buf)
}

func moduleVersions(b []byte) ([]string, error) {
	var r struct {
		Modules []struct {
			Versions []struct{ Version string } `json:"versions"`
		} `json:"modules"`
	}
	if err := json.Unmarshal(b, &r); err != nil || len(r.Modules) == 0 {
		return nil, fmt.Errorf("unexpected registry response")
	}
	var out []string
	for _, v := range r.Modules[0].Versions {
		out = append(out, v.Version)
	}
	return out, nil
}

func providerVersions(b []byte) ([]string, error) {
	var r struct {
		Versions []struct{ Version string } `json:"versions"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	var out []string
	for _, v := range r.Versions {
		out = append(out, v.Version)
	}
	return out, nil
}
