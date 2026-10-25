package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/contracts"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/spec"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

// Self-service through Git: instead of creating a stack directly, the console
// (or an assistant draft) writes the stack's contract files (one YAML file per
// resource) to a new branch of the contracts
// repository and opens a pull request. The pull request is then planned,
// approved and applied before it merges, so Git stays the source of truth.

type proposeBody struct {
	Name        string          `json:"name"`
	BU          string          `json:"bu"`
	Environment string          `json:"environment"`
	Spec        json.RawMessage `json:"spec"`
	Title       string          `json:"title,omitempty"`
}

func (s *Server) proposeStack(w http.ResponseWriter, r *http.Request) {
	var b proposeBody
	if !decode(w, r, &b) {
		return
	}
	p := user(r)
	if !spec.StackNameRe.MatchString(b.Name) {
		writeErr(w, 422, "name must start with a letter and use lowercase letters, digits and dashes (2-63)")
		return
	}
	bu, env := s.target(w, r, b.BU, b.Environment)
	if env == nil {
		return
	}
	if !p.CanChange(bu) {
		writeErr(w, http.StatusForbidden, "proposing stacks needs the developer or admin role in "+bu)
		return
	}
	gen, _, probs := s.build(r.Context(), b.Name, bu, env, b.Spec)
	if probs != nil {
		writeErr(w, 422, "stack spec rejected", probs...)
		return
	}
	ctx := r.Context()
	app, inst, cfg, err := s.prContext(ctx)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	action := "Add"
	if st, err := s.store.GetStack(ctx, b.Name); err == nil {
		switch {
		case st.ManagedBy != "git":
			writeErr(w, http.StatusConflict, "a stack with this name is managed in the console; it cannot be changed through Git")
			return
		case st.BU != bu || st.EnvironmentID != env.ID:
			writeErr(w, http.StatusConflict, "a stack cannot move to another environment or business unit; use a new name")
			return
		}
		action = "Update"
	} else if !errors.Is(err, store.ErrNotFound) {
		s.writeStoreErr(w, err, "")
		return
	}

	// One YAML file per resource; the folder is the stack.
	folder := path.Join(cfg.Path, b.Name)
	if cfg.Layout == "nested" {
		folder = path.Join(cfg.Path, env.Entity, env.Name, bu, b.Name)
	}
	files, err := contracts.Render(gen.Spec, env.Name, bu, cfg.Layout != "nested")
	if err != nil {
		writeErr(w, 422, "the stack cannot be written as contracts: "+err.Error())
		return
	}
	file := folder + "/"

	rnd := make([]byte, 3)
	rand.Read(rnd)
	branch := "pravaha/" + b.Name + "-" + hex.EncodeToString(rnd)
	msg := fmt.Sprintf("%s stack %s (requested by %s)", action, b.Name, p.Subject)
	base, err := app.BranchSHA(ctx, inst, cfg.Repo, cfg.Branch)
	if err == nil {
		err = app.CreateBranch(ctx, inst, cfg.Repo, branch, base)
	}
	var existing map[string]string
	if err == nil {
		existing, err = app.DirFiles(ctx, inst, cfg.Repo, folder, branch)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err != nil {
			break
		}
		err = app.PutFile(ctx, inst, cfg.Repo, folder+"/"+n, branch, msg, files[n], existing[n])
	}
	// Resources removed from the stack: their files go too. Other files in the
	// folder (a README, notes) are left alone.
	for n, sha := range existing {
		if err != nil {
			break
		}
		if _, keep := files[n]; !keep && (strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")) {
			err = app.DeleteFile(ctx, inst, cfg.Repo, folder+"/"+n, branch, msg, sha)
		}
	}
	if err != nil {
		writeErr(w, http.StatusBadGateway, "writing to the contracts repository failed: "+err.Error())
		return
	}
	title := b.Title
	if title == "" {
		title = fmt.Sprintf("%s stack %s (%s, %s/%s)", action, b.Name, bu, env.Entity, env.Name)
	}
	body := fmt.Sprintf("Requested in Cloud Pravaha by **%s**.\n\n- Business unit: `%s`\n- Environment: `%s/%s`\n- File: `%s`\n\n"+
		"Cloud Pravaha plans this change, collects the required approvals and applies it **before** merging; the pull request merges itself once applied.",
		p.Subject, bu, env.Entity, env.Name, file)
	pr, err := app.OpenPR(ctx, inst, cfg.Repo, branch, cfg.Branch, title, body)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "opening the pull request failed: "+err.Error())
		return
	}
	s.audit(ctx, p.Actor(), "stack.propose", "stack/"+b.Name, bu, map[string]any{"pr": pr.Number, "branch": branch, "file": file, "environment": env.Entity + "/" + env.Name})
	n := pr.Number
	s.async(func(ctx2 context.Context) error { return s.planPR(ctx2, n) }) // also started by the webhook; planning twice reuses runs
	writeJSON(w, 201, map[string]any{"pr_number": pr.Number, "html_url": pr.HTMLURL, "branch": branch, "file": file})
}
