// Package orchestrator drives each run's lifecycle timers.
//
// Two engines implement Engine:
//
//   - Builtin: the tenant plane's own reaper and drift scheduler, backed by
//     PostgreSQL. No extra infrastructure.
//   - Temporal: one durable workflow per run ("run-<id>") that follows the run
//     through signals (planned, approved, finished) and owns its timers: a
//     runner that stops reporting fails the run, a plan nobody approves in time
//     is discarded, an apply that never finishes fails. Drift checks are queued
//     Runs are visible in the Temporal UI. Drift checks are only ever started
//     by people; nothing is scheduled.
//
// Either way the database stays the source of truth: workflow activities apply
// guarded, idempotent status changes, so a late signal or a duplicate timer
// can never move a run backwards.
package orchestrator

import (
	"context"
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

// Engine receives run lifecycle events from the tenant plane.
type Engine interface {
	RunCreated(ctx context.Context, runID string)
	Planned(ctx context.Context, runID string, awaitingApproval bool)
	Approved(ctx context.Context, runID string)
	Finished(ctx context.Context, runID string)
	Name() string
}

// Builtin does nothing per event: the reaper and scheduler poll the database.
type Builtin struct{}

func (Builtin) RunCreated(context.Context, string)    {}
func (Builtin) Planned(context.Context, string, bool) {}
func (Builtin) Approved(context.Context, string)      {}
func (Builtin) Finished(context.Context, string)      {}
func (Builtin) Name() string                          { return "builtin" }

// Timeouts for a run's phases.
type Timeouts struct {
	Planning time.Duration // runner silent while planning
	Approval time.Duration // plan waiting for approvals
	Applying time.Duration // apply never finishing
}

var DefaultTimeouts = Timeouts{Planning: 30 * time.Minute, Approval: 24 * time.Hour, Applying: 2 * time.Hour}

// Store is what activities need from the tenant database.
type Store interface {
	// Expire moves a run out of one of the given statuses; false if it had already moved on.
	Expire(ctx context.Context, runID string, from []string, to, reason string) (bool, error)
}

// ---- workflows ----

const (
	SignalPlanned  = "planned"
	SignalApproved = "approved"
	SignalFinished = "finished"
)

type RunInput struct {
	RunID    string
	Timeouts Timeouts
}

// RunLifecycle follows one run from queued to a terminal status.
func RunLifecycle(ctx workflow.Context, in RunInput) (string, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 10},
	})
	planned := workflow.GetSignalChannel(ctx, SignalPlanned)
	approved := workflow.GetSignalChannel(ctx, SignalApproved)
	finished := workflow.GetSignalChannel(ctx, SignalFinished)

	// wait blocks for one of the given signals or a timer; it returns the name
	// of what fired ("timeout" for the timer).
	wait := func(d time.Duration, chans map[string]workflow.ReceiveChannel) (string, bool) {
		tctx, cancel := workflow.WithCancel(ctx)
		defer cancel()
		got, payload := "timeout", false
		sel := workflow.NewSelector(ctx)
		for name, ch := range chans {
			name, ch := name, ch
			sel.AddReceive(ch, func(c workflow.ReceiveChannel, _ bool) {
				var v bool
				c.Receive(ctx, &v)
				got, payload = name, v
			})
		}
		sel.AddFuture(workflow.NewTimer(tctx, d), func(workflow.Future) {})
		sel.Select(ctx)
		return got, payload
	}
	expire := func(from []string, to, reason string) (string, error) {
		var moved bool
		err := workflow.ExecuteActivity(ctx, (*Activities).Expire, in.RunID, from, to, reason).Get(ctx, &moved)
		if err != nil {
			return "", err
		}
		return to + ": " + reason, nil
	}

	got, awaiting := wait(in.Timeouts.Planning, map[string]workflow.ReceiveChannel{SignalPlanned: planned, SignalFinished: finished})
	switch got {
	case "timeout":
		return expire([]string{"queued", "planning"}, "failed", "runner stopped reporting while planning")
	case SignalFinished:
		return "finished", nil
	}
	if !awaiting {
		return "planned without approval needed", nil
	}
	got, _ = wait(in.Timeouts.Approval, map[string]workflow.ReceiveChannel{SignalApproved: approved, SignalFinished: finished})
	switch got {
	case "timeout":
		return expire([]string{"planned"}, "discarded", "plan expired before approval")
	case SignalFinished:
		return "discarded", nil
	}
	got, _ = wait(in.Timeouts.Applying, map[string]workflow.ReceiveChannel{SignalFinished: finished})
	if got == "timeout" {
		return expire([]string{"apply_queued", "applying"}, "failed", "apply did not finish in time")
	}
	return "applied or failed", nil
}

// ---- activities ----

type Activities struct {
	Store   Store
	OnQueue func(ctx context.Context, runIDs []string) // e.g. wake runners, start workflows
}

func (a *Activities) Expire(ctx context.Context, runID string, from []string, to, reason string) (bool, error) {
	activity.GetLogger(ctx).Info("expiring run", "run", runID, "to", to, "reason", reason)
	return a.Store.Expire(ctx, runID, from, to, reason)
}

// ---- the Temporal engine ----

type Temporal struct {
	c         client.Client
	w         worker.Worker
	taskQueue string
	timeouts  Timeouts
	log       func(msg string, args ...any)
}

type TemporalConfig struct {
	Address   string
	Namespace string
	TaskQueue string
	Timeouts  Timeouts
}

// NewTemporal connects to Temporal, registers the workflows and activities,
// and starts a worker on the tenant's task queue.
func NewTemporal(cfg TemporalConfig, acts *Activities, logf func(string, ...any)) (*Temporal, error) {
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}
	// Temporal may still be starting (e.g. in Compose, the namespace can lag
	// the frontend): retry connecting and starting the worker for a while.
	var c client.Client
	var w worker.Worker
	var err error
	for deadline := time.Now().Add(90 * time.Second); ; {
		if c, err = client.Dial(client.Options{HostPort: cfg.Address, Namespace: cfg.Namespace}); err == nil {
			w = worker.New(c, cfg.TaskQueue, worker.Options{})
			w.RegisterWorkflow(RunLifecycle)
			w.RegisterActivity(acts)
			if err = w.Start(); err == nil {
				break
			}
			c.Close()
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		if logf != nil {
			logf("waiting for Temporal", "address", cfg.Address, "err", err)
		}
		time.Sleep(3 * time.Second)
	}
	t := &Temporal{c: c, w: w, taskQueue: cfg.TaskQueue, timeouts: cfg.Timeouts, log: logf}
	// Drift checks are started by people, never on a schedule. Stop the cron
	// workflow earlier versions started, so it no longer fires every minute.
	tctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c.TerminateWorkflow(tctx, "drift-sweep-"+cfg.TaskQueue, "", "drift checks are manual")
	return t, nil
}

func isAlreadyStarted(err error) bool { return temporal.IsWorkflowExecutionAlreadyStartedError(err) }

func (t *Temporal) Name() string { return "temporal" }

func (t *Temporal) Close() {
	t.w.Stop()
	t.c.Close()
}

func workflowID(runID string) string { return "run-" + runID }

func (t *Temporal) RunCreated(ctx context.Context, runID string) {
	_, err := t.c.ExecuteWorkflow(context.WithoutCancel(ctx), client.StartWorkflowOptions{
		ID: workflowID(runID), TaskQueue: t.taskQueue,
	}, RunLifecycle, RunInput{RunID: runID, Timeouts: t.timeouts})
	if err != nil && !isAlreadyStarted(err) {
		t.log("starting run workflow failed", "run", runID, "err", err)
	}
}

func (t *Temporal) signal(ctx context.Context, runID, name string, arg any) {
	if err := t.c.SignalWorkflow(context.WithoutCancel(ctx), workflowID(runID), "", name, arg); err != nil {
		t.log("signalling run workflow failed", "run", runID, "signal", name, "err", err)
	}
}

func (t *Temporal) Planned(ctx context.Context, runID string, awaiting bool) {
	t.signal(ctx, runID, SignalPlanned, awaiting)
}
func (t *Temporal) Approved(ctx context.Context, runID string) {
	t.signal(ctx, runID, SignalApproved, true)
}
func (t *Temporal) Finished(ctx context.Context, runID string) {
	t.signal(ctx, runID, SignalFinished, true)
}
