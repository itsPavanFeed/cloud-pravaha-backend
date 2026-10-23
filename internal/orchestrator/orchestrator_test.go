package orchestrator

import (
	"context"
	"testing"
	"time"

	"go.temporal.io/sdk/testsuite"
)

type fakeStore struct{ expired []string }

func (f *fakeStore) Expire(_ context.Context, runID string, from []string, to, reason string) (bool, error) {
	f.expired = append(f.expired, to+":"+reason)
	return true, nil
}
func (f *fakeStore) QueueDueDrift(context.Context) ([]string, error) { return []string{"r1"}, nil }

var to = Timeouts{Planning: 10 * time.Minute, Approval: time.Hour, Applying: 30 * time.Minute}

func run(t *testing.T, signals func(env *testsuite.TestWorkflowEnvironment)) (string, *fakeStore) {
	var s testsuite.WorkflowTestSuite
	env := s.NewTestWorkflowEnvironment()
	fs := &fakeStore{}
	env.RegisterActivity(&Activities{Store: fs})
	signals(env)
	env.ExecuteWorkflow(RunLifecycle, RunInput{RunID: "r1", Timeouts: to})
	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow did not complete: %v", env.GetWorkflowError())
	}
	var res string
	env.GetWorkflowResult(&res)
	return res, fs
}

func TestRunLifecycle(t *testing.T) {
	// A runner that never reports: the run fails after the planning timeout.
	res, fs := run(t, func(*testsuite.TestWorkflowEnvironment) {})
	if len(fs.expired) != 1 || fs.expired[0] != "failed:runner stopped reporting while planning" {
		t.Fatalf("planning timeout: %v %s", fs.expired, res)
	}
	// Planned but nobody approves: discarded after the approval window.
	_, fs = run(t, func(env *testsuite.TestWorkflowEnvironment) {
		env.RegisterDelayedCallback(func() { env.SignalWorkflow(SignalPlanned, true) }, time.Minute)
	})
	if len(fs.expired) != 1 || fs.expired[0] != "discarded:plan expired before approval" {
		t.Fatalf("approval timeout: %v", fs.expired)
	}
	// The happy path: planned, approved, finished. Nothing expires.
	_, fs = run(t, func(env *testsuite.TestWorkflowEnvironment) {
		env.RegisterDelayedCallback(func() { env.SignalWorkflow(SignalPlanned, true) }, time.Minute)
		env.RegisterDelayedCallback(func() { env.SignalWorkflow(SignalApproved, true) }, 20*time.Minute)
		env.RegisterDelayedCallback(func() { env.SignalWorkflow(SignalFinished, true) }, 25*time.Minute)
	})
	if len(fs.expired) != 0 {
		t.Fatalf("nothing should expire on the happy path: %v", fs.expired)
	}
	// An apply that hangs fails after the apply timeout.
	_, fs = run(t, func(env *testsuite.TestWorkflowEnvironment) {
		env.RegisterDelayedCallback(func() { env.SignalWorkflow(SignalPlanned, true) }, time.Minute)
		env.RegisterDelayedCallback(func() { env.SignalWorkflow(SignalApproved, true) }, 2*time.Minute)
	})
	if len(fs.expired) != 1 || fs.expired[0] != "failed:apply did not finish in time" {
		t.Fatalf("apply timeout: %v", fs.expired)
	}
	// No approval needed (no changes, policy failed, drift): done at planning.
	_, fs = run(t, func(env *testsuite.TestWorkflowEnvironment) {
		env.RegisterDelayedCallback(func() { env.SignalWorkflow(SignalPlanned, false) }, time.Minute)
	})
	if len(fs.expired) != 0 {
		t.Fatalf("terminal plans must not expire: %v", fs.expired)
	}
}

func TestDriftSweep(t *testing.T) {
	var s testsuite.WorkflowTestSuite
	env := s.NewTestWorkflowEnvironment()
	env.RegisterActivity(&Activities{Store: &fakeStore{}})
	env.ExecuteWorkflow(DriftSweep)
	var ids []string
	if env.GetWorkflowError() != nil || env.GetWorkflowResult(&ids) != nil || len(ids) != 1 {
		t.Fatalf("drift sweep: %v %v", env.GetWorkflowError(), ids)
	}
}
