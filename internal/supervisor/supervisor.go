// Package supervisor is the trusted orchestration of one codegen Job
// launch (DD-03 §4–§6): it checks its own identity and the launch facts,
// prepares the fixed layout, waits for the execution scope from the access
// sidecar, stages the inputs, and then runs either the fixed non-paid task
// (supervisor, observer and finalizer: fixed.go) or the bounded team, whose
// trusted coordinator it starts and serves over the process protocol
// (team.go). Every candidate execution goes through internal/process: one
// start, stop and confirmation path whatever ends it. The candidate's exit
// code, its log and everything it wrote are data; none of it becomes a
// verdict.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/config"
	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/launch"
	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/privdrop"
	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/process"
	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/sidecar"
)

// TeamCommand selects the team flow (the team profile's entrypoint
// argument); the mode is the reviewed profile's, never an environment
// variable's.
const TeamCommand = "team"

// candidateMargin is kept between a candidate's bound and the launch
// deadline for the stop, the observer and the finalizer.
const candidateMargin = 15 * time.Second

// Supervisor runs one launch.
type Supervisor struct {
	Config config.Config
	Log    *slog.Logger
	// Self is the supervisor executable (the trampoline and the stop helper).
	Self string
	Now  func() time.Time
	proc *process.Controller
}

// errCanceled marks a launch whose candidate was stopped because the
// supervisor was told to stop (the Pod is being deleted): nothing is
// certified or submitted; the launcher's cleanup closes the attempt.
var errCanceled = errors.New("launch canceled")

// Run executes the launch and returns the process exit code: 0 when the
// trusted flow completed (whatever the verdict), 1 when it could not (no
// scope, no authority, a refused submission, a privilege-drop failure, a
// candidate that could not be stopped, a canceled launch).
func (s *Supervisor) Run(ctx context.Context) int {
	summary := &Summary{Outcome: "infrastructure_failed"}
	defer s.terminate(summary)
	if err := s.run(ctx, summary); err != nil {
		if errors.Is(err, errCanceled) {
			summary.Outcome = "canceled"
		}
		summary.Error = err.Error()
		s.Log.Error("trusted flow did not complete", "error", err.Error())
		return 1
	}
	return 0
}

// launchFacts is what the common part of a launch established for the
// fixed task and the team flow.
type launchFacts struct {
	env       launch.Envelope
	resources Resources
	client    *sidecar.Client
	inputs    map[string][]byte
	started   time.Time
}

func (s *Supervisor) run(ctx context.Context, summary *Summary) error {
	cfg := s.Config
	started := s.Now()
	if err := privdrop.CheckSupervisor(); err != nil {
		return fmt.Errorf("supervisor identity: %w", err)
	}
	// Before anything is forked: orphaned candidate processes reparent to
	// this process, where the stop can find and reap them.
	if err := process.BecomeSubreaper(); err != nil {
		return err
	}
	s.proc = &process.Controller{Self: s.Self, UID: cfg.Candidate.UID, GID: cfg.Candidate.GID, Dir: cfg.Paths.Workspace, Now: s.Now}
	if cfg.Team.Enabled {
		// The validator the coordinator runs has a second step identity (its
		// SSR harness): every stop covers it too.
		s.proc.Others = []process.Identity{{UID: cfg.Team.HarnessUID, GID: cfg.Team.HarnessGID}}
	}
	env, err := launch.Parse([]byte(cfg.Launch.Envelope))
	if err != nil {
		return err
	}
	if env.LaunchID != cfg.Launch.LaunchID || env.AttemptID != cfg.Launch.AttemptID {
		return fmt.Errorf("launch envelope names %s/%s, the launch environment %s/%s", env.LaunchID, env.AttemptID, cfg.Launch.LaunchID, cfg.Launch.AttemptID)
	}
	deadline, _ := env.DeadlineTime()
	if !s.Now().Before(deadline) {
		return errors.New("the launch deadline has passed; nothing runs")
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	resources, err := LoadResources(cfg.Paths.AgentDir, cfg.Candidate.UID, cfg.Candidate.GID)
	if err != nil {
		return fmt.Errorf("trusted resources: %w", err)
	}
	summary.Resources = resources.Digest
	if err := s.prepareLayout(); err != nil {
		return err
	}
	inputDir := s.inputDir()
	if err := os.Mkdir(inputDir, 0o755); err != nil {
		return err
	}
	inputs, err := launch.StageProtected(env, cfg.Paths.Fixtures, inputDir)
	if err != nil {
		return err
	}

	client := &sidecar.Client{Socket: filepath.Join(cfg.Paths.Sockets, "trusted.sock"), Timeout: cfg.Sidecar.RequestTimeout}
	if err := client.WaitFor(ctx, cfg.Sidecar.Wait); err != nil {
		return err
	}
	if err := client.VerifyLayout(cfg.Sidecar.UID); err != nil {
		return fmt.Errorf("sidecar socket layout: %w", err)
	}
	scope, _, err := client.AwaitScope(ctx, 2*time.Second, func(m string) { s.Log.Info("waiting for the execution scope", "reason", m) })
	if err != nil {
		return fmt.Errorf("execution scope: %w", err)
	}
	if scope.AttemptID != env.AttemptID || scope.OperationID != env.OperationID || scope.ProfileID != env.ProfileID || scope.LaunchKey != env.LaunchKey {
		return fmt.Errorf("execution scope (%s/%s/%s/%s) does not match the launch envelope", scope.OperationID, scope.AttemptID, scope.ProfileID, scope.LaunchKey)
	}
	s.Log.Info("execution scope granted", "instanceId", scope.InstanceID, "attemptId", scope.AttemptID)
	for name, b := range inputs {
		if err := client.StageInput(ctx, name, b); err != nil {
			return fmt.Errorf("stage input %s: %w", name, err)
		}
	}
	loaded, err := launch.LoadBound(ctx, env, client, inputDir, cfg.Sidecar.MaxInputBytes, inputs)
	for _, l := range loaded {
		s.Log.Info("input loaded through the sidecar", "name", l.Name, "class", l.Class, "sizeBytes", l.SizeBytes)
	}
	if err != nil {
		return err
	}

	facts := launchFacts{env: env, resources: resources, client: client, inputs: inputs, started: started}
	if cfg.Team.Enabled {
		// P12: the trusted coordinator runs the bounded team; the candidate
		// rounds it asks for are launched, stopped and confirmed here.
		return s.runTeam(ctx, facts, summary)
	}
	return s.runFixed(ctx, facts, summary)
}

func (s *Supervisor) inputDir() string { return filepath.Join(s.Config.Paths.Workspace, "input") }

// prepareLayout fixes the mount layout before the candidate exists: the
// verdict tree is closed to everyone but the supervisor; the workspace
// root is an emptyDir the candidate will create its own tree in; the
// protected inputs go into a root-owned, read-only directory the
// candidate can read but not alter.
func (s *Supervisor) prepareLayout() error {
	cfg := s.Config
	for _, dir := range []string{cfg.Paths.Workspace, cfg.Paths.Verdict} {
		st, err := os.Lstat(dir)
		if err != nil || !st.IsDir() {
			return fmt.Errorf("%s is not a mounted directory: %v", dir, err)
		}
		if st.Sys().(*syscall.Stat_t).Uid != 0 {
			return fmt.Errorf("%s is not root-owned", dir)
		}
	}
	if err := os.Chmod(cfg.Paths.Verdict, 0o700); err != nil {
		return fmt.Errorf("close the verdict tree: %w", err)
	}
	if err := os.Chmod(cfg.Paths.Workspace, 0o1777); err != nil {
		return fmt.Errorf("workspace mode: %w", err)
	}
	// Anything left from an earlier run of this launch identity is stale.
	for _, p := range []string{filepath.Join(cfg.Paths.Workspace, "w"), s.inputDir()} {
		if err := os.RemoveAll(p); err != nil {
			return err
		}
	}
	return nil
}

// candidateEnv is the environment every candidate gets: a fixed PATH, its
// own tree as HOME, the workspace and input locations and the sidecar
// sockets it may (candidate) and may not (trusted) reach.
func (s *Supervisor) candidateEnv(extra ...string) []string {
	cfg := s.Config
	return append([]string{
		"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + filepath.Join(cfg.Paths.Workspace, "w"),
		"ANVILKIT_WORKSPACE=" + cfg.Paths.Workspace, "ANVILKIT_INPUT_DIR=" + s.inputDir(),
		"ANVILKIT_CANDIDATE_SOCKET=" + filepath.Join(cfg.Paths.Sockets, "candidate.sock"), "ANVILKIT_TRUSTED_SOCKET=" + filepath.Join(cfg.Paths.Sockets, "trusted.sock"),
	}, extra...)
}

// candidateTimeout is the candidate's bound: the configured one, shortened
// to leave candidateMargin before the launch deadline.
func (s *Supervisor) candidateTimeout(ctx context.Context) time.Duration {
	timeout := s.Config.Candidate.Timeout
	if d, ok := ctx.Deadline(); ok && time.Until(d)-candidateMargin < timeout {
		timeout = time.Until(d) - candidateMargin
	}
	return timeout
}
