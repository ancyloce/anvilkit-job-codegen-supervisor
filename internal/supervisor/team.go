package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/process"
	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/protocol"
)

// The team flow (DD-03 §1–§3, delivery.md P12): the trusted coordinator of
// the team package runs as a child of the supervisor with the supervisor's
// identity (UID 0, no candidate module ever imported there) and drives the
// bounded LangGraph team, the joint stage store and the submission through
// the sidecar's trusted routes itself. The one thing it cannot do is start
// the Pi coder: every coding round is a run-candidate request of the
// process protocol (internal/protocol) that this process answers by
// launching the reviewed coder program as the candidate through the same
// trampoline, bound, stop and confirmation the fixed task uses, and by
// reporting how the candidate ended once nothing of it runs. The request
// names a round and its directory and nothing else; program, identity,
// environment and bounds are the reviewed configuration's.

// coordinatorStopGrace is how long the coordinator gets to end after
// SIGTERM before its process group is killed.
const coordinatorStopGrace = 30 * time.Second

var (
	// errTeamBound ends the team's context at the team's bound: a candidate
	// round still running then is stopped as at its own bound.
	errTeamBound = fmt.Errorf("the team reached its bound: %w", process.ErrBoundReached)
	// errTeamEnded ends the team's context when the coordinator exited: a
	// candidate round it left running has no one to answer to.
	errTeamEnded = errors.New("the coordinator ended")
	// errProtocol marks a coordinator that left the process protocol.
	errProtocol = errors.New("coordinator protocol violation")
)

func (s *Supervisor) runTeam(ctx context.Context, f launchFacts, summary *Summary) error {
	cfg := s.Config
	teamDir := filepath.Join(cfg.Paths.Verdict, "team")
	if err := os.MkdirAll(teamDir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(cfg.Team.Config); err != nil {
		return fmt.Errorf("team configuration: %w", err)
	}
	bound := cfg.Team.Timeout
	if d, ok := ctx.Deadline(); ok && time.Until(d) < bound {
		bound = time.Until(d)
	}
	if bound < time.Second {
		return errors.New("no time left for the team before the deadline")
	}
	logf, err := os.OpenFile(filepath.Join(teamDir, "coordinator.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command(cfg.Team.Coordinator[0], cfg.Team.Coordinator[1:]...)
	cmd.Env = s.coordinatorEnv(teamDir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start coordinator: %w", err)
	}
	s.proc.SetTrusted(cmd.Process.Pid)
	defer s.proc.SetTrusted(0)
	s.Log.Info("coordinator started", "pid", cmd.Process.Pid, "bound", bound.String())

	// The candidate rounds run under the team's own context: it ends when
	// the team reaches its bound, when the launch is canceled, when the
	// protocol ends in a violation or a final refusal, or when the
	// coordinator exits; a round still running then is stopped and
	// confirmed through the same path as at its own bound before anything
	// continues — the coordinator's end never leaves a candidate writing.
	teamCtx, endTeam := context.WithCancelCause(ctx)
	defer endTeam(nil)
	server := &teamServer{s: s, summary: summary}
	served := make(chan error, 1)
	go func() { served <- server.serve(teamCtx, stdout, stdin) }()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	timer := time.NewTimer(bound)
	defer timer.Stop()

	var werr, perr error
	protocolDone := false
	stop := func(cause error) {
		endTeam(cause)
		werr = stopTrusted(cmd, waited, coordinatorStopGrace)
	}
	for exited := false; !exited; {
		select {
		case werr = <-waited:
			exited = true
		case perr = <-served:
			protocolDone, served = true, nil
			if perr != nil {
				s.Log.Warn("the protocol ended; stopping the coordinator", "reason", perr.Error())
				stop(perr)
				exited = true
			}
		case <-timer.C:
			s.Log.Warn("the team reached its bound; stopping the coordinator and any candidate round")
			stop(errTeamBound)
			exited = true
		case <-ctx.Done():
			s.Log.Warn("launch canceled while the team runs; stopping the coordinator and any candidate round")
			stop(context.Cause(ctx))
			exited = true
		}
	}
	endTeam(errTeamEnded)
	_ = stdin.Close()
	if !protocolDone {
		perr = <-served
	}
	// Nothing the launch started may outlive the team: the coordinator's own
	// children (validation steps) and anything of the candidate are stopped
	// and confirmed gone before the result is read.
	s.proc.SetTrusted(0)
	if _, err := s.proc.StopAll(); err != nil {
		return fmt.Errorf("after the coordinator ended: %w", err)
	}
	if perr != nil {
		return perr
	}
	again, err := LoadResources(cfg.Paths.AgentDir, cfg.Candidate.UID, cfg.Candidate.GID)
	if err != nil || again.Digest != f.resources.Digest {
		return errors.New("trusted resources changed while the team ran")
	}
	result, rerr := readTeamResult(filepath.Join(teamDir, "result.json"))
	if result != nil {
		summary.Verdict, summary.FailureCode, summary.StageID = result.Verdict, result.FailureCode, result.StageID
		summary.Team = &TeamSummary{Outcome: result.Outcome.Kind, Calls: result.Calls, Existing: result.Existing, Error: truncate(result.Error, 300)}
		if result.Counters != nil {
			summary.Team.Rounds, summary.Team.ReviewRounds, summary.Team.Repairs = result.Counters.Rounds, result.Counters.ReviewRounds, result.Counters.Repairs
		}
	}
	if ctx.Err() != nil {
		return fmt.Errorf("%w: the team was stopped and nothing is certified", errCanceled)
	}
	if werr != nil {
		var exit *exec.ExitError
		if !errors.As(werr, &exit) {
			return fmt.Errorf("coordinator: %w", werr)
		}
		if result != nil && result.Outcome.Kind == "canceled" {
			return fmt.Errorf("%w: the coordinator reported the run canceled", errCanceled)
		}
		detail := "no result"
		if rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			detail = "result refused: " + rerr.Error()
		}
		if result != nil {
			detail = result.Outcome.Kind + ": " + truncate(firstLine(result.Error, result.Outcome.Detail), 300)
		}
		return fmt.Errorf("coordinator exited %d (%s)", exit.ExitCode(), detail)
	}
	if rerr != nil {
		return fmt.Errorf("coordinator exited 0 without a result: %w", rerr)
	}
	if result.StageID == "" {
		return errors.New("coordinator exited 0 without an accepted stage")
	}
	summary.Outcome = "completed"
	if result.Existing {
		summary.Duplicate = &DuplicateCheck{Existing: true, SameStage: true}
	}
	s.Log.Info("team result accepted", "stageId", result.StageID, "verdict", result.Verdict, "outcome", result.Outcome.Kind, "rounds", summary.Team.Rounds, "calls", result.Calls)
	return nil
}

// coordinatorEnv is the coordinator's complete environment: the reviewed
// configuration's paths and the launch envelope, nothing inherited.
func (s *Supervisor) coordinatorEnv(teamDir string) []string {
	cfg := s.Config
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + teamDir, "NODE_ENV=production",
		"ANVILKIT_TEAM_CONFIG=" + cfg.Team.Config, "ANVILKIT_AGENT_DIR=" + cfg.Paths.AgentDir,
		"ANVILKIT_WORKSPACE=" + cfg.Paths.Workspace, "ANVILKIT_VERDICT_DIR=" + cfg.Paths.Verdict,
		"ANVILKIT_INPUT_DIR=" + s.inputDir(),
		"ANVILKIT_TRUSTED_SOCKET=" + filepath.Join(cfg.Paths.Sockets, "trusted.sock"), "ANVILKIT_CANDIDATE_SOCKET=" + filepath.Join(cfg.Paths.Sockets, "candidate.sock"),
		"ANVILKIT_LAUNCH_ENVELOPE=" + cfg.Launch.Envelope, "ANVILKIT_OBSERVER_IDENTITY=" + cfg.Team.Observer,
		"ANVILKIT_CODEGEN_TEAM_CONTRACTS_DIR=" + cfg.Team.ContractsDir, "ANVILKIT_VALIDATOR_CONTRACTS_DIR=" + cfg.Team.ContractsDir,
	}
	if p := os.Getenv("PLAYWRIGHT_BROWSERS_PATH"); p != "" {
		env = append(env, "PLAYWRIGHT_BROWSERS_PATH="+p)
	}
	return env
}

// stopTrusted ends a trusted child of the supervisor's own identity:
// SIGTERM, then SIGKILL to its process group after the grace. It returns
// the child's wait result.
func stopTrusted(cmd *exec.Cmd, waited <-chan error, grace time.Duration) error {
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-waited:
		return err
	case <-time.After(grace):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return <-waited
	}
}

// teamServer serves the coordinator's protocol: one request at a time,
// answered after the candidate round ended and was confirmed stopped.
type teamServer struct {
	s                      *Supervisor
	summary                *Summary
	lastRequest, lastRound int
	// final is set by a refusal that ends the launch (the candidate could
	// not run, or its stop could not be established): no round runs after
	// it and the service ends.
	final error
}

// serve reads requests until the channel ends (nil), the coordinator
// leaves the protocol (errProtocol) or a round ends finally (the round's
// error, wrapping process.ErrNotRun or process.ErrStopNotEstablished).
func (t *teamServer) serve(ctx context.Context, from io.Reader, to io.Writer) error {
	requests := protocol.NewReader(from)
	for {
		req, err := requests.Next()
		var v *protocol.Violation
		switch {
		case errors.As(err, &v):
			return fmt.Errorf("%w: %s", errProtocol, v.Reason)
		case err != nil:
			return nil // the channel ended with the coordinator
		case req.RequestID <= t.lastRequest:
			return fmt.Errorf("%w: requestId %d does not follow %d", errProtocol, req.RequestID, t.lastRequest)
		}
		t.lastRequest = req.RequestID
		answer := t.answer(ctx, req)
		if err := protocol.WriteAnswer(to, answer); err != nil && t.final == nil {
			return nil // the coordinator is gone
		}
		if t.final != nil {
			return t.final
		}
	}
}

func (t *teamServer) answer(ctx context.Context, req protocol.Request) any {
	if ctx.Err() != nil {
		return protocol.Refuse(req, protocol.RefusedTeamEnded, "no candidate round runs after the team ended")
	}
	if req.Round <= t.lastRound {
		return protocol.Refuse(req, protocol.RefusedRoundNotNew, fmt.Sprintf("round %d is not greater than round %d", req.Round, t.lastRound))
	}
	if err := t.s.checkRoundDir(req); err != nil {
		return protocol.Refuse(req, protocol.RefusedRoundDirInvalid, err.Error())
	}
	t.lastRound = req.Round
	run, err := t.s.runRound(ctx, req)
	if err != nil {
		// An unestablished stop is reported as exactly that: never as a
		// stopped candidate, never as an outcome the coordinator may build on.
		code := protocol.RefusedCandidateNotRun
		if errors.Is(err, process.ErrStopNotEstablished) {
			code = protocol.RefusedStopNotEstablished
		}
		t.final = fmt.Errorf("round %d: %w", req.Round, err)
		return protocol.Refuse(req, code, err.Error())
	}
	t.summary.CandidateExit, t.summary.CandidateStop = run.Exit, string(run.Reason)
	return protocol.Ended(req, string(run.Reason), run.Exit, run.Signal, run.Stopped, run.Started, run.Ended)
}

// checkRoundDir holds a request's directory to the protocol's rule: the
// workspace's round directory of that round, reached through real
// directories of the supervisor's own identity (the coordinator's) that
// neither group nor others can write. A path the candidate could have
// planted is never handed to the next candidate as its round input.
func (s *Supervisor) checkRoundDir(req protocol.Request) error {
	root := filepath.Join(s.Config.Paths.Workspace, "round")
	want := filepath.Join(root, strconv.Itoa(req.Round))
	if req.RoundDir != want {
		return fmt.Errorf("the round directory is not the workspace's round directory of round %d", req.Round)
	}
	own := uint32(os.Geteuid())
	for _, dir := range []string{root, want} {
		st, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("round directory: %v", err)
		}
		if !st.IsDir() || st.Sys().(*syscall.Stat_t).Uid != own || st.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is not a real directory of the coordinator's identity closed to group and other writes", filepath.Base(dir))
		}
	}
	return nil
}

// runRound runs the reviewed coder program as the candidate of one round.
func (s *Supervisor) runRound(ctx context.Context, req protocol.Request) (process.Ended, error) {
	cfg := s.Config
	logf, err := os.OpenFile(filepath.Join(cfg.Paths.Verdict, "team", fmt.Sprintf("coder-round-%d.log", req.Round)), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return process.Ended{}, fmt.Errorf("%w: %v", process.ErrNotRun, err)
	}
	defer logf.Close()
	return s.proc.Run(ctx, process.Spec{
		Program: cfg.Team.Coder[0], Args: cfg.Team.Coder[1:], Output: logf, Timeout: s.candidateTimeout(ctx),
		Env: s.candidateEnv("ANVILKIT_ROUND_DIR=" + req.RoundDir),
	})
}

// readTeamResult reads the coordinator's result document strictly.
func readTeamResult(path string) (*protocol.TeamResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, protocol.MaxResultBytes+1))
	if err != nil {
		return nil, err
	}
	r, err := protocol.DecodeTeamResult(raw)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func firstLine(a, b string) string {
	if a != "" {
		return strings.SplitN(a, "\n", 2)[0]
	}
	return strings.SplitN(b, "\n", 2)[0]
}
