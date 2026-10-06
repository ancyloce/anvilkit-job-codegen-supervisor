package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/config"
	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/launch"
	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/process"
)

// ExpectedResult is what the fixed task must write for the given inputs:
// the observer computes it independently and never learns it from the
// candidate.
func ExpectedResult(inputs []launch.Input) []byte {
	sorted := append([]launch.Input(nil), inputs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	b.WriteString("anvilkit-codegen-fixed-v1\n")
	for _, in := range sorted {
		fmt.Fprintf(&b, "input %s %s\n", in.Name, in.Digest)
	}
	return []byte(b.String())
}

// fixedCandidateEnv is the P09 fixed task's boundary probes beyond the
// common candidate environment.
func (s *Supervisor) fixedCandidateEnv(inputs map[string][]byte) []string {
	cfg := s.Config
	probes := []string{
		filepath.Join(cfg.Paths.Verdict, "verdict.json"), filepath.Join(cfg.Paths.AgentDir, resourcesFile), filepath.Join(cfg.Paths.Fixtures, "fixed-input.txt"),
		"/proc/1/environ", "/proc/1/cwd/.",
	}
	if p := os.Getenv(config.EnvConfigFile); p != "" {
		probes = append(probes, p)
	}
	return s.candidateEnv(
		"ANVILKIT_PROBE_FILES="+strings.Join(probes, ","),
		"ANVILKIT_PROBE_WRITES="+strings.Join([]string{filepath.Join(cfg.Paths.Verdict, "manifest.json"), filepath.Join(cfg.Paths.AgentDir, "AGENTS.md"), filepath.Join(s.inputDir(), "fixed-input")}, ","),
		"ANVILKIT_PROBE_TARGETS="+strings.Join(cfg.Candidate.ProbeTargets, ","), "ANVILKIT_PROBE_INPUT="+firstName(inputs),
	)
}

// runFixed is the P09 fixed non-paid task: the candidate, then — only once
// no candidate process runs — the observer (a read-only snapshot into the
// verdict tree, the verdict from the bytes, the trusted resources
// rechecked) and the finalizer (verified bytes first, then the manifest
// naming them, submitted twice to record idempotent acceptance).
func (s *Supervisor) runFixed(ctx context.Context, f launchFacts, summary *Summary) error {
	cfg := s.Config
	env := f.env
	evidence := Evidence{SchemaVersion: 1, LaunchID: env.LaunchID, AttemptID: env.AttemptID, ResourcesDigest: f.resources.Digest, StartedAt: f.started, ExpectedDigest: launch.Digest(ExpectedResult(env.Inputs))}
	logf, err := os.OpenFile(filepath.Join(cfg.Paths.Verdict, "candidate.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	run, err := s.proc.Run(ctx, process.Spec{Program: cfg.Candidate.Program, Env: s.fixedCandidateEnv(f.inputs), Output: logf, Timeout: s.candidateTimeout(ctx)})
	if err != nil {
		return err
	}
	evidence.CandidateExit, evidence.CandidateSignal, evidence.CandidateStarted, evidence.CandidateEnded = run.Exit, run.Signal, &run.Started, &run.Ended
	evidence.CandidateStop, evidence.DescendantsStopped = string(run.Reason), run.Stopped
	summary.CandidateExit, summary.CandidateStop = run.Exit, string(run.Reason)
	if run.Reason == process.Canceled {
		// Stopped and confirmed; the launch is ending, so the evidence
		// stays local and no verdict is issued or submitted.
		if err := writeJSON(filepath.Join(cfg.Paths.Verdict, "evidence.json"), evidence); err != nil {
			return err
		}
		return fmt.Errorf("%w: the candidate was stopped (%d process(es) signaled) and nothing is certified", errCanceled, run.Stopped)
	}

	snap, err := snapshot(filepath.Join(cfg.Paths.Workspace, "w", "output"), filepath.Join(cfg.Paths.Verdict, "snapshot"), cfg.Candidate.MaxOutputBytes)
	if err != nil {
		return fmt.Errorf("observer snapshot: %w", err)
	}
	for name := range snap.Files {
		evidence.OutputFiles = append(evidence.OutputFiles, name)
	}
	sort.Strings(evidence.OutputFiles)
	evidence.Refused = snap.Refused
	if p, ok := snap.Files["probes.json"]; ok && json.Valid(p) && len(p) <= 64<<10 {
		evidence.Probes = json.RawMessage(p)
		summary.Probes = probeSummary(p)
	}
	again, err := LoadResources(cfg.Paths.AgentDir, cfg.Candidate.UID, cfg.Candidate.GID)
	evidence.ResourcesIntact = err == nil && again.Digest == f.resources.Digest
	result, ok := snap.Files["result.txt"]
	var verdict, failureCode string
	switch {
	case !evidence.ResourcesIntact:
		verdict, failureCode = "invalid", "PROTECTED_FIXTURE_ALTERED"
	case run.Reason == process.Timeout:
		// A candidate that had to be stopped at its bound is not certified
		// by whatever bytes it left behind.
		verdict, failureCode = "invalid", "DEADLINE_EXCEEDED"
	case !ok:
		verdict, failureCode = "invalid", "CANDIDATE_TEST_FAILED"
	case launch.Digest(result) != evidence.ExpectedDigest:
		verdict, failureCode = "invalid", "RESULT_DIGEST_MISMATCH"
	default:
		verdict, failureCode = "certified", ""
	}
	if ok {
		evidence.ObservedDigest = launch.Digest(result)
	}
	if err := os.WriteFile(filepath.Join(cfg.Paths.Verdict, "verdict.json"), []byte(fmt.Sprintf(`{"verdict":%q,"failureCode":%q}`+"\n", verdict, failureCode)), 0o600); err != nil {
		return err
	}
	summary.Verdict, summary.FailureCode = verdict, failureCode

	outputs := []map[string]string{}
	if ok {
		t, err := f.client.Upload(ctx, "result", "text/plain", result)
		if err != nil {
			return fmt.Errorf("result transfer: %w", err)
		}
		summary.ResultHandle = t.Handle
		outputs = append(outputs, map[string]string{"class": "result", "digest": t.Digest, "sizeBytes": t.SizeBytes, "handle": t.Handle})
	}
	evidenceBytes, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(cfg.Paths.Verdict, "evidence.json"), evidenceBytes, 0o600); err != nil {
		return err
	}
	et, err := f.client.Upload(ctx, "evidence", "application/json", evidenceBytes)
	if err != nil {
		return fmt.Errorf("evidence transfer: %w", err)
	}
	summary.EvidenceHandle = et.Handle
	outputs = append(outputs, map[string]string{"class": "evidence", "digest": et.Digest, "sizeBytes": et.SizeBytes, "handle": et.Handle})
	manifest := map[string]any{
		"schemaVersion": 1, "launchId": env.LaunchID, "attemptId": env.AttemptID, "jobKind": env.JobKind, "profileId": env.ProfileID,
		"verdict": verdict, "outputs": outputs, "completedAt": s.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	if failureCode != "" {
		manifest["failureCode"] = failureCode
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(cfg.Paths.Verdict, "manifest.json"), raw, 0o600); err != nil {
		return err
	}
	stage, err := f.client.Submit(ctx, verdict, failureCode, cfg.Observer.Identity, raw)
	if err != nil {
		return fmt.Errorf("result submission: %w", err)
	}
	summary.StageID = stage.StageID
	// The same bytes submitted again must reenter the same stage.
	repeat, err := f.client.Submit(ctx, verdict, failureCode, cfg.Observer.Identity, raw)
	if err != nil {
		return fmt.Errorf("repeated result submission: %w", err)
	}
	summary.Duplicate = &DuplicateCheck{Existing: repeat.Existing, SameStage: repeat.StageID == stage.StageID}
	summary.Outcome = "completed"
	s.Log.Info("result accepted", "stageId", stage.StageID, "verdict", verdict, "duplicateReentered", repeat.Existing && repeat.StageID == stage.StageID)
	return nil
}

func writeJSON(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func firstName(inputs map[string][]byte) string {
	names := make([]string, 0, len(inputs))
	for n := range inputs {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// probeSummary condenses the candidate's probe report to controlled keys
// and short outcomes for the termination message.
func probeSummary(raw []byte) map[string]string {
	var report struct {
		Outcomes map[string]string `json:"outcomes"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil
	}
	out := map[string]string{}
	for k, v := range report.Outcomes {
		out[truncate(k, 48)] = truncate(v, 48)
	}
	return out
}
