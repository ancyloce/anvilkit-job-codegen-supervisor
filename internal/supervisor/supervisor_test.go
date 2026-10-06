package supervisor_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/config"
	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/launch"
	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/process"
	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/supervisor"
)

const (
	candidateUID = 10001
	sidecarUID   = 10002
	fixedInput   = "anvilkit-codegen-fixed-v1 input\n"
	fixedDigest  = "sha256:abeb263b000189efdd8206ff39eeb4f2f7f3217f1c480491868b46da4a21c6a8"
)

// TestMain doubles as the helper processes. By subcommand, exactly as the
// image entrypoint dispatches: candidate-exec (the privilege-drop
// trampoline), candidate-stop (the stop from inside the candidate
// identity) and supervisor-exec (the whole-process constraint to the
// reviewed set). By environment: "supervise" runs the supervisor as the
// entrypoint does (signals included), "misbehave" is a candidate that
// leaves descendants in new sessions and process groups, "sleeper" one
// such descendant, "threads" reports the capability sets of every thread.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case process.TrampolineCommand:
			os.Exit(process.Trampoline(os.Args[2:]))
		case process.StopCommand:
			self, _ := os.Executable()
			if _, err := os.Stat(filepath.Join(filepath.Dir(self), "deny-stop")); err == nil {
				os.Exit(111) // controlled failure of the test helper, never shipped
			}
			os.Exit(process.Stop(os.Args[2:]))
		case process.SupervisorExecCommand:
			os.Exit(process.SupervisorExec(os.Args[2:]))
		}
	}
	switch os.Getenv("HARNESS_HELPER") {
	case "supervise":
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(2)
		}
		self, _ := os.Executable()
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer stop()
		s := &supervisor.Supervisor{Config: cfg, Log: slog.New(slog.NewJSONHandler(os.Stderr, nil)), Self: self, Now: time.Now}
		os.Exit(s.Run(ctx))
	case "misbehave":
		os.Exit(misbehave())
	case "sleeper":
		for {
			time.Sleep(time.Hour)
		}
	case "threads":
		os.Exit(reportThreads())
	}
	os.Exit(m.Run())
}

// misbehave is the candidate of the stop tests: it performs the fixed task
// (so the bytes alone would certify), starts three descendants — one in a
// new session (setsid), one in a new process group (setpgid), one in its
// own group — records every PID under the workspace and then, by
// HARNESS_MODE, either hangs ("hang") or exits at once ("exit"), leaving
// the descendants behind.
func misbehave() int {
	workspace, inputDir := os.Getenv("ANVILKIT_WORKSPACE"), os.Getenv("ANVILKIT_INPUT_DIR")
	output := filepath.Join(workspace, "w", "output")
	if err := os.MkdirAll(output, 0o755); err != nil {
		return 2
	}
	entries, _ := os.ReadDir(inputDir)
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	result := "anvilkit-codegen-fixed-v1\n"
	for _, n := range names {
		b, _ := os.ReadFile(filepath.Join(inputDir, n))
		result += fmt.Sprintf("input %s sha256:%x\n", n, sha256.Sum256(b))
	}
	if err := os.WriteFile(filepath.Join(output, "result.txt"), []byte(result), 0o644); err != nil {
		return 2
	}
	self, _ := os.Executable()
	pids := []string{strconv.Itoa(os.Getpid())}
	for _, attr := range []*syscall.SysProcAttr{{Setsid: true}, {Setpgid: true}, {}} {
		c := exec.Command(self)
		c.Env = []string{"HARNESS_HELPER=sleeper"}
		c.SysProcAttr = attr
		if err := c.Start(); err != nil {
			return 2
		}
		pids = append(pids, strconv.Itoa(c.Process.Pid))
	}
	if err := os.WriteFile(filepath.Join(workspace, "w", "pids"), []byte(strings.Join(pids, "\n")+"\n"), 0o644); err != nil {
		return 2
	}
	if os.Getenv("HARNESS_MODE") == "exit" {
		return 0
	}
	for {
		time.Sleep(time.Hour)
	}
}

// threadStatus is one thread's capability view.
type threadStatus struct {
	TID                                    string
	CapInh, CapPrm, CapEff, CapBnd, CapAmb uint64
	NoNewPrivs                             int
}

// reportThreads prints the capability sets and no_new_privs of every
// thread of this process after making sure several exist.
func reportThreads() int {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			time.Sleep(200 * time.Millisecond)
		}()
	}
	time.Sleep(50 * time.Millisecond)
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return 1
	}
	var out []threadStatus
	for _, t := range tasks {
		raw, err := os.ReadFile(filepath.Join("/proc/self/task", t.Name(), "status"))
		if err != nil {
			continue
		}
		ts := threadStatus{TID: t.Name()}
		for _, line := range strings.Split(string(raw), "\n") {
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			hex := func() uint64 { n, _ := strconv.ParseUint(value, 16, 64); return n }
			switch key {
			case "CapInh":
				ts.CapInh = hex()
			case "CapPrm":
				ts.CapPrm = hex()
			case "CapEff":
				ts.CapEff = hex()
			case "CapBnd":
				ts.CapBnd = hex()
			case "CapAmb":
				ts.CapAmb = hex()
			case "NoNewPrivs":
				ts.NoNewPrivs, _ = strconv.Atoi(value)
			}
		}
		out = append(out, ts)
	}
	wg.Wait()
	_ = json.NewEncoder(os.Stdout).Encode(out)
	return 0
}

// fakeSidecar serves the trusted and candidate sockets with the DD-03
// ownership and the sidecar's route rules (the real sidecar is tested in
// its own repository and in the integration suite); it records what the
// trusted harness sent.
type fakeSidecar struct {
	mu        sync.Mutex
	scope     map[string]any
	scopeCode int // 0: serve the scope; otherwise the failure status/code below
	scopeFail string
	inputs    map[string][]byte
	transfers []map[string]string
	manifests []json.RawMessage
	stageID   string
}

func peerUID(c net.Conn) (uint32, bool) {
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *unix.Ucred
	_ = raw.Control(func(fd uintptr) { cred, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil || cred == nil {
		return 0, false
	}
	return cred.Uid, true
}

type uidKey struct{}

func (f *fakeSidecar) serve(t *testing.T, dir string) {
	t.Helper()
	fail := func(w http.ResponseWriter, status int, code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"code":%q}`, code)
	}
	trusted := http.NewServeMux()
	trusted.HandleFunc("GET /v1/scope", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.scopeCode != 0 {
			fail(w, f.scopeCode, f.scopeFail)
			return
		}
		names := []string{}
		for n := range f.inputs {
			names = append(names, n)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"scope": f.scope, "launchId": "lch_1", "inputs": names})
	})
	trusted.HandleFunc("PUT /v1/inputs/{name}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.inputs[r.PathValue("name")] = b
		f.mu.Unlock()
		w.WriteHeader(200)
		fmt.Fprint(w, "{}")
	})
	trusted.HandleFunc("POST /v1/transfers", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		h := fmt.Sprintf("hdl_%d", len(f.transfers)+1)
		rec := map[string]string{"handle": h, "transferId": "xfer_" + h, "class": r.Header.Get("X-Anvilkit-Class"), "digest": launch.Digest(b), "sizeBytes": fmt.Sprint(len(b)), "objectVersion": "v1", "state": "finalized", "mediaType": r.Header.Get("Content-Type"), "body": string(b)}
		f.transfers = append(f.transfers, rec)
		_ = json.NewEncoder(w).Encode(rec)
	})
	trusted.HandleFunc("POST /v1/results", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Verdict          string          `json:"verdict"`
			ObserverIdentity string          `json:"observerIdentity"`
			Manifest         json.RawMessage `json:"manifest"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		defer f.mu.Unlock()
		existing := len(f.manifests) > 0 && string(f.manifests[0]) == string(in.Manifest)
		f.manifests = append(f.manifests, in.Manifest)
		_ = json.NewEncoder(w).Encode(map[string]any{"stageId": f.stageID, "resultDigest": launch.Digest(in.Manifest), "existing": existing})
	})
	trusted.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fail(w, 403, "ROUTE_FORBIDDEN") })
	candidate := http.NewServeMux()
	candidate.HandleFunc("GET /v1/inputs/{name}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		b, ok := f.inputs[r.PathValue("name")]
		f.mu.Unlock()
		if !ok {
			fail(w, 404, "NOT_FOUND")
			return
		}
		_, _ = w.Write(b)
	})
	candidate.HandleFunc("POST /v1/model/relay", func(w http.ResponseWriter, r *http.Request) { fail(w, 503, "DEPENDENCY_UNAVAILABLE") })
	candidate.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fail(w, 403, "ROUTE_FORBIDDEN") })
	guard := func(uid uint32, h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got, _ := r.Context().Value(uidKey{}).(uint32); got != uid {
				fail(w, 403, "PEER_UID_MISMATCH")
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	listen := func(name string, group uint32, h http.Handler) {
		path := filepath.Join(dir, name)
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		require.NoError(t, err)
		require.NoError(t, os.Chown(path, sidecarUID, int(group)))
		require.NoError(t, os.Chmod(path, 0o660))
		srv := &http.Server{Handler: h, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			uid, _ := peerUID(c)
			return context.WithValue(ctx, uidKey{}, uid)
		}}
		srv.SetKeepAlivesEnabled(false)
		go srv.Serve(l)
		t.Cleanup(func() { srv.Close() })
	}
	listen("trusted.sock", 0, guard(0, trusted))
	listen("candidate.sock", candidateUID, guard(candidateUID, candidate))
}

type layout struct {
	root, workspace, verdict, sockets, agent, fixtures, termination, candidate, cfg, helper string
}

// prepare builds the DD-03 layout under /tmp (world-traversable), the
// candidate program, a world-readable copy of the test binary (the
// supervisor executable, which the candidate identity must be able to
// execute for the stop) and the supervisor's configuration file.
func prepare(t *testing.T) layout {
	t.Helper()
	if os.Geteuid() != 0 {
		if os.Getenv("ANVILKIT_REQUIRE_ROOT_TESTS") != "" {
			t.Fatal("ANVILKIT_REQUIRE_ROOT_TESTS is set: the harness tests must run as root")
		}
		t.Skip("the harness tests run the supervisor as root and the candidate as UID 10001")
	}
	root, err := os.MkdirTemp("/tmp", "harness-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(root) })
	require.NoError(t, os.Chmod(root, 0o755))
	l := layout{root: root, workspace: filepath.Join(root, "workspace"), verdict: filepath.Join(root, "verdict"), sockets: filepath.Join(root, "run", "sockets"), agent: filepath.Join(root, "agent"), fixtures: filepath.Join(root, "fixtures"), termination: filepath.Join(root, "termination-log"), candidate: filepath.Join(root, "anvilkit-codegen-candidate"), cfg: filepath.Join(root, "config.yaml")}
	for _, d := range []string{l.workspace, l.verdict} {
		require.NoError(t, os.Mkdir(d, 0o777))
		require.NoError(t, os.Chmod(d, 0o777)) // an emptyDir
	}
	require.NoError(t, os.MkdirAll(l.sockets, 0o711))
	require.NoError(t, os.Chown(l.sockets, sidecarUID, 0))
	require.NoError(t, os.Chmod(l.sockets, 0o711))
	require.NoError(t, os.Mkdir(l.agent, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(l.agent, "resources.json"), []byte(`{"schemaVersion":1,"systemPrompt":"trusted","tools":[],"skills":[]}`), 0o600))
	require.NoError(t, os.Mkdir(l.fixtures, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(l.fixtures, "fixed-input.txt"), []byte(fixedInput), 0o600))
	build := exec.Command("go", "build", "-o", l.candidate, "../../cmd/anvilkit-codegen-candidate")
	out, err := build.CombinedOutput()
	require.NoError(t, err, string(out))
	self, err := os.Executable()
	require.NoError(t, err)
	raw, err := os.ReadFile(self)
	require.NoError(t, err)
	l.helper = filepath.Join(root, "helper")
	require.NoError(t, os.WriteFile(l.helper, raw, 0o755))
	writeConfig(t, l, "60s")
	return l
}

func writeConfig(t *testing.T, l layout, candidateTimeout string) {
	t.Helper()
	require.NoError(t, os.WriteFile(l.cfg, []byte(fmt.Sprintf("paths:\n  workspace: %s\n  verdict: %s\n  sockets: %s\n  agent_dir: %s\n  fixtures: %s\n  termination_log: %s\ncandidate:\n  program: %s\n  timeout: %s\nsidecar:\n  wait: 10s\n", l.workspace, l.verdict, l.sockets, l.agent, l.fixtures, l.termination, l.candidate, candidateTimeout)), 0o600))
}

// misbehavingCandidate installs the stop tests' candidate program: a shell
// wrapper (the trampoline executes it as UID 10001) that runs the helper
// in misbehave mode.
func misbehavingCandidate(t *testing.T, l layout, mode string) {
	t.Helper()
	require.NoError(t, os.WriteFile(l.candidate, []byte("#!/bin/sh\nHARNESS_HELPER=misbehave HARNESS_MODE="+mode+" exec "+l.helper+"\n"), 0o755))
}

// recordedPIDs reads the PIDs the misbehaving candidate recorded.
func recordedPIDs(t *testing.T, l layout) []int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(l.workspace, "w", "pids"))
	require.NoError(t, err)
	var pids []int
	for _, f := range strings.Fields(string(raw)) {
		n, err := strconv.Atoi(f)
		require.NoError(t, err)
		pids = append(pids, n)
	}
	require.Len(t, pids, 4, "the leader and its three descendants")
	return pids
}

// requireGone asserts that none of the PIDs is a live UID 10001 process.
func requireGone(t *testing.T, pids []int) {
	t.Helper()
	for _, pid := range pids {
		raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
		if err != nil {
			continue
		}
		status := string(raw)
		require.False(t, strings.Contains(status, "\nUid:\t10001") && !strings.Contains(status, "State:\tZ"), "pid %d still runs as the candidate:\n%s", pid, status)
	}
}

func envelopeFor(deadline time.Time) string {
	return fmt.Sprintf(`{"schemaVersion":1,"launchId":"lch_1","launchKey":"cg-test","operationId":"op_1","attemptId":"att_1","profileId":"harness-wiring-dev-v1","profileRevision":"1","jobKind":"codegen","executionEpoch":"1","launchEpoch":"1","deadline":%q,"inputs":[{"name":"fixed-input","digest":%q}]}`, deadline.UTC().Format(time.RFC3339), fixedDigest)
}

// supervisorCommand is the supervisor started as a Job container starts
// it: through supervisor-exec, so the whole process (every thread) holds
// SETUID, SETGID and SETPCAP and nothing else, as UID 0 with no_new_privs.
func supervisorCommand(l layout, env string) *exec.Cmd {
	cmd := exec.Command(l.helper, process.SupervisorExecCommand, "--", l.helper)
	cmd.Env = []string{"HARNESS_HELPER=supervise", "ANVILKIT_CODEGEN_CONFIG=" + l.cfg, "ANVILKIT_LAUNCH_ID=lch_1", "ANVILKIT_ATTEMPT_ID=att_1", "ANVILKIT_LAUNCH_ENVELOPE=" + env, "PATH=/usr/bin:/bin"}
	return cmd
}

// supervise runs the supervisor as a root subprocess and returns its exit
// code and the termination summary.
func supervise(t *testing.T, l layout, env string) (int, supervisor.Summary, string) {
	t.Helper()
	out, err := supervisorCommand(l, env).CombinedOutput()
	return supervised(t, l, out, err)
}

func supervised(t *testing.T, l layout, out []byte, err error) (int, supervisor.Summary, string) {
	t.Helper()
	code := 0
	var exit *exec.ExitError
	if err != nil {
		require.ErrorAs(t, err, &exit, string(out))
		code = exit.ExitCode()
	}
	var summary supervisor.Summary
	raw, rerr := os.ReadFile(l.termination)
	if rerr == nil {
		require.NoError(t, json.Unmarshal(raw, &summary), string(raw))
	}
	return code, summary, string(out)
}

func readEvidence(t *testing.T, l layout) supervisor.Evidence {
	t.Helper()
	var evidence supervisor.Evidence
	raw, err := os.ReadFile(filepath.Join(l.verdict, "evidence.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &evidence))
	return evidence
}

func scopeFor(deadline time.Time) map[string]any {
	return map[string]any{"tenantId": "tenant_a", "operationId": "op_1", "attemptId": "att_1", "instanceId": "inst_1", "current": true, "profileId": "harness-wiring-dev-v1", "executionEpoch": "1", "launchKey": "cg-test", "deadline": deadline.UTC().Format(time.RFC3339)}
}

// The complete trusted flow: the candidate runs as UID 10001 with an empty
// identity, produces the fixed result, the observer certifies it from the
// bytes, the finalizer uploads result and evidence and submits the manifest
// twice (the second reenters). The candidate's probe report shows the
// boundary it observed on this host.
func TestTrustedFlowWithFixedCandidate(t *testing.T) {
	l := prepare(t)
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_1"}
	fs.serve(t, l.sockets)
	code, summary, log := supervise(t, l, envelopeFor(deadline))
	require.Equal(t, 0, code, log)
	require.Equal(t, "completed", summary.Outcome, log)
	require.Equal(t, "certified", summary.Verdict)
	require.Equal(t, "stg_1", summary.StageID)
	require.NotNil(t, summary.Duplicate)
	require.True(t, summary.Duplicate.Existing && summary.Duplicate.SameStage, "the second submission reentered the stage")
	require.NotNil(t, summary.CandidateExit)
	require.Equal(t, 0, *summary.CandidateExit)
	require.Equal(t, "exited", summary.CandidateStop)

	// The observer's expectation was computed from the envelope, and the
	// candidate's bytes matched it.
	env, err := launch.Parse([]byte(envelopeFor(deadline)))
	require.NoError(t, err)
	expected := supervisor.ExpectedResult(env.Inputs)
	require.Len(t, fs.transfers, 2)
	require.Equal(t, "result", fs.transfers[0]["class"])
	require.Equal(t, string(expected), fs.transfers[0]["body"])
	require.Equal(t, "evidence", fs.transfers[1]["class"])
	require.Len(t, fs.manifests, 2)
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(fs.manifests[0], &manifest))
	require.Equal(t, "certified", manifest["verdict"])
	require.Equal(t, "lch_1", manifest["launchId"])
	require.Equal(t, "codegen", manifest["jobKind"])
	outputs := manifest["outputs"].([]any)
	require.Len(t, outputs, 2)
	require.Equal(t, "hdl_1", outputs[0].(map[string]any)["handle"])
	require.Equal(t, launch.Digest(expected), outputs[0].(map[string]any)["digest"])

	// The candidate wrote into its own tree only; the verdict tree holds
	// the trusted snapshot, verdict and evidence, unreadable by 10001.
	st, err := os.Stat(l.verdict)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), st.Mode().Perm())
	for _, name := range []string{"snapshot/result.txt", "snapshot/probes.json", "verdict.json", "evidence.json", "manifest.json", "candidate.log"} {
		_, err := os.Stat(filepath.Join(l.verdict, name))
		require.NoError(t, err, name)
	}
	wst, err := os.Stat(filepath.Join(l.workspace, "w", "output", "result.txt"))
	require.NoError(t, err)
	require.Equal(t, uint32(candidateUID), wst.Sys().(*syscall.Stat_t).Uid, "the candidate wrote as 10001")

	// What the candidate observed from inside its identity.
	evidence := readEvidence(t, l)
	require.True(t, evidence.ResourcesIntact, "planted AGENTS.md/.pi/SYSTEM.md/skills changed nothing the harness loads")
	require.Equal(t, "exited", evidence.CandidateStop)
	require.Equal(t, 0, evidence.DescendantsStopped, "the fixed candidate leaves nothing behind")
	var probes struct {
		Outcomes map[string]string `json:"outcomes"`
		Identity map[string]any    `json:"identity"`
	}
	require.NoError(t, json.Unmarshal(evidence.Probes, &probes))
	o := probes.Outcomes
	require.Equal(t, "true", o["capabilities-empty"], "%v", o)
	require.Equal(t, "1", o["no-new-privs"])
	require.Equal(t, "true", o["groups-empty"])
	require.Equal(t, "10001\t10001\t10001\t10001", strings.ReplaceAll(o["uid"], "    ", "\t"))
	var detail struct {
		Detail map[string]string `json:"detail"`
	}
	_ = json.Unmarshal(evidence.Probes, &detail)
	require.Equal(t, "0", o["inherited-fds"], "foreign descriptors: %s", detail.Detail["inherited-fds"])
	require.Equal(t, "EPERM", o["setuid-0"])
	require.Equal(t, "EACCES", o["read:verdict.json"], "the verdict tree is closed")
	require.Equal(t, "EACCES", o["read:resources.json"], "trusted resources are protected")
	require.Equal(t, "EACCES", o["read:fixed-input.txt"], "protected fixtures are unreadable; only the staged copy is")
	require.Equal(t, "EACCES", o["read:environ"], "the supervisor's environment (the envelope) is unreadable")
	require.Equal(t, "EACCES", o["write:manifest.json"], "a forged manifest cannot be written")
	require.Equal(t, "EACCES", o["write:AGENTS.md"])
	require.Equal(t, "EACCES", o["write:fixed-input"], "staged inputs are read-only")
	require.Equal(t, "EACCES", o["connect:trusted.sock"], "the trusted socket is not reachable")
	require.Equal(t, "200 ", o["candidate:inputs-permitted"])
	require.Equal(t, "404 NOT_FOUND", o["candidate:inputs-other"])
	require.Equal(t, "403 ROUTE_FORBIDDEN", o["candidate:results"])
	require.Equal(t, "403 ROUTE_FORBIDDEN", o["candidate:scope"])
	require.Equal(t, "503 DEPENDENCY_UNAVAILABLE", o["candidate:model-relay"])
	require.Equal(t, "CREATED", o["socket:af-unix"])
	// Without a syscall profile the host allows AF_INET/AF_INET6 sockets;
	// the report records that as observed (the seccomp profile of the Job
	// template and the gVisor qualification cover it), it is not asserted.
	t.Logf("network probes on this host: af-inet=%s af-inet6=%s connect=%v", o["socket:af-inet"], o["socket:af-inet6"], o["connect:127.0.0.1:9"])
	for _, planted := range []string{"AGENTS.md", "SYSTEM.md", ".pi/settings.json", "skills/evil/SKILL.md"} {
		require.Equal(t, "WRITTEN", o["plant:"+planted])
	}
}

// Without authority nothing runs: a scope answered NO_AUTHORITY (a
// duplicate Pod) leaves the candidate unexecuted and the flow failed.
func TestNoAuthorityRunsNothing(t *testing.T) {
	l := prepare(t)
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), scopeCode: 403, scopeFail: "NO_AUTHORITY", inputs: map[string][]byte{}, stageID: "stg_x"}
	fs.serve(t, l.sockets)
	code, summary, log := supervise(t, l, envelopeFor(deadline))
	require.Equal(t, 1, code, log)
	require.Equal(t, "infrastructure_failed", summary.Outcome)
	require.Contains(t, summary.Error, "NO_AUTHORITY")
	require.Nil(t, summary.CandidateExit, "the candidate never started")
	_, err := os.Stat(filepath.Join(l.workspace, "w"))
	require.True(t, os.IsNotExist(err), "no candidate tree exists")
	require.Empty(t, fs.transfers)
	require.Empty(t, fs.manifests)
}

// A scope that names another attempt than the envelope is refused before
// any input is staged.
func TestScopeMustMatchTheEnvelope(t *testing.T) {
	l := prepare(t)
	deadline := time.Now().Add(10 * time.Minute)
	scope := scopeFor(deadline)
	scope["attemptId"] = "att_other"
	fs := &fakeSidecar{scope: scope, inputs: map[string][]byte{}, stageID: "stg_x"}
	fs.serve(t, l.sockets)
	code, summary, _ := supervise(t, l, envelopeFor(deadline))
	require.Equal(t, 1, code)
	require.Contains(t, summary.Error, "does not match the launch envelope")
	require.Empty(t, fs.inputs)
}

// A protected input whose bytes do not hash to the envelope's digest is
// refused: typed inputs are bound to digests.
func TestProtectedInputMustMatchTheEnvelopeDigest(t *testing.T) {
	l := prepare(t)
	require.NoError(t, os.WriteFile(filepath.Join(l.fixtures, "fixed-input.txt"), []byte("tampered\n"), 0o600))
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_x"}
	fs.serve(t, l.sockets)
	code, summary, _ := supervise(t, l, envelopeFor(deadline))
	require.Equal(t, 1, code)
	require.Contains(t, summary.Error, "the envelope binds")
	require.Nil(t, summary.CandidateExit)
}

// A trusted resource directory the candidate could write to is refused.
func TestWritableAgentDirIsRefused(t *testing.T) {
	l := prepare(t)
	require.NoError(t, os.Chmod(l.agent, 0o777))
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_x"}
	fs.serve(t, l.sockets)
	code, summary, _ := supervise(t, l, envelopeFor(deadline))
	require.Equal(t, 1, code)
	require.Contains(t, summary.Error, "writable by group or others")
}

// A supervisor that does not hold exactly the reviewed capability set
// executes nothing: started directly by the root test (every capability,
// no supervisor-exec) it refuses before the candidate exists.
func TestPrivilegeDropFailureDeniesExecution(t *testing.T) {
	l := prepare(t)
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_x"}
	fs.serve(t, l.sockets)
	cmd := exec.Command(l.helper)
	cmd.Env = []string{"HARNESS_HELPER=supervise", "ANVILKIT_CODEGEN_CONFIG=" + l.cfg, "ANVILKIT_LAUNCH_ID=lch_1", "ANVILKIT_ATTEMPT_ID=att_1", "ANVILKIT_LAUNCH_ENVELOPE=" + envelopeFor(deadline), "PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit, string(out))
	require.Equal(t, 1, exit.ExitCode())
	require.Contains(t, string(out), "outside the reviewed set", "a root caller with every capability is not the reviewed supervisor")
	_, err = os.Stat(filepath.Join(l.workspace, "w"))
	require.True(t, os.IsNotExist(err))
}

// supervisor-exec constrains the whole process, not one thread: every
// thread of the started program holds exactly SETUID, SETGID and SETPCAP
// in its permitted, effective and bounding sets, nothing inheritable or
// ambient, and no_new_privs. Without CAP_KILL on any thread, nothing in
// the supervisor can signal the candidate directly.
func TestSupervisorExecConstrainsEveryThread(t *testing.T) {
	l := prepare(t)
	cmd := exec.Command(l.helper, process.SupervisorExecCommand, "--", l.helper)
	cmd.Env = []string{"HARNESS_HELPER=threads"}
	out, err := cmd.Output()
	require.NoError(t, err, string(out))
	var threads []threadStatus
	require.NoError(t, json.Unmarshal(out, &threads), string(out))
	require.GreaterOrEqual(t, len(threads), 4, "several threads exist")
	const reviewed = uint64(1<<6 | 1<<7 | 1<<8) // SETGID, SETUID, SETPCAP
	for _, th := range threads {
		require.Equal(t, reviewed, th.CapEff, "thread %s effective", th.TID)
		require.Equal(t, reviewed, th.CapPrm, "thread %s permitted", th.TID)
		require.Equal(t, reviewed, th.CapBnd, "thread %s bounding", th.TID)
		require.Zero(t, th.CapInh|th.CapAmb, "thread %s inheritable/ambient", th.TID)
		require.Equal(t, 1, th.NoNewPrivs, "thread %s no_new_privs", th.TID)
	}
}

// A candidate that outlives its bound is stopped: the leader and its
// descendants in a new session, a new process group and its own group are
// all gone before the observer reads the workspace, the run is reported
// as stopped at its bound and the bytes it left behind do not certify it.
func TestCandidateBoundStopsEveryDescendant(t *testing.T) {
	l := prepare(t)
	writeConfig(t, l, "2s")
	misbehavingCandidate(t, l, "hang")
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_t"}
	fs.serve(t, l.sockets)
	started := time.Now()
	code, summary, log := supervise(t, l, envelopeFor(deadline))
	require.Less(t, time.Since(started), 30*time.Second, "the stop is bounded")
	require.Equal(t, 0, code, log)
	require.Equal(t, "completed", summary.Outcome, log)
	require.Equal(t, "invalid", summary.Verdict)
	require.Equal(t, "DEADLINE_EXCEEDED", summary.FailureCode, "bytes left by a stopped candidate certify nothing")
	require.Equal(t, "timeout", summary.CandidateStop)
	require.Nil(t, summary.CandidateExit, "the leader was killed, it did not exit")
	requireGone(t, recordedPIDs(t, l))
	evidence := readEvidence(t, l)
	require.Equal(t, "timeout", evidence.CandidateStop)
	require.Equal(t, "killed", evidence.CandidateSignal)
	require.GreaterOrEqual(t, evidence.DescendantsStopped, 2, "the descendants in a new session and a new group escaped the group kill and were found on the parent chain")
	require.Contains(t, evidence.OutputFiles, "result.txt", "the observer still snapshots what was left, as evidence")
	require.Len(t, fs.manifests, 2, "the invalid verdict is submitted with the evidence")
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(fs.manifests[0], &manifest))
	require.Equal(t, "invalid", manifest["verdict"])
	require.Equal(t, "DEADLINE_EXCEEDED", manifest["failureCode"])
}

// A leader that exits before its descendants does not end candidate
// execution: the descendants are stopped and confirmed gone before the
// observer starts; the result the leader wrote is certified from the
// bytes as usual.
func TestLeaderExitLeavesNoDescendantBehind(t *testing.T) {
	l := prepare(t)
	misbehavingCandidate(t, l, "exit")
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_e"}
	fs.serve(t, l.sockets)
	code, summary, log := supervise(t, l, envelopeFor(deadline))
	require.Equal(t, 0, code, log)
	require.Equal(t, "completed", summary.Outcome, log)
	require.Equal(t, "certified", summary.Verdict)
	require.Equal(t, "exited", summary.CandidateStop)
	require.NotNil(t, summary.CandidateExit)
	require.Equal(t, 0, *summary.CandidateExit)
	requireGone(t, recordedPIDs(t, l))
	evidence := readEvidence(t, l)
	require.GreaterOrEqual(t, evidence.DescendantsStopped, 2, "descendants outside the leader's group were stopped")
}

// A canceled launch (SIGTERM to the supervisor, as the kubelet sends on
// Pod deletion) stops the candidate and its descendants, confirms it, and
// ends without a verdict or a submission.
func TestCancellationStopsTheCandidate(t *testing.T) {
	l := prepare(t)
	misbehavingCandidate(t, l, "hang")
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_c"}
	fs.serve(t, l.sockets)
	cmd := supervisorCommand(l, envelopeFor(deadline))
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	require.NoError(t, cmd.Start())
	require.Eventually(t, func() bool {
		_, err := os.Stat(filepath.Join(l.workspace, "w", "pids"))
		return err == nil
	}, 30*time.Second, 50*time.Millisecond, "the candidate started")
	pids := recordedPIDs(t, l)
	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	err := cmd.Wait()
	code, summary, log := supervised(t, l, []byte(out.String()), err)
	require.Equal(t, 1, code, log)
	require.Equal(t, "canceled", summary.Outcome, log)
	require.Contains(t, summary.Error, "launch canceled")
	require.Equal(t, "canceled", summary.CandidateStop)
	require.Empty(t, summary.Verdict, "no verdict")
	require.Empty(t, summary.StageID)
	requireGone(t, pids)
	require.Empty(t, fs.transfers, "nothing uploaded")
	require.Empty(t, fs.manifests, "nothing submitted")
	_, err = os.Stat(filepath.Join(l.verdict, "verdict.json"))
	require.True(t, os.IsNotExist(err), "no verdict was written")
	evidence := readEvidence(t, l)
	require.Equal(t, "canceled", evidence.CandidateStop)
	require.GreaterOrEqual(t, evidence.DescendantsStopped, 2)
}

// Even a normally exited candidate with valid output cannot reach the
// observer if the trusted stop helper failed to establish containment.
func TestUnconfirmedStopNeverObservesOrSubmits(t *testing.T) {
	l := prepare(t)
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_1"}
	fs.serve(t, l.sockets)
	require.NoError(t, os.WriteFile(filepath.Join(l.root, "deny-stop"), nil, 0o444))
	code, summary, log := supervise(t, l, envelopeFor(deadline))
	require.Equal(t, 1, code, log)
	require.Equal(t, "infrastructure_failed", summary.Outcome)
	require.Contains(t, summary.Error, "candidate stop not established")
	require.Empty(t, summary.Verdict)
	require.Empty(t, summary.StageID)
	require.NoDirExists(t, filepath.Join(l.verdict, "snapshot"))
	require.NoFileExists(t, filepath.Join(l.verdict, "verdict.json"))
	fs.mu.Lock()
	defer fs.mu.Unlock()
	require.Empty(t, fs.transfers)
	require.Empty(t, fs.manifests)
}

// teamLayout adds the team mode to the layout: a coordinator that asks for
// one candidate round, records the answer and exits, and a coder that
// records its PID and writes a heartbeat line every 100 ms until it is
// stopped. Both are shell scripts (the real
// programs are the team package's); the reviewed programs, identities,
// bounds and environment stay the supervisor's.
func teamLayout(t *testing.T, l layout, teamTimeout, candidateTimeout string) {
	t.Helper()
	coordinator := filepath.Join(l.root, "coordinator.sh")
	coder := filepath.Join(l.root, "coder.sh")
	teamConfig := filepath.Join(l.root, "team.yaml")
	require.NoError(t, os.WriteFile(coordinator, []byte("#!/bin/sh\numask 022\nmkdir -p \"$ANVILKIT_WORKSPACE/round/1\"\nprintf '{\"type\":\"run-candidate\",\"protocolVersion\":1,\"requestId\":1,\"round\":1,\"roundDir\":\"%s/round/1\"}\\n' \"$ANVILKIT_WORKSPACE\"\nread answer\nprintf '%s\\n' \"$answer\" > \"$ANVILKIT_VERDICT_DIR/team/answer.json\"\nexit 0\n"), 0o755))
	require.NoError(t, os.WriteFile(coder, []byte("#!/bin/sh\nmkdir -p \"$ANVILKIT_WORKSPACE/w\"\necho $$ > \"$ANVILKIT_WORKSPACE/w/pid\"\nwhile true; do date +%s%N >> \"$ANVILKIT_WORKSPACE/w/heartbeat\"; sleep 0.1; done\n"), 0o755))
	require.NoError(t, os.WriteFile(teamConfig, []byte("schemaVersion: 1\n"), 0o600))
	require.NoError(t, os.WriteFile(l.cfg, []byte(fmt.Sprintf("paths:\n  workspace: %s\n  verdict: %s\n  sockets: %s\n  agent_dir: %s\n  fixtures: %s\n  termination_log: %s\ncandidate:\n  program: %s\n  timeout: %s\nsidecar:\n  wait: 10s\nteam:\n  enabled: true\n  coordinator: [%s]\n  coder: [%s]\n  config: %s\n  contracts_dir: %s\n  timeout: %s\n  observer: anvilkit-codegen-team\n", l.workspace, l.verdict, l.sockets, l.agent, l.fixtures, l.termination, l.candidate, candidateTimeout, coordinator, coder, teamConfig, l.root, teamTimeout)), 0o600))
}

// heartbeatBounds reads the coder's heartbeat file: the number of lines and
// the last timestamp it wrote.
func heartbeatBounds(t *testing.T, l layout) (int, time.Time) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(l.workspace, "w", "heartbeat"))
	require.NoError(t, err)
	lines := strings.Fields(string(raw))
	require.NotEmpty(t, lines, "the coder wrote at least one heartbeat")
	last, err := strconv.ParseInt(lines[len(lines)-1], 10, 64)
	require.NoError(t, err)
	return len(lines), time.Unix(0, last)
}

// The team's bound ends the candidate round with it: with a one-second team
// bound and a five-second candidate bound, the coder is stopped and
// confirmed gone through the same stop path as at its own bound, well
// before the candidate bound; nothing is certified or submitted, and the
// candidate's stop is reported as at the bound it actually hit.
func TestTeamBoundStopsTheCandidateRound(t *testing.T) {
	l := prepare(t)
	teamLayout(t, l, "1s", "5s")
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_team"}
	fs.serve(t, l.sockets)
	started := time.Now()
	code, summary, log := supervise(t, l, envelopeFor(deadline))
	ended := time.Now()
	require.Equal(t, 1, code, log)
	require.Equal(t, "infrastructure_failed", summary.Outcome, log)
	require.Contains(t, summary.Error, "coordinator exited")
	require.Equal(t, "timeout", summary.CandidateStop, "the team bound stopped the round as a bound")
	require.Empty(t, summary.StageID)
	require.Empty(t, summary.Verdict)
	require.Empty(t, fs.manifests, "nothing submitted")
	// The coder could not still be writing at second three: its last heartbeat
	// is before that, and the round ended before the candidate's own bound.
	beats, last := heartbeatBounds(t, l)
	require.Less(t, last.Sub(started), 3*time.Second, "last heartbeat at %s after the start (%d beats)", last.Sub(started), beats)
	require.Less(t, ended.Sub(started), 5*time.Second, "the run ended before the candidate's own bound")
	raw, err := os.ReadFile(filepath.Join(l.workspace, "w", "pid"))
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	requireGone(t, []int{pid})
	// Nothing keeps writing after the run: the heartbeat file is unchanged a moment later.
	time.Sleep(300 * time.Millisecond)
	beatsAfter, _ := heartbeatBounds(t, l)
	require.Equal(t, beats, beatsAfter)
}

// A normal team round: the coder ends on its own, the supervisor confirms
// the stop and answers the coordinator with the candidate's end, and the
// coordinator's own exit ends the team. Here the coordinator exits 0 without
// an accepted stage, which is an infrastructure failure, never "completed".
func TestTeamRoundCompletesAndCoordinatorExitEndsTheTeam(t *testing.T) {
	l := prepare(t)
	teamLayout(t, l, "30s", "30s")
	// A coder that ends by itself after a few heartbeats.
	require.NoError(t, os.WriteFile(filepath.Join(l.root, "coder.sh"), []byte("#!/bin/sh\nmkdir -p \"$ANVILKIT_WORKSPACE/w\"\necho $$ > \"$ANVILKIT_WORKSPACE/w/pid\"\nfor i in 1 2 3; do date +%s%N >> \"$ANVILKIT_WORKSPACE/w/heartbeat\"; sleep 0.1; done\nexit 0\n"), 0o755))
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_team"}
	fs.serve(t, l.sockets)
	code, summary, log := supervise(t, l, envelopeFor(deadline))
	require.Equal(t, 1, code, log)
	require.Equal(t, "infrastructure_failed", summary.Outcome, log)
	require.Contains(t, summary.Error, "coordinator exited 0 without a result")
	require.Equal(t, "exited", summary.CandidateStop)
	require.NotNil(t, summary.CandidateExit)
	require.Equal(t, 0, *summary.CandidateExit)
	raw, err := os.ReadFile(filepath.Join(l.verdict, "team", "answer.json"))
	require.NoError(t, err)
	var answer struct {
		Type string `json:"type"`
		Stop string `json:"stop"`
		Exit *int   `json:"exit"`
	}
	require.NoError(t, json.Unmarshal(raw, &answer), string(raw))
	require.Equal(t, "candidate-ended", answer.Type)
	require.Equal(t, "exited", answer.Stop)
	require.NotNil(t, answer.Exit)
	beats, _ := heartbeatBounds(t, l)
	require.Equal(t, 3, beats)
}

// A candidate round whose stop cannot be established fails the launch: the
// coordinator is refused, nothing is reported stopped and nothing is
// completed — also when the team's bound is what ends the round.
func TestTeamUnconfirmedStopFailsTheLaunch(t *testing.T) {
	l := prepare(t)
	teamLayout(t, l, "1s", "5s")
	require.NoError(t, os.WriteFile(filepath.Join(l.root, "deny-stop"), nil, 0o444))
	// The coder this test makes unstoppable for the supervisor is the test's
	// to remove (the root test process can signal it; in a Pod the
	// container's end does).
	t.Cleanup(func() {
		if raw, err := os.ReadFile(filepath.Join(l.workspace, "w", "pid")); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_team"}
	fs.serve(t, l.sockets)
	code, summary, log := supervise(t, l, envelopeFor(deadline))
	require.Equal(t, 1, code, log)
	require.Equal(t, "infrastructure_failed", summary.Outcome, log)
	require.Contains(t, summary.Error, "candidate stop not established")
	require.Empty(t, summary.CandidateStop, "an unestablished stop is not a stopped candidate")
	raw, err := os.ReadFile(filepath.Join(l.workspace, "w", "pid"))
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	require.NoError(t, syscall.Kill(pid, 0), "the coder the stop could not reach is still alive: the failure reported exactly that")
	require.Empty(t, summary.StageID)
	require.Empty(t, fs.manifests)
}
