package privdrop_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/privdrop"
)

type reportOut struct {
	Status privdrop.Status `json:"status"`
	FDs    map[int]string  `json:"fds"`
	Cwd    string          `json:"cwd"`
}

// TestMain doubles as the helper processes: "report" prints the kernel's
// view of the process (it is what the trampoline executes as the
// candidate), "trampoline" restricts itself to the supervisor set and
// performs the drop, "trampoline-noroot" attempts the drop without root.
func TestMain(m *testing.M) {
	switch os.Getenv("PRIVDROP_HELPER") {
	case "report":
		st, err := privdrop.ReadStatus()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fds := map[int]string{}
		for _, fd := range privdrop.ForeignFDs() {
			fds[fd.FD] = fd.Target
		}
		cwd, _ := os.Getwd()
		_ = json.NewEncoder(os.Stdout).Encode(reportOut{Status: st, FDs: fds, Cwd: cwd})
		os.Exit(0)
	case "trampoline", "trampoline-noroot", "trampoline-ls":
		if os.Getenv("PRIVDROP_HELPER") != "trampoline-noroot" {
			if err := privdrop.RestrictToSupervisorSet(); err != nil {
				fmt.Fprintln(os.Stderr, "restrict:", err)
				os.Exit(3)
			}
		}
		target := privdrop.Target{UID: 10001, GID: 10001, Dir: os.Getenv("PRIVDROP_DIR"), Program: os.Getenv("PRIVDROP_PROGRAM"), Env: []string{"PRIVDROP_HELPER=report"}}
		if os.Getenv("PRIVDROP_HELPER") == "trampoline-ls" {
			// A non-Go candidate: what it lists is exactly what it inherited.
			target = privdrop.Target{UID: 10001, GID: 10001, Dir: os.Getenv("PRIVDROP_DIR"), Program: "/bin/sh", Args: []string{"-c", "exec ls -l /proc/self/fd"}, Env: []string{"PATH=/usr/bin:/bin"}}
		}
		err := privdrop.Exec(target)
		fmt.Fprintln(os.Stderr, "refused:", err)
		os.Exit(111)
	}
	os.Exit(m.Run())
}

// worldDir returns a directory the candidate UID can traverse and a copy
// of the test binary it can execute: go test's build directory is 0700.
func worldDir(t *testing.T) (string, string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "privdrop-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	require.NoError(t, os.Chmod(dir, 0o755))
	self, err := os.Executable()
	require.NoError(t, err)
	raw, err := os.ReadFile(self)
	require.NoError(t, err)
	program := filepath.Join(dir, "helper")
	require.NoError(t, os.WriteFile(program, raw, 0o755))
	return dir, program
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		if os.Getenv("ANVILKIT_REQUIRE_ROOT_TESTS") != "" {
			t.Fatal("ANVILKIT_REQUIRE_ROOT_TESTS is set: the privilege drop tests must run as root")
		}
		t.Skip("the privilege drop needs a root caller (the supervisor's identity)")
	}
}

// As root with the supervisor set, the trampoline hands the candidate a
// fully dropped identity: every UID and GID 10001, no supplementary group,
// every capability set empty, no_new_privs set, only descriptors 0-2 open
// (an inherited descriptor is closed), the workspace as working directory.
func TestDropToCandidateIdentity(t *testing.T) {
	requireRoot(t)
	dir, program := worldDir(t)
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	cmd := exec.Command(program)
	cmd.Env = []string{"PRIVDROP_HELPER=trampoline", "PRIVDROP_DIR=" + dir, "PRIVDROP_PROGRAM=" + program}
	cmd.ExtraFiles = []*os.File{w} // fd 3 in the child: must not reach the candidate
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(t, cmd.Run(), stderr.String())
	w.Close()
	var rep reportOut
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &rep), stdout.String())
	require.Equal(t, [4]uint32{10001, 10001, 10001, 10001}, rep.Status.UIDs)
	require.Equal(t, [4]uint32{10001, 10001, 10001, 10001}, rep.Status.GIDs)
	require.Empty(t, rep.Status.Groups, "supplementary groups cleared")
	require.Zero(t, rep.Status.CapInh|rep.Status.CapPrm|rep.Status.CapEff|rep.Status.CapBnd|rep.Status.CapAmb, "every capability set empty, including bounding")
	require.Equal(t, 1, rep.Status.NoNewPrivs)
	// The candidate's own runtime may create anonymous descriptors after
	// the exec (epoll, eventfd); nothing inherited may exist: no pipe, no
	// socket, no file. The pipe the test passed as fd 3 must be gone.
	for fd, target := range rep.FDs {
		require.LessOrEqual(t, fd, 2, "descriptor %d (%s) reached the candidate", fd, target)
	}
	require.Equal(t, dir, rep.Cwd)
	_, err = io.ReadAll(r)
	require.NoError(t, err)

	// The strict descriptor check uses a non-Go candidate (ls), whose only
	// descriptors are 0-2 and the directory it lists: the pipe passed as
	// fd 3 must not appear.
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available for the ls probe")
	}
	r2, w2, err := os.Pipe()
	require.NoError(t, err)
	defer r2.Close()
	cmd = exec.Command(program)
	cmd.Env = []string{"PRIVDROP_HELPER=trampoline-ls", "PRIVDROP_DIR=" + dir}
	cmd.ExtraFiles = []*os.File{w2}
	stdout.Reset()
	stderr.Reset()
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(t, cmd.Run(), stderr.String())
	w2.Close()
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || strings.HasPrefix(line, "total") {
			continue
		}
		name, target := fields[len(fields)-3], fields[len(fields)-1]
		switch name {
		case "0", "1", "2":
		default:
			require.True(t, strings.HasSuffix(target, "/fd"), "descriptor %s -> %s reached the candidate (ls output: %s)", name, target, stdout.String())
		}
	}
}

// Without root the drop cannot be performed and the candidate program is
// never executed: the trampoline exits with its refusal code and nothing
// was printed by the program.
func TestDropRefusedWithoutRoot(t *testing.T) {
	requireRoot(t)
	dir, program := worldDir(t)
	cmd := exec.Command(program)
	cmd.Env = []string{"PRIVDROP_HELPER=trampoline-noroot", "PRIVDROP_DIR=" + dir, "PRIVDROP_PROGRAM=" + program}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, 111, exit.ExitCode())
	require.Contains(t, stderr.String(), "refused")
	require.Empty(t, stdout.String(), "the candidate program did not run")
}

// A supervisor holding more than the reviewed set is refused: the drop
// does not start from an over-privileged identity.
func TestSupervisorSetIsExact(t *testing.T) {
	requireRoot(t)
	err := privdrop.CheckSupervisor()
	require.Error(t, err, "a root test process holds every capability, outside the reviewed set")
	require.Contains(t, err.Error(), "outside the reviewed set")
}

func TestRootTargetRefused(t *testing.T) {
	err := privdrop.Exec(privdrop.Target{UID: 0, GID: 10001, Program: "/bin/true"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "must not run as root")
}

func TestVerifyCandidateRules(t *testing.T) {
	ok := privdrop.Status{UIDs: [4]uint32{10001, 10001, 10001, 10001}, GIDs: [4]uint32{10001, 10001, 10001, 10001}, NoNewPrivs: 1}
	require.NoError(t, privdrop.VerifyCandidate(ok, 10001, 10001))
	bad := ok
	bad.CapBnd = 1 << 7
	require.ErrorContains(t, privdrop.VerifyCandidate(bad, 10001, 10001), "capability sets not empty")
	bad = ok
	bad.Groups = []uint32{0}
	require.ErrorContains(t, privdrop.VerifyCandidate(bad, 10001, 10001), "supplementary groups")
	bad = ok
	bad.NoNewPrivs = 0
	require.ErrorContains(t, privdrop.VerifyCandidate(bad, 10001, 10001), "no_new_privs")
	bad = ok
	bad.UIDs[2] = 0
	require.True(t, strings.Contains(privdrop.VerifyCandidate(bad, 10001, 10001).Error(), "identity"))
}
