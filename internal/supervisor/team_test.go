package supervisor_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The team flow's process protocol with shell coordinators: what the
// supervisor does with a candidate round when the launch is canceled, when
// the coordinator dies mid-round, when the candidate leaves descendants in
// other sessions and groups, and when the coordinator leaves the protocol.

// coordinatorScript installs a coordinator shell script (the supervisor runs
// it with its own identity) after the common team layout.
func coordinatorScript(t *testing.T, l layout, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(l.root, "coordinator.sh"), []byte("#!/bin/sh\numask 022\n"+body), 0o755))
}

// request is one run-candidate line as the coordinator script prints it.
func request(id, round int, dir string) string {
	return fmt.Sprintf(`printf '{"type":"run-candidate","protocolVersion":1,"requestId":%d,"round":%d,"roundDir":"%%s"}\n' "%s"`+"\n", id, round, dir)
}

func readAnswers(t *testing.T, l layout) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(l.verdict, "team", "answers"))
	require.NoError(t, err)
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var a map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &a), line)
		out = append(out, a)
	}
	return out
}

func pidOf(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	return pid
}

// A canceled launch (SIGTERM, as on Pod deletion) while a team round runs:
// the round is stopped and confirmed, the coordinator is stopped, nothing
// is certified or submitted, and the coder writes nothing afterwards.
func TestTeamCancellationStopsTheRound(t *testing.T) {
	l := prepare(t)
	teamLayout(t, l, "60s", "60s")
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_c"}
	fs.serve(t, l.sockets)
	cmd := supervisorCommand(l, envelopeFor(deadline))
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	require.NoError(t, cmd.Start())
	require.Eventually(t, func() bool {
		_, err := os.Stat(filepath.Join(l.workspace, "w", "heartbeat"))
		return err == nil
	}, 30*time.Second, 50*time.Millisecond, "the coder started")
	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	err := cmd.Wait()
	code, summary, log := supervised(t, l, []byte(out.String()), err)
	require.Equal(t, 1, code, log)
	require.Equal(t, "canceled", summary.Outcome, log)
	require.Equal(t, "canceled", summary.CandidateStop, "the round ended by the cancellation")
	require.Empty(t, summary.StageID)
	require.Empty(t, fs.manifests, "nothing submitted")
	requireGone(t, []int{pidOf(t, filepath.Join(l.workspace, "w", "pid"))})
	beats, _ := heartbeatBounds(t, l)
	time.Sleep(300 * time.Millisecond)
	after, _ := heartbeatBounds(t, l)
	require.Equal(t, beats, after, "nothing of the candidate writes after the launch ended")
}

// A coordinator that dies while its round runs (killed, no answer read):
// the round is stopped through the same path as at its bound, nothing of
// the candidate keeps writing, and the launch fails.
func TestCoordinatorDeathStopsTheRound(t *testing.T) {
	l := prepare(t)
	teamLayout(t, l, "60s", "60s")
	coordinatorScript(t, l, "mkdir -p \"$ANVILKIT_WORKSPACE/round/1\"\n"+request(1, 1, "$ANVILKIT_WORKSPACE/round/1")+
		"while [ ! -f \"$ANVILKIT_WORKSPACE/w/heartbeat\" ]; do sleep 0.05; done\nkill -9 $$\n")
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_d"}
	fs.serve(t, l.sockets)
	started := time.Now()
	code, summary, log := supervise(t, l, envelopeFor(deadline))
	require.Less(t, time.Since(started), 30*time.Second, "the round did not run to its own bound")
	require.Equal(t, 1, code, log)
	require.Equal(t, "infrastructure_failed", summary.Outcome, log)
	require.Contains(t, summary.Error, "coordinator exited")
	require.Equal(t, "canceled", summary.CandidateStop, "the coordinator's end stopped the round")
	require.Empty(t, fs.manifests)
	requireGone(t, []int{pidOf(t, filepath.Join(l.workspace, "w", "pid"))})
	beats, _ := heartbeatBounds(t, l)
	time.Sleep(300 * time.Millisecond)
	after, _ := heartbeatBounds(t, l)
	require.Equal(t, beats, after)
}

// A coder that leaves descendants in a new session, a new process group
// and its own group and exits: before the supervisor answers, every one of
// them is stopped and gone — the coordinator checks from its side, as root,
// the moment it reads the answer.
func TestTeamRoundDescendantsAreGoneBeforeTheAnswer(t *testing.T) {
	l := prepare(t)
	teamLayout(t, l, "60s", "60s")
	require.NoError(t, os.WriteFile(filepath.Join(l.root, "coder.sh"), []byte("#!/bin/sh\nmkdir -p \"$ANVILKIT_WORKSPACE/w\"\nHARNESS_HELPER=misbehave HARNESS_MODE=exit exec "+l.helper+"\n"), 0o755))
	coordinatorScript(t, l, "mkdir -p \"$ANVILKIT_WORKSPACE/round/1\"\n"+request(1, 1, "$ANVILKIT_WORKSPACE/round/1")+
		"read answer\nprintf '%s\\n' \"$answer\" >> \"$ANVILKIT_VERDICT_DIR/team/answers\"\n"+
		"alive=0\nfor p in $(cat \"$ANVILKIT_WORKSPACE/w/pids\"); do if [ -e /proc/$p ] && ! grep -q '^State:.*Z' /proc/$p/status 2>/dev/null; then alive=$((alive+1)); fi; done\n"+
		"echo $alive > \"$ANVILKIT_VERDICT_DIR/team/alive\"\nexit 0\n")
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_e"}
	fs.serve(t, l.sockets)
	code, summary, log := supervise(t, l, envelopeFor(deadline))
	require.Equal(t, 1, code, log)
	require.Contains(t, summary.Error, "without a result", "the shell coordinator seals nothing")
	answers := readAnswers(t, l)
	require.Len(t, answers, 1)
	require.Equal(t, "candidate-ended", answers[0]["type"])
	require.Equal(t, "exited", answers[0]["stop"])
	require.GreaterOrEqual(t, answers[0]["descendantsStopped"], float64(2), "the descendants outside the leader's group were found on the parent chain")
	alive, err := os.ReadFile(filepath.Join(l.verdict, "team", "alive"))
	require.NoError(t, err)
	require.Equal(t, "0", strings.TrimSpace(string(alive)), "no recorded candidate process was alive when the answer arrived")
	requireGone(t, recordedPIDs(t, l))
}

// The protocol's request rules: a round that is not new and a directory
// that is not the workspace's real round directory are refused without a
// candidate; a planted link is never a round directory.
func TestTeamRefusesStaleRoundsAndForeignDirectories(t *testing.T) {
	l := prepare(t)
	teamLayout(t, l, "60s", "60s")
	require.NoError(t, os.WriteFile(filepath.Join(l.root, "coder.sh"), []byte("#!/bin/sh\nmkdir -p \"$ANVILKIT_WORKSPACE/w\"\necho ran >> \"$ANVILKIT_WORKSPACE/w/ran\"\n"), 0o755))
	elsewhere := filepath.Join(l.root, "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o755))
	coordinatorScript(t, l, "ws=\"$ANVILKIT_WORKSPACE\"\nans() { read answer; printf '%s\\n' \"$answer\" >> \"$ANVILKIT_VERDICT_DIR/team/answers\"; }\n"+
		"mkdir -p \"$ws/round/1\"\n"+request(1, 1, "$ws/round/1")+"ans\n"+
		request(2, 1, "$ws/round/1")+"ans\n"+
		request(3, 2, "$ws/round/3")+"ans\n"+
		"ln -s "+elsewhere+" \"$ws/round/2\"\n"+request(4, 2, "$ws/round/2")+"ans\n"+
		"mkdir -p \"$ws/round/4\" && chmod 0777 \"$ws/round/4\"\n"+request(5, 4, "$ws/round/4")+"ans\nexit 0\n")
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_r"}
	fs.serve(t, l.sockets)
	code, _, log := supervise(t, l, envelopeFor(deadline))
	require.Equal(t, 1, code, log)
	answers := readAnswers(t, l)
	require.Len(t, answers, 5, log)
	require.Equal(t, "candidate-ended", answers[0]["type"])
	for i, want := range []string{"ROUND_NOT_NEW", "ROUND_DIR_INVALID", "ROUND_DIR_INVALID", "ROUND_DIR_INVALID"} {
		require.Equal(t, "refused", answers[i+1]["type"], i)
		require.Equal(t, want, answers[i+1]["code"], "request %d: %v", i+2, answers[i+1]["reason"])
		require.EqualValues(t, i+2, answers[i+1]["requestId"])
	}
	ran, err := os.ReadFile(filepath.Join(l.workspace, "w", "ran"))
	require.NoError(t, err)
	require.Equal(t, "ran\n", string(ran), "only the first round ran a candidate")
}

// A coordinator that leaves the protocol — a line that is not a request,
// or a requestId that does not increase — ends the team: no candidate runs
// for it, the coordinator is stopped and the launch fails.
func TestTeamProtocolViolationEndsTheLaunch(t *testing.T) {
	for name, lines := range map[string]string{
		"duplicate member": `printf '{"type":"run-candidate","protocolVersion":1,"requestId":1,"requestId":2,"round":1,"roundDir":"%s/round/1"}\n' "$ANVILKIT_WORKSPACE"` + "\n",
		"unknown member":   `printf '{"type":"run-candidate","protocolVersion":1,"requestId":1,"round":1,"roundDir":"%s/round/1","program":"/bin/sh"}\n' "$ANVILKIT_WORKSPACE"` + "\n",
		"diagnostics":      "echo 'coordinator starting'\n",
		"requestId reused": request(1, 1, "$ANVILKIT_WORKSPACE/round/1") + "read answer\n" + request(1, 2, "$ANVILKIT_WORKSPACE/round/2"),
	} {
		t.Run(name, func(t *testing.T) {
			l := prepare(t)
			teamLayout(t, l, "60s", "60s")
			require.NoError(t, os.WriteFile(filepath.Join(l.root, "coder.sh"), []byte("#!/bin/sh\nmkdir -p \"$ANVILKIT_WORKSPACE/w\"\necho ran >> \"$ANVILKIT_WORKSPACE/w/ran\"\n"), 0o755))
			coordinatorScript(t, l, "mkdir -p \"$ANVILKIT_WORKSPACE/round/1\" \"$ANVILKIT_WORKSPACE/round/2\"\n"+lines+"sleep 60\n")
			deadline := time.Now().Add(10 * time.Minute)
			fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_p"}
			fs.serve(t, l.sockets)
			started := time.Now()
			code, summary, log := supervise(t, l, envelopeFor(deadline))
			require.Less(t, time.Since(started), 30*time.Second, "the coordinator was stopped, not waited for")
			require.Equal(t, 1, code, log)
			require.Contains(t, summary.Error, "coordinator protocol violation")
			require.Empty(t, fs.manifests)
			ran, _ := os.ReadFile(filepath.Join(l.workspace, "w", "ran"))
			if name == "requestId reused" {
				require.Equal(t, "ran\n", string(ran), "the first, valid round ran; the second request ran nothing")
			} else {
				require.Empty(t, string(ran), "no candidate ran")
			}
		})
	}
}

// VAL-05: the coordinator runs the validator's steps as UID 10001 among its
// own children, and in the team container it is not PID 1. A step process
// that detached (a new session, its parent gone) is reparented to the
// supervisor — the child subreaper — outside the coordinator's subtree.
// When the coordinator has ended, every descendant, such an orphan
// included, is stopped as the candidate identity and confirmed gone before
// the team result is read; the launch then fails on that result alone.
func TestCoordinatorLeftoversAreGoneBeforeTheResultIsRead(t *testing.T) {
	l := prepare(t)
	teamLayout(t, l, "60s", "60s")
	left := filepath.Join(l.verdict, "team", "left")
	coordinatorScript(t, l, detachedAs("10001", left+".10001")+detachedAs("10003", left+".10003")+"exit 0\n")
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_left"}
	fs.serve(t, l.sockets)
	code, summary, log := supervise(t, l, envelopeFor(deadline))
	require.Equal(t, 1, code, log)
	require.Contains(t, summary.Error, "coordinator exited 0 without a result", log)
	require.Empty(t, fs.manifests)
	requireGone(t, []int{pidOf(t, left+".10001")})
	requireGoneAs(t, "10003", []int{pidOf(t, left+".10003")})
}

// A validator ended mid-run (its CLI killed) can leave a process of its SSR
// harness identity (UID 10003) behind, reparented to the supervisor. The
// next candidate round's stop runs as that identity too: the round is
// answered as ended — not refused as an unestablished stop — and the
// harness process is gone when the answer arrives.
func TestTeamRoundStopCoversTheHarnessIdentity(t *testing.T) {
	l := prepare(t)
	teamLayout(t, l, "60s", "60s")
	require.NoError(t, os.WriteFile(filepath.Join(l.root, "coder.sh"), []byte("#!/bin/sh\nmkdir -p \"$ANVILKIT_WORKSPACE/w\"\nexit 0\n"), 0o755))
	left := filepath.Join(l.verdict, "team", "left.10003")
	coordinatorScript(t, l, detachedAs("10003", left)+"mkdir -p \"$ANVILKIT_WORKSPACE/round/1\"\n"+request(1, 1, "$ANVILKIT_WORKSPACE/round/1")+
		"read answer\nprintf '%s\\n' \"$answer\" >> \"$ANVILKIT_VERDICT_DIR/team/answers\"\n"+
		"p=$(cat \""+left+"\")\nif [ -e /proc/$p ] && ! grep -q '^State:.*Z' /proc/$p/status; then echo 1; else echo 0; fi > \"$ANVILKIT_VERDICT_DIR/team/alive\"\nexit 0\n")
	deadline := time.Now().Add(10 * time.Minute)
	fs := &fakeSidecar{scope: scopeFor(deadline), inputs: map[string][]byte{}, stageID: "stg_h"}
	fs.serve(t, l.sockets)
	code, _, log := supervise(t, l, envelopeFor(deadline))
	require.Equal(t, 1, code, log)
	answers := readAnswers(t, l)
	require.Len(t, answers, 1)
	require.Equal(t, "candidate-ended", answers[0]["type"], "the round's stop was established: %v", answers[0])
	alive, err := os.ReadFile(filepath.Join(l.verdict, "team", "alive"))
	require.NoError(t, err)
	require.Equal(t, "0", strings.TrimSpace(string(alive)), "the harness process was gone when the answer arrived")
	requireGoneAs(t, "10003", []int{pidOf(t, left)})
}

// detachedAs is a coordinator script fragment: a process of the identity
// uid in a new session whose parent is gone (reparented to the supervisor),
// its pid recorded at file.
func detachedAs(uid, file string) string {
	return "pid=$(setpriv --reuid=" + uid + " --regid=" + uid + " --clear-groups -- /bin/sh -c 'setsid sleep 300 </dev/null >/dev/null 2>&1 & echo $!')\n" +
		"[ -n \"$pid\" ] && [ -e /proc/$pid ] || exit 3\n" +
		"grep -q '^Uid:[[:space:]]*" + uid + "' /proc/$pid/status || exit 4\n" +
		"echo $pid > \"" + file + "\"\n"
}

// requireGoneAs asserts that none of the PIDs is a live process of uid.
func requireGoneAs(t *testing.T, uid string, pids []int) {
	t.Helper()
	for _, pid := range pids {
		raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
		if err != nil {
			continue
		}
		status := string(raw)
		require.False(t, strings.Contains(status, "\nUid:\t"+uid) && !strings.Contains(status, "State:\tZ"), "pid %d still runs as %s:\n%s", pid, uid, status)
	}
}
