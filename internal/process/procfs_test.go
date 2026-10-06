package process

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func pids(ps []proc) []int {
	out := make([]int, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.pid)
	}
	sort.Ints(out)
	return out
}

// The parent chain decides, not sessions or groups: everything below the
// supervisor is the candidate's except an excluded subtree (the stop
// helper; the trusted coordinator and its children while it runs);
// zombies are not alive.
func TestDescendantsFollowTheParentChain(t *testing.T) {
	procs := map[int]proc{
		1:   {pid: 1, ppid: 0},
		10:  {pid: 10, ppid: 1},              // the supervisor
		11:  {pid: 11, ppid: 10, uid: 10001}, // a candidate leader
		12:  {pid: 12, ppid: 11, uid: 10001}, // its child in a new session
		13:  {pid: 13, ppid: 10, uid: 10001}, // an orphan reparented to the subreaper
		14:  {pid: 14, ppid: 13, uid: 10001, state: 'Z'},
		20:  {pid: 20, ppid: 10},             // the trusted coordinator
		21:  {pid: 21, ppid: 20, uid: 10001}, // a validation step it runs
		30:  {pid: 30, ppid: 10, uid: 10001}, // the stop helper
		99:  {pid: 99, ppid: 1, uid: 10001},  // not ours
		100: {pid: 100, ppid: 99},
	}
	require.Equal(t, []int{11, 12, 13, 20, 21, 30}, pids(descendants(procs, 10)))
	require.Equal(t, []int{11, 12, 13}, pids(descendants(procs, 10, 30, 20)))
	require.Equal(t, []int{11, 12, 13, 30}, pids(descendants(procs, 10, 0, 20)), "0 excludes nothing")
	require.Equal(t, proc{pid: 7, ppid: 3, uid: 10001, state: 'S'}, parseStatus(7, "Name:\tx\nState:\tS (sleeping)\nPPid:\t3\nUid:\t10001\t10001\t10001\t10001\n"))
}

func TestTrampolineArguments(t *testing.T) {
	require.Equal(t, []string{"candidate-exec", "--uid", "10001", "--gid", "10001", "--dir", "/workspace", "--", "/bin/coder", "a"}, trampolineArgs(10001, 10001, "/workspace", "/bin/coder", "a"))
	require.Equal(t, PrivdropDenied, Trampoline([]string{"--uid"}), "a flag without its value is refused, never a panic")
	require.Equal(t, PrivdropDenied, Trampoline([]string{"--uid", "10001", "--"}), "no program")
	require.Equal(t, 2, Stop([]string{"--root"}))
	require.Equal(t, 2, Stop([]string{"--pgid", "5"}), "--root is required")
}
