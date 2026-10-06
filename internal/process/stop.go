package process

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Stopping the candidate (DD-03 §5). The supervisor is UID 0 with SETUID,
// SETGID and SETPCAP only: without CAP_KILL it cannot signal a UID 10001
// process, so neither a group kill, a parent-death signal nor a context
// cancel of the candidate establishes anything. What can signal the
// candidate's processes is the candidate identity itself. The supervisor
// therefore stops the candidate through its own trampoline: a helper that
// passes the reviewed privilege drop (UID 10001, every capability set
// empty, no_new_privs) and, from inside that identity, kills the
// candidate's process group and every descendant of the supervisor it can
// still find — descendants that left the group or the session through
// setsid/setpgid included — until none is left. The supervisor is a child
// subreaper, so an orphaned descendant is reparented to it and stays
// visible on the parent chain; it reaps what was stopped and confirms
// from its own read of /proc, not from the helper's report, that no
// descendant remains. A stop that cannot be confirmed is a failure of the
// launch: no verdict, no submission, no further round.

// StopCommand is the supervisor's subcommand that runs as the candidate
// identity and stops the candidate's processes.
const StopCommand = "candidate-stop"

// stopHelperBound bounds the stop helper and the leader's end after it.
const stopHelperBound = 60 * time.Second

// stopReport is what the stop helper prints; the supervisor's own
// confirmation, not this report, decides.
type stopReport struct {
	Killed int `json:"killed"`
	Rounds int `json:"rounds"`
}

// Stop is the candidate-stop subcommand: running as the candidate
// identity, it kills the process group and then every descendant of the
// supervisor (--root) it can signal, round after round, until no live
// descendant other than itself (and the --exclude subtree) is left. It
// exits 0 with a report on stdout, 3 when a descendant refuses the
// signal, 4 when descendants are still alive after the bounded rounds.
func Stop(args []string) int {
	var root, pgid, exclude int
	var err error
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			err = fmt.Errorf("%s needs a value", args[i])
		} else {
			switch args[i] {
			case "--root":
				root, err = strconv.Atoi(args[i+1])
			case "--pgid":
				pgid, err = strconv.Atoi(args[i+1])
			case "--exclude":
				exclude, err = strconv.Atoi(args[i+1])
			default:
				err = fmt.Errorf("unexpected argument %q", args[i])
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "candidate-stop:", err)
			return 2
		}
	}
	if root <= 0 {
		fmt.Fprintln(os.Stderr, "candidate-stop: --root is required")
		return 2
	}
	if pgid > 0 {
		// The whole group first (one signal for every member still in it);
		// the descendant walk below covers whatever left the group.
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}
	self, own := os.Getpid(), uint32(os.Getuid())
	report := stopReport{}
	for round := 0; round < 300; round++ {
		procs, err := scan()
		if err != nil {
			fmt.Fprintln(os.Stderr, "candidate-stop: /proc:", err)
			return 2
		}
		live := descendants(procs, root, self, exclude)
		if len(live) == 0 {
			report.Rounds = round
			_ = json.NewEncoder(os.Stdout).Encode(report)
			return 0
		}
		for _, p := range live {
			switch err := syscall.Kill(p.pid, syscall.SIGKILL); {
			case err == nil:
				report.Killed++
			case errors.Is(err, syscall.ESRCH):
			case errors.Is(err, syscall.EPERM) && p.uid != own:
				// Not the candidate identity (a trampoline that has not
				// dropped yet): it becomes signalable once it has, or the
				// rounds run out.
			default:
				fmt.Fprintf(os.Stderr, "candidate-stop: pid %d (uid %d): %v\n", p.pid, p.uid, err)
				return 3
			}
		}
		time.Sleep(min(time.Duration(round+1)*5*time.Millisecond, 50*time.Millisecond))
	}
	fmt.Fprintln(os.Stderr, "candidate-stop: descendants still alive after the bounded rounds")
	return 4
}

// BecomeSubreaper makes orphaned descendants of this process reparent to
// it instead of init, keeping every candidate process on its parent chain
// and reapable here. It is called before anything is forked.
func BecomeSubreaper() error {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("child subreaper: %w", err)
	}
	return nil
}

// reapOrphans collects every exited child of this process (orphans
// reparented to the subreaper) except the processes in keep, whose own
// waiters collect them: a blanket wait would steal another waiter's
// status.
func reapOrphans(keep ...int) {
	procs, err := scan()
	if err != nil {
		return
	}
	self := os.Getpid()
	for _, p := range procs {
		if p.ppid != self || p.state != 'Z' {
			continue
		}
		kept := false
		for _, k := range keep {
			kept = kept || k == p.pid
		}
		if !kept {
			var ws syscall.WaitStatus
			_, _ = syscall.Wait4(p.pid, &ws, syscall.WNOHANG, nil)
		}
	}
}

// confirmStopped is the supervisor's own check that no descendant is left
// running outside the excluded subtree: it reads /proc itself and never
// trusts the helper.
func confirmStopped(exclude int) error {
	procs, err := scan()
	if err != nil {
		return fmt.Errorf("confirm stop: %w", err)
	}
	if live := descendants(procs, os.Getpid(), exclude); len(live) != 0 {
		return fmt.Errorf("%d candidate process(es) still alive after the stop", len(live))
	}
	return nil
}
