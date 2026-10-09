package process

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Reason is why candidate execution ended.
type Reason string

const (
	// Exited: the leader exited on its own.
	Exited Reason = "exited"
	// Timeout: the candidate's bound, or a bound the caller's context
	// carries as its cause (ErrBoundReached), was reached first.
	Timeout Reason = "timeout"
	// Canceled: the caller's context ended first for any other cause.
	Canceled Reason = "canceled"
)

var (
	// ErrBoundReached, as (or wrapped in) a context's cause, makes the end
	// of a running candidate a Timeout rather than a cancellation.
	ErrBoundReached = errors.New("bound reached")
	// ErrNotRun: the candidate was not executed (it could not be started,
	// no time was left, or the privilege drop refused it).
	ErrNotRun = errors.New("candidate not run")
	// ErrStopNotEstablished: the supervisor could not confirm that no
	// candidate process is left. Nothing may observe, seal, submit or run
	// another round after it.
	ErrStopNotEstablished = errors.New("candidate stop not established")
)

// Spec is one candidate execution: the program and its arguments (the
// reviewed configuration's, never a caller's), its complete environment,
// where its stdout and stderr go, and its bound.
type Spec struct {
	Program string
	Args    []string
	Env     []string
	Output  *os.File
	Timeout time.Duration
}

// Ended is the supervisor's account of one candidate execution, given only
// once nothing of the candidate runs: how the leader ended, why execution
// ended, how many processes the stop signaled, and when it started and
// was confirmed ended.
type Ended struct {
	Exit           *int
	Signal         string
	Reason         Reason
	Stopped        int
	Started, Ended time.Time
}

// Identity is a non-root UID and GID a candidate's processes run as.
type Identity struct {
	UID, GID uint32
}

// Controller performs the process operations of one launch for the
// candidate identity.
type Controller struct {
	// Self is the supervisor executable: the trampoline and the stop helper.
	Self string
	// UID and GID are the candidate identity; Dir its working directory.
	UID, GID uint32
	Dir      string
	// Others are further identities processes of the launch run as without
	// being the candidate program (in the team mode the validator's SSR
	// harness): every stop runs the helper as each of them too, since only
	// an identity can signal its own processes, and every confirmation
	// counts them.
	Others []Identity
	Now    func() time.Time
	// trusted is the pid of a trusted child of the supervisor (the team
	// coordinator) while it runs: its subtree is not the candidate's and is
	// left out of every candidate stop and confirmation.
	trusted int
}

// SetTrusted names (pid > 0) or clears (0) the trusted child.
func (c *Controller) SetTrusted(pid int) { c.trusted = pid }

func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Run executes a candidate through the trampoline in its own process
// group, waits for the leader, the bound or the context, and then — the
// same path whatever ended the wait, a leader that exited on its own
// included, since it may have left descendants — stops every candidate
// process from inside the candidate identity, waits for the leader, reaps
// and confirms from /proc that none is left. Only then does it return an
// Ended. An error wrapping ErrStopNotEstablished means the stop could not
// be confirmed; one wrapping ErrNotRun means the candidate never executed.
func (c *Controller) Run(ctx context.Context, spec Spec) (Ended, error) {
	var e Ended
	if spec.Timeout < time.Second {
		return e, fmt.Errorf("%w: no time is left for the candidate", ErrNotRun)
	}
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return e, fmt.Errorf("%w: %v", ErrNotRun, err)
	}
	defer devnull.Close()
	cmd := exec.Command(c.Self, trampolineArgs(c.UID, c.GID, c.Dir, spec.Program, spec.Args...)...)
	cmd.Env = spec.Env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, spec.Output, spec.Output
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	e.Started = c.now()
	if err := cmd.Start(); err != nil {
		return e, fmt.Errorf("%w: start: %v", ErrNotRun, err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	bound := time.NewTimer(spec.Timeout)
	defer bound.Stop()
	var werr error
	leaderDone := false
	select {
	case werr = <-waited:
		e.Reason, leaderDone = Exited, true
	case <-bound.C:
		e.Reason = Timeout
	case <-ctx.Done():
		e.Reason = Canceled
		if errors.Is(context.Cause(ctx), ErrBoundReached) {
			e.Reason = Timeout
		}
	}
	stopped, err := c.stopCandidate(cmd.Process.Pid)
	if err != nil {
		return e, fmt.Errorf("%w: %v", ErrStopNotEstablished, err)
	}
	e.Stopped = stopped
	if !leaderDone {
		select {
		case werr = <-waited:
		case <-time.After(stopHelperBound):
			return e, fmt.Errorf("%w: the leader did not exit after the stop", ErrStopNotEstablished)
		}
	}
	reapOrphans(c.trusted)
	if err := confirmStopped(c.trusted); err != nil {
		return e, fmt.Errorf("%w: %v", ErrStopNotEstablished, err)
	}
	e.Ended = c.now()
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
		switch {
		case ws.Exited():
			code := ws.ExitStatus()
			e.Exit = &code
		case ws.Signaled():
			e.Signal = ws.Signal().String()
		}
	}
	if e.Exit != nil && *e.Exit == PrivdropDenied {
		return e, fmt.Errorf("%w: the privilege drop failed; the candidate was not executed", ErrNotRun)
	}
	if e.Exit == nil && e.Signal == "" {
		return e, fmt.Errorf("%w: the end of the candidate is not known: %v", ErrNotRun, werr)
	}
	return e, nil
}

// StopAll stops every descendant of the supervisor, the trusted child's
// subtree included: run once the trusted child has ended (its own
// children, such as validation steps, may be left), so nothing the launch
// started keeps running. Descendants with the supervisor's own identity
// are signaled directly; the candidate identity's through the stop
// helper. It returns how many processes were signaled; an error wraps
// ErrStopNotEstablished.
func (c *Controller) StopAll() (int, error) {
	if c.trusted != 0 {
		return 0, fmt.Errorf("%w: the trusted child is still named", ErrStopNotEstablished)
	}
	procs, err := scan()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrStopNotEstablished, err)
	}
	own, killed := uint32(os.Geteuid()), 0
	for _, p := range descendants(procs, os.Getpid()) {
		if p.uid == own && syscall.Kill(p.pid, syscall.SIGKILL) == nil {
			killed++
		}
	}
	stopped, err := c.stopCandidate(0)
	if err != nil {
		return killed, fmt.Errorf("%w: %v", ErrStopNotEstablished, err)
	}
	// Signaled processes need a moment to die before they can be reaped.
	deadline := time.Now().Add(stopHelperBound)
	for {
		reapOrphans()
		err := confirmStopped(0)
		if err == nil {
			return killed + stopped, nil
		}
		if time.Now().After(deadline) {
			return killed + stopped, fmt.Errorf("%w: %v", ErrStopNotEstablished, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// stopCandidate runs the stop helper as the candidate identity through the
// trampoline (pgid 0: no group, descendants only), then as each of the
// other identities (descendants only), each under a bound. It returns how
// many processes the helpers signaled.
func (c *Controller) stopCandidate(pgid int) (int, error) {
	killed, err := c.stopAs(Identity{UID: c.UID, GID: c.GID}, pgid)
	if err != nil {
		return killed, err
	}
	for _, other := range c.Others {
		// After the candidate's helper (which waits for every process still
		// of UID 0 to drop or die), only an identity with a live process left
		// needs its own helper; the confirmation counts every identity.
		if !c.hasDescendantsOf(other.UID) {
			continue
		}
		n, err := c.stopAs(other, 0)
		killed += n
		if err != nil {
			return killed, fmt.Errorf("as UID %d: %w", other.UID, err)
		}
	}
	return killed, nil
}

// hasDescendantsOf reports whether a live descendant outside the trusted
// subtree runs as uid (true when /proc cannot be read: the helper then runs).
func (c *Controller) hasDescendantsOf(uid uint32) bool {
	procs, err := scan()
	if err != nil {
		return true
	}
	for _, p := range descendants(procs, os.Getpid(), c.trusted) {
		if p.uid == uid {
			return true
		}
	}
	return false
}

// stopAs runs the stop helper as one identity and waits for it under a
// bound.
func (c *Controller) stopAs(id Identity, pgid int) (int, error) {
	args := []string{StopCommand, "--root", strconv.Itoa(os.Getpid())}
	if pgid > 0 {
		args = append(args, "--pgid", strconv.Itoa(pgid))
	}
	if c.trusted > 0 {
		args = append(args, "--exclude", strconv.Itoa(c.trusted))
	}
	cmd := exec.Command(c.Self, trampolineArgs(id.UID, id.GID, c.Dir, c.Self, args...)...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start the stop helper: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() == PrivdropDenied {
				return 0, fmt.Errorf("the stop helper could not take the candidate identity: %s", strings.TrimSpace(stderr.String()))
			}
			return 0, fmt.Errorf("the stop helper failed: %v: %s", err, strings.TrimSpace(stderr.String()))
		}
	case <-time.After(stopHelperBound):
		// A helper this process cannot signal either; the launch fails and
		// the container's end takes every process with it.
		return 0, fmt.Errorf("the stop helper did not return within %s", stopHelperBound)
	}
	var report stopReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return 0, fmt.Errorf("the stop helper reported nothing readable: %s", strings.TrimSpace(stderr.String()))
	}
	return report.Killed, nil
}
