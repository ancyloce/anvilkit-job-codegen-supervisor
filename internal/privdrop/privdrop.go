// Package privdrop is the privilege drop of DD-03 §5, performed by the
// supervisor's trampoline in the child process immediately before the
// candidate program is executed: starting as UID 0 with only SETUID,
// SETGID and SETPCAP effective, it disables keepcaps, empties the bounding
// set, clears the supplementary groups, sets the real, effective and saved
// GID and UID to the candidate's, clears the inheritable and ambient sets,
// enables no_new_privs, closes every descriptor but 0, 1 and 2, verifies
// all of that from the kernel's own view of the thread and only then
// executes the candidate. Any failure at any step denies execution: the
// candidate program never runs with a privilege the sequence did not
// remove.
package privdrop

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	capSetGID  = 6
	capSetUID  = 7
	capSetPCAP = 8
	// allowed is the reviewed effective set of the supervisor.
	allowed = uint64(1<<capSetGID | 1<<capSetUID | 1<<capSetPCAP)
)

// Target names the candidate execution.
type Target struct {
	UID, GID uint32
	Dir      string
	Program  string
	Args     []string
	Env      []string
}

// Status is the kernel's view of the calling thread.
type Status struct {
	UIDs, GIDs                             [4]uint32
	Groups                                 []uint32
	CapInh, CapPrm, CapEff, CapBnd, CapAmb uint64
	NoNewPrivs                             int
}

// ReadStatus parses /proc/thread-self/status.
func ReadStatus() (Status, error) {
	raw, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return Status{}, err
	}
	var st Status
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		switch key {
		case "Uid", "Gid":
			if len(fields) != 4 {
				return Status{}, fmt.Errorf("status %s: %q", key, value)
			}
			var ids [4]uint32
			for i, f := range fields {
				n, err := strconv.ParseUint(f, 10, 32)
				if err != nil {
					return Status{}, err
				}
				ids[i] = uint32(n)
			}
			if key == "Uid" {
				st.UIDs = ids
			} else {
				st.GIDs = ids
			}
		case "Groups":
			st.Groups = nil
			for _, f := range fields {
				n, err := strconv.ParseUint(f, 10, 32)
				if err != nil {
					return Status{}, err
				}
				st.Groups = append(st.Groups, uint32(n))
			}
		case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
			if len(fields) != 1 {
				return Status{}, fmt.Errorf("status %s: %q", key, value)
			}
			n, err := strconv.ParseUint(fields[0], 16, 64)
			if err != nil {
				return Status{}, err
			}
			switch key {
			case "CapInh":
				st.CapInh = n
			case "CapPrm":
				st.CapPrm = n
			case "CapEff":
				st.CapEff = n
			case "CapBnd":
				st.CapBnd = n
			case "CapAmb":
				st.CapAmb = n
			}
		case "NoNewPrivs":
			if len(fields) == 1 {
				st.NoNewPrivs, _ = strconv.Atoi(fields[0])
			}
		}
	}
	return st, nil
}

// CheckSupervisor verifies that the calling process is the trusted
// supervisor as the Job template grants it: UID 0 with an effective set
// inside {SETUID, SETGID, SETPCAP} and nothing else.
func CheckSupervisor() error {
	st, err := ReadStatus()
	if err != nil {
		return err
	}
	if st.UIDs[1] != 0 {
		return fmt.Errorf("the supervisor runs as uid %d, expected 0", st.UIDs[1])
	}
	if st.CapEff&^allowed != 0 {
		return fmt.Errorf("effective capabilities %016x are outside the reviewed set (SETUID, SETGID, SETPCAP)", st.CapEff)
	}
	if st.CapEff&allowed != allowed {
		return fmt.Errorf("effective capabilities %016x lack SETUID, SETGID or SETPCAP; the candidate cannot be isolated", st.CapEff)
	}
	return nil
}

// ExecAsSupervisor executes program with the reviewed supervisor identity
// for the whole new process: the calling thread's bounding set is reduced
// to SETUID, SETGID and SETPCAP, its inheritable and ambient sets are
// cleared, no_new_privs is set, and the program is executed from that
// thread, so a root exec computes the new image's permitted and effective
// sets as exactly the bounding set (as a container runtime does for a
// Job's supervisor). It exists for development harnesses outside a Job
// container, where the caller holds every capability; it can only remove
// privileges. It returns only on failure, before the program ran.
func ExecAsSupervisor(program string, args, env []string) error {
	if err := RestrictToSupervisorSet(); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	return syscall.Exec(program, append([]string{program}, args...), env)
}

// RestrictToSupervisorSet reduces the calling thread's permitted,
// effective and inheritable capabilities and its bounding set to the
// reviewed supervisor set. Capabilities are per thread: this constrains
// the thread that calls it (locked to its goroutine) and nothing else of
// a running process, which is why it is used only immediately before an
// execve on that thread (ExecAsSupervisor, the privdrop tests), never to
// constrain a running supervisor. It cannot add a capability.
func RestrictToSupervisorSet() error {
	runtime.LockOSThread()
	// The bounding set first, while CAP_SETPCAP is still effective: a root
	// process regains its bounding set on execve, so the trampoline this
	// process executes would otherwise start with every capability again.
	// A container runtime bounds the container the same way.
	last, err := lastCap()
	if err != nil {
		return err
	}
	for c := 0; c <= last; c++ {
		if allowed&(1<<uint(c)) != 0 {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
			return fmt.Errorf("drop capability %d from the bounding set: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	data[0].Permitted, data[0].Effective, data[0].Inheritable = uint32(allowed), uint32(allowed), 0
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("restrict capabilities: %w", err)
	}
	return CheckSupervisor()
}

// Exec drops to the target and executes the program. It returns only on
// failure, before the program ran.
func Exec(t Target) error {
	runtime.LockOSThread()
	if t.UID == 0 || t.GID == 0 {
		return errors.New("the candidate must not run as root")
	}
	if err := CheckSupervisor(); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("disable keepcaps: %w", err)
	}
	last, err := lastCap()
	if err != nil {
		return err
	}
	for c := 0; c <= last; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
			return fmt.Errorf("drop capability %d from the bounding set: %w", c, err)
		}
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("clear supplementary groups: %w", err)
	}
	if err := syscall.Setresgid(int(t.GID), int(t.GID), int(t.GID)); err != nil {
		return fmt.Errorf("setresgid %d: %w", t.GID, err)
	}
	if err := syscall.Setresuid(int(t.UID), int(t.UID), int(t.UID)); err != nil {
		return fmt.Errorf("setresuid %d: %w", t.UID, err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("clear capability sets: %w", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	st, err := ReadStatus()
	if err != nil {
		return err
	}
	if err := VerifyCandidate(st, t.UID, t.GID); err != nil {
		return err
	}
	if err := closeExtraFDs(); err != nil {
		return err
	}
	if err := os.Chdir(t.Dir); err != nil {
		return fmt.Errorf("chdir %s: %w", t.Dir, err)
	}
	// No return on success: the candidate image replaces this process.
	return syscall.Exec(t.Program, append([]string{t.Program}, t.Args...), t.Env)
}

// VerifyCandidate checks that a thread status is the fully dropped
// candidate identity: every UID/GID the candidate's, no supplementary
// group, every capability set empty, no_new_privs set.
func VerifyCandidate(st Status, uid, gid uint32) error {
	for i := range st.UIDs {
		if st.UIDs[i] != uid || st.GIDs[i] != gid {
			return fmt.Errorf("identity is uid %v gid %v, expected all %d/%d", st.UIDs, st.GIDs, uid, gid)
		}
	}
	if len(st.Groups) != 0 {
		return fmt.Errorf("supplementary groups %v remain", st.Groups)
	}
	if st.CapInh|st.CapPrm|st.CapEff|st.CapBnd|st.CapAmb != 0 {
		return fmt.Errorf("capability sets not empty: inh %x prm %x eff %x bnd %x amb %x", st.CapInh, st.CapPrm, st.CapEff, st.CapBnd, st.CapAmb)
	}
	if st.NoNewPrivs != 1 {
		return errors.New("no_new_privs is not set")
	}
	return nil
}

func lastCap() (int, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0, fmt.Errorf("cap_last_cap: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || n < 0 || n > 63 {
		return 0, fmt.Errorf("cap_last_cap: %q", raw)
	}
	return n, nil
}

// OpenFDs lists the open descriptors of the calling process, excluding the
// one used to list them.
func OpenFDs() ([]int, error) {
	d, err := os.Open("/proc/self/fd")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	var fds []int
	for _, n := range names {
		fd, err := strconv.Atoi(n)
		if err != nil || fd == int(d.Fd()) {
			continue
		}
		fds = append(fds, fd)
	}
	return fds, nil
}

// closeExtraFDs closes every descriptor above 2 and verifies that only 0,
// 1 and 2 remain.
func closeExtraFDs() error {
	fds, err := OpenFDs()
	if err != nil {
		return err
	}
	for _, fd := range fds {
		if fd > 2 {
			_ = unix.Close(fd)
		}
	}
	fds, err = OpenFDs()
	if err != nil {
		return err
	}
	for _, fd := range fds {
		if fd > 2 {
			return fmt.Errorf("descriptor %d (%s) is still open after closing", fd, readLink(fd))
		}
	}
	return nil
}

// ForeignFD is an open descriptor with what it refers to.
type ForeignFD struct {
	FD     int
	Target string
}

// ForeignFDs lists the open descriptors of the calling process that are
// not anonymous descriptors of its own runtime (epoll, eventfd, ...): the
// descriptors that could have been inherited.
func ForeignFDs() []ForeignFD {
	fds, err := OpenFDs()
	if err != nil {
		return nil
	}
	var out []ForeignFD
	for _, fd := range fds {
		target := readLink(fd)
		// Anonymous inodes (epoll, eventfd) and the cgroup limit file the
		// Go runtime watches are opened by the process itself after exec.
		if strings.HasPrefix(target, "anon_inode:") || strings.HasPrefix(target, "/sys/fs/cgroup/") {
			continue
		}
		out = append(out, ForeignFD{FD: fd, Target: target})
	}
	return out
}

func readLink(fd int) string {
	s, err := os.Readlink(filepath.Join("/proc/self/fd", strconv.Itoa(fd)))
	if err != nil {
		return "?"
	}
	return s
}
