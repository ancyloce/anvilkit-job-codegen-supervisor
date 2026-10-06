// Package process holds the Linux process operations of the codegen Job's
// trusted supervisor (DD-03 §5): starting a candidate program through the
// privilege-drop trampoline, stopping every candidate process from inside
// the candidate identity, reaping, and confirming from /proc that nothing
// of the candidate is left. It decides nothing about what runs or for how
// long: the orchestration in internal/supervisor states the program, the
// environment and the bound, and receives how the execution ended.
package process

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// proc is one entry of /proc.
type proc struct {
	pid, ppid int
	uid       uint32
	state     byte
}

// scan reads pid, parent, real UID and state of every process visible in
// /proc.
func scan() (map[int]proc, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	procs := map[int]proc{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "status"))
		if err != nil {
			continue // exited between the listing and the read
		}
		procs[pid] = parseStatus(pid, string(raw))
	}
	return procs, nil
}

func parseStatus(pid int, status string) proc {
	p := proc{pid: pid}
	for _, line := range strings.Split(status, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		switch key {
		case "PPid":
			p.ppid, _ = strconv.Atoi(fields[0])
		case "Uid":
			n, _ := strconv.ParseUint(fields[0], 10, 32)
			p.uid = uint32(n)
		case "State":
			p.state = fields[0][0]
		}
	}
	return p
}

// under reports whether pid descends from ancestor on the parent chain.
func under(procs map[int]proc, pid, ancestor int) bool {
	cur, hops := procs[pid].ppid, 0
	for cur > 0 && hops < 1024 {
		if cur == ancestor {
			return true
		}
		parent, ok := procs[cur]
		if !ok {
			return false
		}
		cur, hops = parent.ppid, hops+1
	}
	return false
}

// descendants lists the live processes (no zombies) below root on the
// parent chain, leaving out every process in excluded and everything below
// one of them (the stop helper itself; in the team flow the trusted
// coordinator and its own children, which are not the candidate's). Every
// process the candidate starts descends from the supervisor: a new session
// or process group changes nothing on that chain, and with the supervisor
// as child subreaper an orphan is reparented to it rather than to init.
func descendants(procs map[int]proc, root int, excluded ...int) []proc {
	var out []proc
	for _, p := range procs {
		if p.pid == root || p.state == 'Z' || p.state == 'X' || !under(procs, p.pid, root) {
			continue
		}
		skip := false
		for _, x := range excluded {
			if x > 0 && (p.pid == x || under(procs, p.pid, x)) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, p)
		}
	}
	return out
}
