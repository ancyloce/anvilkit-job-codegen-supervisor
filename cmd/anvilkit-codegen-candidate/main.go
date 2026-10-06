// anvilkit-codegen-candidate is the fixed, non-paid candidate task of the
// P09 harness: it runs as the candidate UID inside the workspace, reads the
// permitted inputs, writes the fixed result and a report of the boundary it
// observed. Nothing it writes is a verdict; the trusted observer decides
// from the bytes. The probes exist so that runtime qualification can read,
// from inside the candidate identity, what the kernel and the sidecar
// actually allowed.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type report struct {
	Identity map[string]any    `json:"identity"`
	Outcomes map[string]string `json:"outcomes"`
	Detail   map[string]string `json:"detail"`
}

func main() {
	workspace := os.Getenv("ANVILKIT_WORKSPACE")
	inputDir := os.Getenv("ANVILKIT_INPUT_DIR")
	if workspace == "" || inputDir == "" {
		fmt.Fprintln(os.Stderr, "candidate: ANVILKIT_WORKSPACE and ANVILKIT_INPUT_DIR are required")
		os.Exit(2)
	}
	work := filepath.Join(workspace, "w")
	output := filepath.Join(work, "output")
	if err := os.MkdirAll(output, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "candidate: workspace:", err)
		os.Exit(2)
	}
	rep := report{Identity: map[string]any{}, Outcomes: map[string]string{}, Detail: map[string]string{}}

	// The fixed task: one line per permitted input, in name order.
	entries, _ := os.ReadDir(inputDir)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var result strings.Builder
	result.WriteString("anvilkit-codegen-fixed-v1\n")
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(inputDir, n))
		if err != nil {
			rep.Outcomes["input-read:"+n] = errString(err)
			continue
		}
		fmt.Fprintf(&result, "input %s sha256:%x\n", n, sha256.Sum256(b))
	}
	if err := os.WriteFile(filepath.Join(output, "result.txt"), []byte(result.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "candidate: result:", err)
		os.Exit(1)
	}

	probeIdentity(&rep)
	probeFiles(&rep)
	probeSockets(&rep)
	probeNetwork(&rep)
	probeResources(&rep, work)

	raw, _ := json.MarshalIndent(rep, "", " ")
	if err := os.WriteFile(filepath.Join(output, "probes.json"), raw, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "candidate: probes:", err)
		os.Exit(1)
	}
	fmt.Println("candidate: fixed task complete")
}

func errString(err error) string {
	if err == nil {
		return "ok"
	}
	var errno syscall.Errno
	if pe, ok := err.(*os.PathError); ok {
		err = pe.Err
	}
	if oe, ok := err.(*net.OpError); ok {
		err = oe.Err
	}
	if se, ok := err.(*os.SyscallError); ok {
		err = se.Err
	}
	if e, ok := err.(syscall.Errno); ok {
		errno = e
	}
	if errno != 0 {
		return strings.ToUpper(unix.ErrnoName(errno))
	}
	s := err.Error()
	if strings.Contains(s, "timeout") || strings.Contains(s, "deadline") {
		return "TIMEOUT"
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func probeIdentity(rep *report) {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		rep.Outcomes["identity"] = errString(err)
		return
	}
	caps := uint64(0)
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Uid", "Gid", "Groups", "NoNewPrivs", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "Seccomp":
			rep.Identity[k] = v
			if strings.HasPrefix(k, "Cap") {
				n, _ := strconv.ParseUint(v, 16, 64)
				caps |= n
			}
		}
	}
	rep.Outcomes["capabilities-empty"] = strconv.FormatBool(caps == 0)
	rep.Outcomes["no-new-privs"] = fmt.Sprint(rep.Identity["NoNewPrivs"])
	rep.Outcomes["uid"] = fmt.Sprint(rep.Identity["Uid"])
	rep.Outcomes["groups-empty"] = strconv.FormatBool(strings.TrimSpace(fmt.Sprint(rep.Identity["Groups"])) == "")
	// Inherited descriptors: nothing beyond 0, 1 and 2 may be open.
	d, err := os.Open("/proc/self/fd")
	if err == nil {
		fds, _ := d.Readdirnames(-1)
		d.Close()
		var extra []string
		for _, f := range fds {
			n, _ := strconv.Atoi(f)
			if n <= 2 || n == int(d.Fd()) {
				continue
			}
			// Anonymous descriptors are this runtime's own (epoll, eventfd);
			// anything else could only have been inherited.
			// Anonymous descriptors are this runtime's own (epoll, eventfd),
			// as is the cgroup limit file it watches; a descriptor that is
			// gone by the time it is read back was a transient of this
			// process. An inherited descriptor is none of those: it is
			// stable and names a file, pipe or socket.
			target, err := os.Readlink(filepath.Join("/proc/self/fd", f))
			if err != nil || strings.HasPrefix(target, "anon_inode:") || strings.HasPrefix(target, "/sys/fs/cgroup/") {
				continue
			}
			extra = append(extra, f+"->"+target)
		}
		rep.Outcomes["inherited-fds"] = strconv.Itoa(len(extra))
		rep.Detail["inherited-fds"] = strings.Join(extra, ",")
	}
	if err := unix.Setuid(0); err != nil {
		rep.Outcomes["setuid-0"] = errString(err)
	} else {
		rep.Outcomes["setuid-0"] = "SUCCEEDED"
	}
}

func probeFiles(rep *report) {
	for _, p := range strings.Split(os.Getenv("ANVILKIT_PROBE_FILES"), ",") {
		if p == "" {
			continue
		}
		f, err := os.Open(p)
		if err == nil {
			_, err = io.ReadAll(io.LimitReader(f, 64))
			f.Close()
			if err == nil {
				rep.Outcomes["read:"+filepath.Base(p)] = "READABLE"
				continue
			}
		}
		rep.Outcomes["read:"+filepath.Base(p)] = errString(err)
	}
	for _, p := range strings.Split(os.Getenv("ANVILKIT_PROBE_WRITES"), ",") {
		if p == "" {
			continue
		}
		err := os.WriteFile(p, []byte("forged\n"), 0o644)
		if err == nil {
			rep.Outcomes["write:"+filepath.Base(p)] = "WRITABLE"
			continue
		}
		rep.Outcomes["write:"+filepath.Base(p)] = errString(err)
	}
}

func httpOver(socket string, method, path string, body string) (int, string, error) {
	tr := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return net.DialTimeout("unix", socket, 2*time.Second)
	}, DisableKeepAlives: true}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, err := http.NewRequest(method, "http://sidecar"+path, strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var f struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(raw, &f)
	return resp.StatusCode, f.Code, nil
}

func probeSockets(rep *report) {
	trusted, candidate := os.Getenv("ANVILKIT_TRUSTED_SOCKET"), os.Getenv("ANVILKIT_CANDIDATE_SOCKET")
	if c, err := net.DialTimeout("unix", trusted, 2*time.Second); err == nil {
		c.Close()
		rep.Outcomes["connect:trusted.sock"] = "CONNECTED"
	} else {
		rep.Outcomes["connect:trusted.sock"] = errString(err)
	}
	input := os.Getenv("ANVILKIT_PROBE_INPUT")
	answer := func(key, method, path, body string) {
		status, code, err := httpOver(candidate, method, path, body)
		if err != nil {
			rep.Outcomes[key] = errString(err)
			return
		}
		rep.Outcomes[key] = strconv.Itoa(status) + " " + code
	}
	if input != "" {
		answer("candidate:inputs-permitted", http.MethodGet, "/v1/inputs/"+input, "")
	}
	answer("candidate:inputs-other", http.MethodGet, "/v1/inputs/not-permitted", "")
	answer("candidate:scope", http.MethodGet, "/v1/scope", "")
	answer("candidate:results", http.MethodPost, "/v1/results", `{"verdict":"certified","observerIdentity":"candidate","manifest":{}}`)
	answer("candidate:transfers", http.MethodPost, "/v1/transfers", "x")
	answer("candidate:knowledge", http.MethodPost, "/v1/knowledge/search", "{}")
	answer("candidate:model-relay", http.MethodPost, "/v1/model/relay", "{}")
	// Descriptor delegation over the candidate socket: the sidecar must
	// close the connection without serving anything.
	conn, err := net.DialTimeout("unix", candidate, 2*time.Second)
	if err != nil {
		rep.Outcomes["candidate:fd-delegation"] = errString(err)
		return
	}
	uc := conn.(*net.UnixConn)
	f, _ := os.Open(os.DevNull)
	rights := unix.UnixRights(int(f.Fd()))
	_, _, err = uc.WriteMsgUnix([]byte("GET /v1/inputs/"+input+" HTTP/1.1\r\nHost: sidecar\r\n\r\n"), rights, nil)
	f.Close()
	if err != nil {
		rep.Outcomes["candidate:fd-delegation"] = errString(err)
		uc.Close()
		return
	}
	_ = uc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	n, err := uc.Read(buf)
	uc.Close()
	switch {
	case err == io.EOF, n == 0 && err != nil:
		rep.Outcomes["candidate:fd-delegation"] = "CLOSED"
	case err != nil:
		rep.Outcomes["candidate:fd-delegation"] = errString(err)
	default:
		rep.Outcomes["candidate:fd-delegation"] = "SERVED"
	}
}

func probeNetwork(rep *report) {
	for name, domain := range map[string]int{"socket:af-inet": unix.AF_INET, "socket:af-inet6": unix.AF_INET6, "socket:af-unix": unix.AF_UNIX} {
		fd, err := unix.Socket(domain, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			rep.Outcomes[name] = errString(err)
			continue
		}
		_ = unix.Close(fd)
		rep.Outcomes[name] = "CREATED"
	}
	for _, target := range strings.Split(os.Getenv("ANVILKIT_PROBE_TARGETS"), ",") {
		if target == "" {
			continue
		}
		c, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err != nil {
			rep.Outcomes["connect:"+target] = errString(err)
			continue
		}
		c.Close()
		rep.Outcomes["connect:"+target] = "CONNECTED"
	}
}

// probeResources plants every discovery file a coding agent might read:
// the trusted harness must not load any of them.
func probeResources(rep *report, work string) {
	for _, p := range []string{"AGENTS.md", "SYSTEM.md", ".pi/settings.json", ".pi/extensions/evil.js", "skills/evil/SKILL.md", ".claude/settings.json"} {
		full := filepath.Join(work, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte("candidate resource; must never become trusted instruction\n"), 0o644); err != nil {
			rep.Outcomes["plant:"+p] = errString(err)
		} else {
			rep.Outcomes["plant:"+p] = "WRITTEN"
		}
	}
}
