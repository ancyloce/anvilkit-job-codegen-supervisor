package supervisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Resources are the trusted resources of the harness (DD-03 §6): one
// explicit file in the explicit read-only agent directory. There is no
// discovery: nothing named AGENTS.md, .pi, SYSTEM.md, extensions, skills or
// settings is looked for anywhere, and the candidate workspace is never a
// resource location. The loader refuses an agent directory the candidate
// could write to.
type Resources struct {
	SchemaVersion int      `json:"schemaVersion"`
	SystemPrompt  string   `json:"systemPrompt"`
	Tools         []string `json:"tools"`
	Skills        []string `json:"skills"`
	Digest        string   `json:"-"`
}

const resourcesFile = "resources.json"

// LoadResources reads agentDir/resources.json and nothing else.
func LoadResources(agentDir string, candidateUID, candidateGID uint32) (Resources, error) {
	st, err := os.Lstat(agentDir)
	if err != nil {
		return Resources{}, fmt.Errorf("agent dir: %w", err)
	}
	sys := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.IsDir():
		return Resources{}, fmt.Errorf("agent dir %s is not a directory", agentDir)
	case sys.Uid != 0 || sys.Uid == candidateUID || sys.Gid == candidateGID:
		return Resources{}, fmt.Errorf("agent dir %s is owned by %d:%d; trusted resources must be root-owned and not the candidate's", agentDir, sys.Uid, sys.Gid)
	case st.Mode().Perm()&0o022 != 0:
		return Resources{}, fmt.Errorf("agent dir %s is writable by group or others (%o)", agentDir, st.Mode().Perm())
	}
	fd, err := unix.Open(filepath.Join(agentDir, resourcesFile), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return Resources{}, fmt.Errorf("trusted resources: %w", err)
	}
	f := os.NewFile(uintptr(fd), resourcesFile)
	defer f.Close()
	fst, err := f.Stat()
	if err != nil {
		return Resources{}, err
	}
	fsys := fst.Sys().(*syscall.Stat_t)
	if !fst.Mode().IsRegular() || fsys.Uid != 0 || fst.Mode().Perm()&0o022 != 0 {
		return Resources{}, fmt.Errorf("trusted resources file is not a root-owned, unwritable regular file")
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(&limitedReader{r: f, n: 1 << 20}); err != nil {
		return Resources{}, err
	}
	var r Resources
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Resources{}, fmt.Errorf("trusted resources: %w", err)
	}
	if r.SchemaVersion != 1 {
		return Resources{}, fmt.Errorf("trusted resources: schemaVersion %d", r.SchemaVersion)
	}
	r.Digest = fmt.Sprintf("sha256:%x", sha256.Sum256(buf.Bytes()))
	return r, nil
}

type limitedReader struct {
	r interface{ Read([]byte) (int, error) }
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, fmt.Errorf("trusted resources exceed the 1 MiB bound")
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}
