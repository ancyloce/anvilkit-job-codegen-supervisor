package supervisor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Snapshot is the trusted observer's read-only copy of the candidate's
// output directory: regular files only, no symlink followed, bounded in
// number and bytes, copied into the verdict tree the candidate cannot
// reach. The verdict is computed from this copy, never from the live
// workspace and never from anything the candidate reported.
type Snapshot struct {
	Files map[string][]byte
	// Refused lists entries the snapshot did not copy (symlinks, special
	// files, oversize files) with the reason; they never enter the verdict.
	Refused map[string]string
}

const maxSnapshotFiles = 256

func snapshot(outputDir, into string, maxBytes int64) (Snapshot, error) {
	snap := Snapshot{Files: map[string][]byte{}, Refused: map[string]string{}}
	root, err := unix.Open(outputDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) || err == syscall.ENOENT {
			return snap, nil
		}
		return snap, fmt.Errorf("output dir: %w", err)
	}
	dir := os.NewFile(uintptr(root), outputDir)
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return snap, fmt.Errorf("output dir: %w", err)
	}
	sort.Strings(names)
	if err := os.MkdirAll(into, 0o700); err != nil {
		return snap, err
	}
	var total int64
	for i, name := range names {
		if i >= maxSnapshotFiles {
			snap.Refused[name] = "beyond the file bound"
			continue
		}
		if strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
			snap.Refused[name] = "invalid name"
			continue
		}
		fd, err := unix.Openat(root, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			snap.Refused[name] = "not openable without following links: " + err.Error()
			continue
		}
		f := os.NewFile(uintptr(fd), name)
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			snap.Refused[name] = "not a regular file"
			f.Close()
			continue
		}
		if st.Size() > maxBytes || total+st.Size() > 4*maxBytes {
			snap.Refused[name] = fmt.Sprintf("%d bytes exceed the bound", st.Size())
			f.Close()
			continue
		}
		b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
		f.Close()
		if err != nil || int64(len(b)) > maxBytes {
			snap.Refused[name] = "unreadable or grew past the bound"
			continue
		}
		total += int64(len(b))
		if err := os.WriteFile(filepath.Join(into, name), b, 0o600); err != nil {
			return snap, fmt.Errorf("snapshot %s: %w", name, err)
		}
		snap.Files[name] = b
	}
	return snap, nil
}
