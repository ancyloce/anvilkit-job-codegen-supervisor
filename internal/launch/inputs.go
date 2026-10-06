package launch

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/sidecar"
)

// Digest is the contracts' sha256 digest form of bytes.
func Digest(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }

// StageProtected copies the protected fixtures of the image that the
// envelope names (inputs without a handle) into the candidate-readable
// input directory, verifying each against the digest the envelope binds
// it to. The fixed task's fixtures are text, the team's frozen brief a JSON
// document; both are protected fixtures of the image.
func StageProtected(env Envelope, fixturesDir, inputDir string) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, in := range env.Inputs {
		if in.Handle != "" {
			continue // loaded through the sidecar once the scope is granted (LoadBound)
		}
		var b []byte
		var err error
		for _, ext := range []string{".txt", ".json"} {
			if b, err = os.ReadFile(filepath.Join(fixturesDir, in.Name+ext)); err == nil {
				break
			}
		}
		if err != nil {
			return nil, fmt.Errorf("protected input %s: %w", in.Name, err)
		}
		if got := Digest(b); got != in.Digest {
			return nil, fmt.Errorf("protected input %s hashes to %s, the envelope binds %s", in.Name, got, in.Digest)
		}
		if err := os.WriteFile(filepath.Join(inputDir, in.Name), b, 0o644); err != nil {
			return nil, err
		}
		out[in.Name] = b
	}
	return out, nil
}

// Loader is what LoadBound needs of the access sidecar.
type Loader interface {
	LoadInput(ctx context.Context, name string) (sidecar.LoadedInput, error)
	ReadInput(ctx context.Context, name string, maxBytes int64) ([]byte, error)
}

// LoadBound obtains every input the envelope binds to an artifact handle
// through the sidecar (P13-04): the sidecar reads it from Control under the
// granted scope and stages it; the bytes are read back, verified against
// the digest the envelope binds and written into the input directory. A
// handle-bound input never comes from the image. It returns the loaded
// inputs for the caller's log (name, class, size).
func LoadBound(ctx context.Context, env Envelope, loader Loader, inputDir string, maxBytes int64, inputs map[string][]byte) ([]sidecar.LoadedInput, error) {
	var loaded []sidecar.LoadedInput
	for _, in := range env.Inputs {
		if in.Handle == "" {
			continue
		}
		l, err := loader.LoadInput(ctx, in.Name)
		if err != nil {
			return loaded, fmt.Errorf("load input %s: %w", in.Name, err)
		}
		b, err := loader.ReadInput(ctx, in.Name, maxBytes)
		if err != nil {
			return loaded, fmt.Errorf("read input %s: %w", in.Name, err)
		}
		if got := Digest(b); got != in.Digest || got != l.Digest {
			return loaded, fmt.Errorf("loaded input %s hashes to %s, the envelope binds %s (the sidecar reported %s)", in.Name, got, in.Digest, l.Digest)
		}
		if err := os.WriteFile(filepath.Join(inputDir, in.Name), b, 0o644); err != nil {
			return loaded, err
		}
		inputs[in.Name] = b
		loaded = append(loaded, l)
	}
	return loaded, nil
}
