package launch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/sidecar"
)

const okEnvelope = `{"schemaVersion":1,"launchId":"lch_1","launchKey":"cg-test","operationId":"op_1","attemptId":"att_1","profileId":"codegen-team-dev-v1","profileRevision":"2","jobKind":"codegen","executionEpoch":"1","launchEpoch":"1","deadline":"2026-10-06T10:00:00Z","inputs":[{"name":"brief","digest":"sha256:` + "0000000000000000000000000000000000000000000000000000000000000000" + `"}]}`

func TestEnvelopeIsStrict(t *testing.T) {
	_, err := Parse([]byte(okEnvelope))
	require.NoError(t, err)
	for name, doc := range map[string]string{
		"unknown member":   strings.Replace(okEnvelope, `"jobKind"`, `"image":"x","jobKind"`, 1),
		"trailing data":    okEnvelope + `{}`,
		"local deadline":   strings.Replace(okEnvelope, `2026-10-06T10:00:00Z`, `2026-10-06T10:00:00+02:00`, 1),
		"unknown job kind": strings.Replace(okEnvelope, `"codegen"`, `"shell"`, 1),
		"duplicate input":  strings.Replace(okEnvelope, `"inputs":[`, `"inputs":[{"name":"brief","digest":"sha256:`+strings.Repeat("1", 64)+`"},`, 1),
		"bad launch key":   strings.Replace(okEnvelope, `"cg-test"`, `"CG_TEST"`, 1),
		"schema version":   strings.Replace(okEnvelope, `"schemaVersion":1`, `"schemaVersion":2`, 1),
	} {
		_, err := Parse([]byte(doc))
		require.Error(t, err, name)
	}
}

type fakeLoader struct {
	reported, served []byte
	fail             error
}

func (f fakeLoader) LoadInput(context.Context, string) (sidecar.LoadedInput, error) {
	return sidecar.LoadedInput{Name: "stage", Class: "stage", Digest: Digest(f.reported), SizeBytes: int64(len(f.reported))}, f.fail
}

func (f fakeLoader) ReadInput(context.Context, string, int64) ([]byte, error) { return f.served, nil }

// Inputs are bound to digests: a protected fixture or a handle-bound load
// whose bytes are not the envelope's is refused before anything runs.
func TestInputsAreBoundToTheirDigests(t *testing.T) {
	dir, fixtures := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(fixtures, "brief.json"), []byte(`{"x":1}`), 0o600))
	env := Envelope{Inputs: []Input{{Name: "brief", Digest: Digest([]byte(`{"x":1}`))}}}
	got, err := StageProtected(env, fixtures, dir)
	require.NoError(t, err)
	require.Equal(t, `{"x":1}`, string(got["brief"]))
	env.Inputs[0].Digest = Digest([]byte("other"))
	_, err = StageProtected(env, fixtures, dir)
	require.ErrorContains(t, err, "the envelope binds")

	stage := []byte("stage archive")
	bound := Envelope{Inputs: []Input{{Name: "stage", Digest: Digest(stage), Handle: "hdl_1"}}}
	inputs := map[string][]byte{}
	_, err = LoadBound(context.Background(), bound, fakeLoader{reported: stage, served: stage}, dir, 1<<20, inputs)
	require.NoError(t, err)
	require.Equal(t, stage, inputs["stage"])
	_, err = LoadBound(context.Background(), bound, fakeLoader{reported: stage, served: []byte("swapped")}, dir, 1<<20, map[string][]byte{})
	require.ErrorContains(t, err, "hashes to")
	_, err = LoadBound(context.Background(), bound, fakeLoader{fail: errors.New("NO_AUTHORITY")}, dir, 1<<20, map[string][]byte{})
	require.ErrorContains(t, err, "NO_AUTHORITY")
}
