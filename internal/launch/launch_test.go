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

// The optional component (P0.8): its source revision always, the
// allocated identity all three members or none, each of its form; an
// envelope without it stays valid.
func TestEnvelopeComponentIsStrict(t *testing.T) {
	const component = `"component":{"componentId":"cmp_hero_fixed","puckType":"Hero","packageName":"@anvilkit/hero-fixed","sourceRevision":"1"},`
	with := strings.Replace(okEnvelope, `"inputs":`, component+`"inputs":`, 1)
	e, err := Parse([]byte(with))
	require.NoError(t, err)
	id, typ, pkg := "cmp_hero_fixed", "Hero", "@anvilkit/hero-fixed"
	require.Equal(t, &Component{ComponentID: &id, PuckType: &typ, PackageName: &pkg, SourceRevision: "1"}, e.Component)
	e, err = Parse([]byte(okEnvelope))
	require.NoError(t, err)
	require.Nil(t, e.Component)
	// A preview or release launch names the revision alone.
	e, err = Parse([]byte(strings.Replace(okEnvelope, `"inputs":`, `"component":{"sourceRevision":"4"},"inputs":`, 1)))
	require.NoError(t, err)
	require.Equal(t, &Component{SourceRevision: "4"}, e.Component)
	for name, doc := range map[string]string{
		"null":               strings.Replace(okEnvelope, `"inputs":`, `"component":null,"inputs":`, 1),
		"not an object":      strings.Replace(okEnvelope, `"inputs":`, `"component":"cmp_hero_fixed","inputs":`, 1),
		"empty object":       strings.Replace(okEnvelope, `"inputs":`, `"component":{},"inputs":`, 1),
		"unknown member":     strings.Replace(with, `"sourceRevision":"1"}`, `"sourceRevision":"1","version":"1.0.0"}`, 1),
		"missing revision":   strings.Replace(with, `,"sourceRevision":"1"}`, `}`, 1),
		"missing package":    strings.Replace(with, `"packageName":"@anvilkit/hero-fixed",`, ``, 1),
		"component id alone": strings.Replace(with, `"puckType":"Hero","packageName":"@anvilkit/hero-fixed",`, ``, 1),
		"empty component id": strings.Replace(with, `"componentId":"cmp_hero_fixed"`, `"componentId":""`, 1),
		"empty package":      strings.Replace(with, `"@anvilkit/hero-fixed"`, `""`, 1),
		"long package":       strings.Replace(with, `"@anvilkit/hero-fixed"`, `"`+strings.Repeat("a", 215)+`"`, 1),
		"lowercase type":     strings.Replace(with, `"puckType":"Hero"`, `"puckType":"hero"`, 1),
		"bad component id":   strings.Replace(with, `"cmp_hero_fixed"`, `"-cmp"`, 1),
		"revision not a seq": strings.Replace(with, `"sourceRevision":"1"`, `"sourceRevision":"01"`, 1),
		"numeric revision":   strings.Replace(with, `"sourceRevision":"1"`, `"sourceRevision":1`, 1),
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
