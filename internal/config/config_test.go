package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var launchFacts = []string{EnvLaunchID + "=lch_1", EnvAttemptID + "=att_1", EnvLaunchEnvelope + "={}"}

func write(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(text), 0o600))
	return path
}

// The reviewed file of this repository loads as the image bakes it, with
// the launch facts from the environment only.
func TestReviewedConfigurationLoads(t *testing.T) {
	c, err := LoadFrom(filepath.Join("..", "..", "config.yaml"), launchFacts)
	require.NoError(t, err)
	require.Equal(t, uint32(10001), c.Candidate.UID)
	require.Equal(t, uint32(10002), c.Sidecar.UID)
	require.Equal(t, 5*time.Minute, c.Candidate.Timeout)
	require.Equal(t, "lch_1", c.Launch.LaunchID)
	require.False(t, c.Team.Enabled, "the mode is the profile's entrypoint argument, never the file's default")
	require.Equal(t, []string{"/usr/local/bin/node", "/anvilkit/team/dist/coordinator.js"}, c.Team.Coordinator)
	require.Equal(t, [2]uint32{10003, 10003}, [2]uint32{c.Team.HarnessUID, c.Team.HarnessGID}, "the validator's SSR harness identity")
	c.Team.Enabled = true
	require.NoError(t, c.Validate())
}

func TestOverridesAreRefused(t *testing.T) {
	path := write(t, "candidate:\n  timeout: 1m\n")
	_, err := LoadFrom(path, append(launchFacts, "ANVILKIT_CODEGEN_CANDIDATE_PROGRAM=/bin/sh"))
	require.ErrorContains(t, err, "not allowed overrides")
	_, err = LoadFrom(write(t, "launch:\n  launch_id: x\n"), launchFacts)
	require.ErrorContains(t, err, "only through the environment")
	_, err = LoadFrom(write(t, "candidate:\n  program_path: /bin/sh\n"), launchFacts)
	require.Error(t, err, "an unknown key is refused")
	_, err = LoadFrom(path, nil)
	require.ErrorContains(t, err, EnvLaunchEnvelope)
}

func TestBoundsAndIdentities(t *testing.T) {
	for name, text := range map[string]string{
		"root candidate":           "candidate:\n  uid: 0\n",
		"sidecar is the candidate": "sidecar:\n  uid: 10001\n",
		"candidate bound":          "candidate:\n  timeout: 25h\n",
		"output bound":             "candidate:\n  max_output_bytes: 0\n",
	} {
		_, err := LoadFrom(write(t, text), launchFacts)
		require.Error(t, err, name)
	}
	c, err := LoadFrom(write(t, "team:\n  coordinator: []\n"), launchFacts)
	require.NoError(t, err, "the team section is checked only once the team mode is selected")
	c.Team.Enabled = true
	require.ErrorContains(t, c.Validate(), "team.coordinator")
	for name, text := range map[string]string{
		"root harness":             "team:\n  harness_uid: 0\n",
		"harness is the candidate": "team:\n  harness_uid: 10001\n",
		"harness is the sidecar":   "team:\n  harness_uid: 10002\n",
		"root harness group":       "team:\n  harness_gid: 0\n",
	} {
		c, err := LoadFrom(write(t, text), launchFacts)
		require.NoError(t, err, name)
		c.Team.Enabled = true
		require.ErrorContains(t, c.Validate(), "team.harness_uid", name)
	}
}
