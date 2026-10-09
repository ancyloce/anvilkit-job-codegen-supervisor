// Package config builds the trusted harness's configuration snapshot with
// koanf (A09): defaults < the reviewed config.yaml baked into the image
// (root-owned, unreadable by the candidate) < the launch facts the Job
// template injects through the environment (ANVILKIT_LAUNCH_ID,
// ANVILKIT_ATTEMPT_ID, ANVILKIT_LAUNCH_ENVELOPE). Every path of the DD-03
// layout is fixed here; nothing in the candidate workspace is ever read as
// configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

const (
	envPrefix         = "ANVILKIT_CODEGEN_"
	EnvConfigFile     = "ANVILKIT_CODEGEN_CONFIG"
	DefaultConfigFile = "config.yaml"
	EnvLaunchID       = "ANVILKIT_LAUNCH_ID"
	EnvAttemptID      = "ANVILKIT_ATTEMPT_ID"
	EnvLaunchEnvelope = "ANVILKIT_LAUNCH_ENVELOPE"
)

// Paths is the fixed mount layout: the writable candidate workspace, the
// trusted verdict tree, the sidecar sockets, the explicit read-only agent
// directory of trusted resources and the protected fixtures.
type Paths struct {
	Workspace      string `koanf:"workspace"`
	Verdict        string `koanf:"verdict"`
	Sockets        string `koanf:"sockets"`
	AgentDir       string `koanf:"agent_dir"`
	Fixtures       string `koanf:"fixtures"`
	TerminationLog string `koanf:"termination_log"`
}

type Candidate struct {
	UID            uint32        `koanf:"uid"`
	GID            uint32        `koanf:"gid"`
	Program        string        `koanf:"program"`
	Timeout        time.Duration `koanf:"timeout"`
	MaxOutputBytes int64         `koanf:"max_output_bytes"`
	// ProbeTargets are TCP endpoints the fixed candidate tries to reach to
	// report the network boundary it observed (evidence, never a verdict).
	ProbeTargets []string `koanf:"probe_targets"`
}

type Sidecar struct {
	UID            uint32        `koanf:"uid"`
	Wait           time.Duration `koanf:"wait"`
	RequestTimeout time.Duration `koanf:"request_timeout"`
	// MaxInputBytes bounds one input loaded through the sidecar (P13-04).
	MaxInputBytes int64 `koanf:"max_input_bytes"`
}

type Observer struct {
	Identity string `koanf:"identity"`
}

// Team is the P12 mode of the harness: instead of the fixed non-paid task,
// the supervisor starts the trusted coordinator (a Node process, UID 0)
// and launches the Pi coder as the candidate whenever the coordinator asks
// for a round, through the same trampoline, stop and confirmation as the
// fixed task. The programs and the reviewed team configuration are fixed
// here; the coordinator's requests name only a round and its input
// directory.
type Team struct {
	Enabled bool `koanf:"enabled"`
	// Coordinator and Coder are the program and arguments of the two
	// entrypoints of the team package.
	Coordinator []string `koanf:"coordinator"`
	Coder       []string `koanf:"coder"`
	// Config is the reviewed team.yaml (limits, route, validation).
	Config string `koanf:"config"`
	// ContractsDir holds the contract schemas the coordinator validates its
	// manifests against.
	ContractsDir string `koanf:"contracts_dir"`
	// Timeout bounds the whole coordinator run (the deadline bounds it too).
	Timeout time.Duration `koanf:"timeout"`
	// Observer is the observer identity the coordinator submits under.
	Observer string `koanf:"observer"`
	// HarnessUID and HarnessGID are the second step identity of the
	// independent validator the coordinator runs in the team container (its
	// SSR harness, UID/GID 10003, used for nothing else in the Pod). Every
	// candidate stop and confirmation covers it as well as the candidate's:
	// a validator ended mid-run can leave a harness process behind.
	HarnessUID uint32 `koanf:"harness_uid"`
	HarnessGID uint32 `koanf:"harness_gid"`
}

// Launch is the per-Job identity, environment-only.
type Launch struct {
	LaunchID  string `koanf:"launch_id"`
	AttemptID string `koanf:"attempt_id"`
	Envelope  string `koanf:"envelope"`
}

type Config struct {
	Paths     Paths     `koanf:"paths"`
	Candidate Candidate `koanf:"candidate"`
	Sidecar   Sidecar   `koanf:"sidecar"`
	Observer  Observer  `koanf:"observer"`
	Team      Team      `koanf:"team"`
	Launch    Launch    `koanf:"launch"`
}

var defaults = map[string]any{
	"paths.workspace":            "/workspace",
	"paths.verdict":              "/anvilkit/verdict",
	"paths.sockets":              "/run/anvilkit/sockets",
	"paths.agent_dir":            "/anvilkit/agent",
	"paths.fixtures":             "/anvilkit/fixtures",
	"paths.termination_log":      "/dev/termination-log",
	"candidate.uid":              10001,
	"candidate.gid":              10001,
	"candidate.program":          "/usr/local/bin/anvilkit-codegen-candidate",
	"candidate.timeout":          "5m",
	"candidate.max_output_bytes": 8 << 20,
	"candidate.probe_targets":    []string{"127.0.0.1:9", "[::1]:9", "169.254.169.254:80"},
	"sidecar.uid":                10002,
	"sidecar.wait":               "60s",
	"sidecar.request_timeout":    "60s",
	"sidecar.max_input_bytes":    67108864,
	"observer.identity":          "anvilkit-codegen-supervisor",
	"team.enabled":               false,
	"team.coordinator":           []string{"/usr/local/bin/node", "/anvilkit/team/dist/coordinator.js"},
	"team.coder":                 []string{"/usr/local/bin/node", "/anvilkit/team/dist/coder.js"},
	"team.config":                "/etc/anvilkit/anvilkit-codegen/team.yaml",
	"team.contracts_dir":         "/anvilkit/contracts",
	"team.timeout":               "24h",
	"team.observer":              "anvilkit-codegen-team",
	"team.harness_uid":           10003,
	"team.harness_gid":           10003,
}

// launchEnv maps the launch facts the Job template injects.
var launchEnv = map[string]string{EnvLaunchID: "launch.launch_id", EnvAttemptID: "launch.attempt_id", EnvLaunchEnvelope: "launch.envelope"}

func Load() (Config, error) {
	path := os.Getenv(EnvConfigFile)
	if path == "" {
		path = DefaultConfigFile
	}
	return LoadFrom(path, os.Environ())
}

// LoadFrom is Load with explicit inputs (tests).
func LoadFrom(path string, environ []string) (Config, error) {
	k := koanf.New(".")
	if err := k.Load(confmap.Provider(defaults, "."), nil); err != nil {
		return Config{}, err
	}
	if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
		return Config{}, fmt.Errorf("config file %s: %w", path, err)
	}
	if k.Exists("launch") {
		return Config{}, fmt.Errorf("config file %s: launch facts are supplied only through the environment", path)
	}
	var unknown []string
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if key, ok := launchEnv[name]; ok {
			if err := k.Set(key, value); err != nil {
				return Config{}, err
			}
			continue
		}
		if strings.HasPrefix(name, envPrefix) && name != EnvConfigFile {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return Config{}, fmt.Errorf("config: environment variables are not allowed overrides: %s", strings.Join(unknown, ", "))
	}
	var c Config
	if err := k.UnmarshalWithConf("", &c, koanf.UnmarshalConf{DecoderConfig: &mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeDurationHookFunc(), ErrorUnused: true, WeaklyTypedInput: true, Result: &c,
	}}); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	return c, c.Validate()
}

// Validate checks the snapshot (also after the team mode is selected by the
// supervisor's command).
func (c Config) Validate() error {
	var errs []error
	for name, v := range map[string]string{"paths.workspace": c.Paths.Workspace, "paths.verdict": c.Paths.Verdict, "paths.sockets": c.Paths.Sockets, "paths.agent_dir": c.Paths.AgentDir, "paths.fixtures": c.Paths.Fixtures, "paths.termination_log": c.Paths.TerminationLog, "candidate.program": c.Candidate.Program, "observer.identity": c.Observer.Identity} {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	if c.Candidate.UID == 0 || c.Candidate.GID == 0 {
		errs = append(errs, errors.New("candidate.uid and candidate.gid must not be root"))
	}
	if c.Sidecar.UID == 0 || c.Sidecar.UID == c.Candidate.UID {
		errs = append(errs, errors.New("sidecar.uid must be neither root nor the candidate"))
	}
	within := func(name string, v, lo, hi time.Duration) {
		if v < lo || v > hi {
			errs = append(errs, fmt.Errorf("%s %s outside [%s, %s]", name, v, lo, hi))
		}
	}
	within("candidate.timeout", c.Candidate.Timeout, time.Second, 24*time.Hour)
	within("sidecar.wait", c.Sidecar.Wait, time.Second, time.Hour)
	within("sidecar.request_timeout", c.Sidecar.RequestTimeout, time.Second, time.Hour)
	if c.Candidate.MaxOutputBytes < 1 || c.Candidate.MaxOutputBytes > 256<<20 {
		errs = append(errs, fmt.Errorf("candidate.max_output_bytes %d outside [1, 256Mi]", c.Candidate.MaxOutputBytes))
	}
	if c.Team.Enabled {
		if len(c.Team.Coordinator) == 0 || len(c.Team.Coder) == 0 {
			errs = append(errs, errors.New("team.coordinator and team.coder are required when the team is enabled"))
		}
		for name, v := range map[string]string{"team.config": c.Team.Config, "team.contracts_dir": c.Team.ContractsDir, "team.observer": c.Team.Observer} {
			if v == "" {
				errs = append(errs, fmt.Errorf("%s is required when the team is enabled", name))
			}
		}
		within("team.timeout", c.Team.Timeout, time.Second, 24*time.Hour)
		if c.Team.HarnessUID == 0 || c.Team.HarnessGID == 0 || c.Team.HarnessUID == c.Candidate.UID || c.Team.HarnessUID == c.Sidecar.UID {
			errs = append(errs, errors.New("team.harness_uid and team.harness_gid must be neither root, the candidate nor the sidecar"))
		}
	}
	if c.Launch.LaunchID == "" || c.Launch.AttemptID == "" || c.Launch.Envelope == "" {
		errs = append(errs, fmt.Errorf("%s, %s and %s are required", EnvLaunchID, EnvAttemptID, EnvLaunchEnvelope))
	}
	return errors.Join(errs...)
}
