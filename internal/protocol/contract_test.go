package protocol

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The contract copy (contract/, verbatim from anvilkit-agent-contracts
// jobs/codegen/) is the protocol's single source: these tests hold the
// supervisor's codec to it — its constants, enumerations, patterns and
// member sets, and every fixture's outcome.

//go:embed contract/protocol.schema.json
var schemaJSON []byte

//go:embed contract/fixtures.json
var fixturesJSON []byte

//go:embed contract/SOURCE
var sourceText string

type schemaDoc struct {
	ID   string                     `json:"$id"`
	Defs map[string]json.RawMessage `json:"$defs"`
}

type def struct {
	Const      any                        `json:"const"`
	Enum       []string                   `json:"enum"`
	Pattern    string                     `json:"pattern"`
	Maximum    *int                       `json:"maximum"`
	Minimum    *int                       `json:"minimum"`
	Required   []string                   `json:"required"`
	Properties map[string]json.RawMessage `json:"properties"`
}

func loadSchema(t *testing.T) schemaDoc {
	t.Helper()
	var doc schemaDoc
	require.NoError(t, json.Unmarshal(schemaJSON, &doc))
	require.Equal(t, "urn:anvilkit:codegen-protocol:v1", doc.ID)
	return doc
}

func defOf(t *testing.T, raw json.RawMessage) def {
	t.Helper()
	var d def
	require.NoError(t, json.Unmarshal(raw, &d))
	return d
}

// The copy is the one SOURCE records: an edit here without a refresh from
// the contracts repository fails.
func TestContractCopyMatchesItsSource(t *testing.T) {
	want := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(sourceText))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		path, digest, ok := strings.Cut(line, " ")
		require.True(t, ok, line)
		want[path] = digest
	}
	for path, content := range map[string][]byte{"jobs/codegen/protocol.schema.json": schemaJSON, "jobs/codegen/fixtures.json": fixturesJSON} {
		require.Equal(t, want[path], fmt.Sprintf("sha256:%x", sha256.Sum256(content)), path)
	}
}

func TestContractConstantsAndEnumerations(t *testing.T) {
	doc := loadSchema(t)
	d := func(name string) def { return defOf(t, doc.Defs[name]) }
	require.EqualValues(t, Version, d("protocolVersion").Const)
	require.EqualValues(t, MaxLineBytes, d("maxLineBytes").Const)
	require.EqualValues(t, MaxResultBytes, d("maxResultBytes").Const)
	require.Equal(t, 1, *d("round").Minimum)
	require.Equal(t, MaxRound, *d("round").Maximum)
	require.Equal(t, StopReasons, d("stopReason").Enum)
	require.Equal(t, RefusalCodes, d("refusalCode").Enum)
	require.Equal(t, OutcomeKinds, d("teamOutcomeKind").Enum)
	require.Equal(t, roundDirPattern.String(), d("roundDir").Pattern)
	require.Equal(t, failureCodePattern.String(), d("failureCode").Pattern)
	team := d("teamResult")
	require.Equal(t, Verdicts, defOf(t, team.Properties["verdict"]).Enum)
	require.Equal(t, stageIDPattern.String(), defOf(t, team.Properties["stageId"]).Pattern)
	require.Equal(t, signalPattern.String(), defOf(t, d("candidateEnded").Properties["signal"]).Pattern)
	// The answers carry the schema's timestamp form.
	ts := regexp.MustCompile(d("timestamp").Pattern)
	for _, at := range []time.Time{time.Date(2026, 10, 6, 10, 0, 4, 0, time.UTC), time.Date(2026, 10, 6, 10, 0, 4, 123456789, time.FixedZone("x", 7200))} {
		require.Regexp(t, ts, timestamp(at))
	}
	for _, code := range RefusalCodes {
		require.Regexp(t, failureCodePattern, code)
	}
}

// jsonNames lists the JSON member names of a struct type.
func jsonNames(v any) (names, always []string) {
	rt := reflect.TypeOf(v)
	for i := 0; i < rt.NumField(); i++ {
		name, opts, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		names = append(names, name)
		if !strings.Contains(opts, "omitempty") {
			always = append(always, name)
		}
	}
	sort.Strings(names)
	sort.Strings(always)
	return names, always
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Every message type of the codec names exactly the schema's members, and
// what the supervisor writes always carries every required one.
func TestContractMemberSets(t *testing.T) {
	doc := loadSchema(t)
	for name, v := range map[string]any{"runCandidate": Request{}, "candidateEnded": CandidateEnded{}, "refused": Refused{}, "teamResult": TeamResult{}} {
		d := defOf(t, doc.Defs[name])
		names, always := jsonNames(v)
		require.Equal(t, keys(d.Properties), names, name)
		if name == "candidateEnded" || name == "refused" {
			required := append([]string(nil), d.Required...)
			sort.Strings(required)
			require.Equal(t, required, always, "%s: the supervisor writes every required member and only those always", name)
		}
	}
	outcome := defOf(t, defOf(t, doc.Defs["teamResult"]).Properties["outcome"])
	names, _ := jsonNames(Outcome{})
	require.Equal(t, keys(outcome.Properties), names)
	counters := defOf(t, defOf(t, doc.Defs["teamResult"]).Properties["counters"])
	names, _ = jsonNames(Counters{})
	require.Equal(t, keys(counters.Properties), names)
}

// Every fixture of the contract: the requests and team results the
// supervisor decodes are accepted exactly when the contract says they are
// valid; the answers it writes represent every valid fixture byte for
// byte in meaning (decoded strictly and written back).
func TestContractFixtures(t *testing.T) {
	var fx struct {
		Schema string `json:"schema"`
		Cases  []struct {
			Name     string          `json:"name"`
			Ref      string          `json:"ref"`
			Valid    bool            `json:"valid"`
			Instance json.RawMessage `json:"instance"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(fixturesJSON, &fx))
	require.Equal(t, "urn:anvilkit:codegen-protocol:v1", fx.Schema)
	seen := map[string]int{}
	for _, c := range fx.Cases {
		ref := strings.TrimPrefix(c.Ref, "#/$defs/")
		seen[ref]++
		var compact bytes.Buffer
		require.NoError(t, json.Compact(&compact, c.Instance))
		switch ref {
		case "runCandidate":
			_, err := DecodeRequest(compact.Bytes())
			require.Equal(t, c.Valid, err == nil, "%s: %v", c.Name, err)
		case "teamResult":
			_, err := DecodeTeamResult(compact.Bytes())
			require.Equal(t, c.Valid, err == nil, "%s: %v", c.Name, err)
		case "candidateEnded", "refused", "answer":
			if !c.Valid {
				continue // the supervisor never reads answers; it writes them
			}
			var typ struct {
				Type string `json:"type"`
			}
			require.NoError(t, json.Unmarshal(c.Instance, &typ))
			var answer any
			switch typ.Type {
			case TypeCandidateEnded:
				var a CandidateEnded
				require.NoError(t, decodeStrictAnswer(compact.Bytes(), &a), c.Name)
				answer = a
			case TypeRefused:
				var a Refused
				require.NoError(t, decodeStrictAnswer(compact.Bytes(), &a), c.Name)
				answer = a
			default:
				t.Fatalf("%s: unknown answer type %q", c.Name, typ.Type)
			}
			var line bytes.Buffer
			require.NoError(t, WriteAnswer(&line, answer))
			require.JSONEq(t, compact.String(), line.String(), c.Name)
		default:
			t.Fatalf("%s: no codec for %s", c.Name, c.Ref)
		}
	}
	for _, ref := range []string{"runCandidate", "candidateEnded", "refused", "teamResult"} {
		require.Positive(t, seen[ref], "the contract has fixtures of %s", ref)
	}
}

// decodeStrictAnswer decodes an answer as strictly as a request, allowing
// the one null the protocol has (a signaled leader's exit).
func decodeStrictAnswer(raw []byte, v any) error { return decodeStrict(raw, v, "exit") }
