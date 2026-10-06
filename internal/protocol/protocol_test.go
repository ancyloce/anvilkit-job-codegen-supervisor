package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const validLine = `{"type":"run-candidate","protocolVersion":1,"requestId":1,"round":1,"roundDir":"/workspace/round/1"}`

// What the fixtures cannot state, because it is not a JSON instance: the
// line itself. Each of these ends the protocol.
func TestRequestLinesAreStrict(t *testing.T) {
	for name, line := range map[string]string{
		"duplicate member":                      `{"type":"run-candidate","protocolVersion":1,"requestId":1,"round":1,"round":2,"roundDir":"/workspace/round/1"}`,
		"duplicate member by escape":            `{"type":"run-candidate","protocolVersion":1,"requestId":1,"round":1,"round":2,"roundDir":"/workspace/round/1"}`,
		"null member":                           `{"type":"run-candidate","protocolVersion":1,"requestId":null,"round":1,"roundDir":"/workspace/round/1"}`,
		"unknown member":                        `{"type":"run-candidate","protocolVersion":1,"requestId":1,"round":1,"roundDir":"/workspace/round/1","env":["X=1"]}`,
		"trailing data":                         validLine + ` {}`,
		"two objects":                           validLine + validLine,
		"not an object":                         `["run-candidate"]`,
		"empty line":                            ``,
		"not UTF-8":                             "{\"type\":\"run-candidate\xff\"}",
		"string number":                         `{"type":"run-candidate","protocolVersion":1,"requestId":"1","round":1,"roundDir":"/workspace/round/1"}`,
		"fractional number":                     `{"type":"run-candidate","protocolVersion":1,"requestId":1.5,"round":1,"roundDir":"/workspace/round/1"}`,
		"traversal":                             `{"type":"run-candidate","protocolVersion":1,"requestId":1,"round":1,"roundDir":"/workspace/../round/1"}`,
		"comment":                               `{"type":"run-candidate", /* */ "protocolVersion":1,"requestId":1,"round":1,"roundDir":"/workspace/round/1"}`,
		"an answer is no request":               `{"type":"refused","protocolVersion":1,"requestId":1,"round":1,"code":"TEAM_ENDED","reason":"x"}`,
		"another protocol version":              strings.Replace(validLine, `"protocolVersion":1`, `"protocolVersion":2`, 1),
		"nested duplicate in an unknown member": `{"type":"run-candidate","protocolVersion":1,"requestId":1,"round":1,"roundDir":"/workspace/round/1","x":{"a":1,"a":2}}`,
	} {
		_, err := DecodeRequest([]byte(line))
		var v *Violation
		require.ErrorAs(t, err, &v, name)
	}
	req, err := DecodeRequest([]byte(validLine))
	require.NoError(t, err)
	require.Equal(t, Request{Type: TypeRunCandidate, ProtocolVersion: 1, RequestID: 1, Round: 1, RoundDir: "/workspace/round/1"}, req)
}

func TestReaderBoundsAndEnds(t *testing.T) {
	// Requests in order, then a clean end of the channel.
	r := NewReader(strings.NewReader(validLine + "\n" + strings.Replace(validLine, `"requestId":1`, `"requestId":2`, 1) + "\n"))
	for _, id := range []int{1, 2} {
		req, err := r.Next()
		require.NoError(t, err)
		require.Equal(t, id, req.RequestID)
	}
	_, err := r.Next()
	require.ErrorIs(t, err, io.EOF)

	// A line one byte over the bound, its newline included, is refused
	// without being decoded; one at the bound is read and decoded (here
	// refused only for its oversize directory, which the schema bounds).
	pad := func(total int) string {
		prefix := `{"type":"run-candidate","protocolVersion":1,"requestId":1,"round":1,"roundDir":"/`
		suffix := `/round/1"}`
		return prefix + strings.Repeat("a", total-1-len(prefix)-len(suffix)) + suffix + "\n"
	}
	at := pad(MaxLineBytes)
	require.Len(t, at, MaxLineBytes)
	_, err = NewReader(strings.NewReader(at)).Next()
	var v *Violation
	require.ErrorAs(t, err, &v)
	require.NotContains(t, v.Reason, "exceeds", "a line at the bound is decoded")
	require.Contains(t, v.Reason, "roundDir")
	_, err = NewReader(strings.NewReader(pad(MaxLineBytes + 1))).Next()
	require.ErrorAs(t, err, &v)
	require.Contains(t, v.Reason, "exceeds")

	// A channel that closes inside a line is a violation, never a request.
	_, err = NewReader(strings.NewReader(validLine)).Next()
	require.ErrorAs(t, err, &v)
}

func TestAnswersAreTheSchemasShape(t *testing.T) {
	req := Request{Type: TypeRunCandidate, ProtocolVersion: 1, RequestID: 3, Round: 2, RoundDir: "/w/round/2"}
	started, ended := time.Date(2026, 10, 6, 10, 0, 0, 5, time.UTC), time.Date(2026, 10, 6, 10, 0, 4, 0, time.UTC)
	code := 0
	var buf bytes.Buffer
	require.NoError(t, WriteAnswer(&buf, Ended(req, StopExited, &code, "ignored", 0, started, ended)))
	require.JSONEq(t, `{"type":"candidate-ended","protocolVersion":1,"requestId":3,"round":2,"stop":"exited","exit":0,"descendantsStopped":0,"startedAt":"2026-10-06T10:00:00.000000005Z","endedAt":"2026-10-06T10:00:04Z"}`, buf.String())
	require.True(t, strings.HasSuffix(buf.String(), "}\n"))
	buf.Reset()
	require.NoError(t, WriteAnswer(&buf, Ended(req, StopTimeout, nil, "killed", 3, started, ended)))
	var killed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &killed))
	require.Nil(t, killed["exit"])
	require.Contains(t, killed, "exit", "exit is always present, null when a signal ended the leader")
	require.Equal(t, "killed", killed["signal"])
	buf.Reset()
	require.NoError(t, WriteAnswer(&buf, Refuse(req, RefusedStopNotEstablished, strings.Repeat("é", 400))))
	var refused Refused
	require.NoError(t, json.Unmarshal(buf.Bytes(), &refused))
	require.Len(t, []rune(refused.Reason), 300)
	require.Equal(t, RefusedRoundNotNew, Refuse(req, RefusedRoundNotNew, "").Reason, "a reason is never empty")
	require.Error(t, WriteAnswer(&buf, req), "a request is not written as an answer")
}

func TestTeamResultIsStrict(t *testing.T) {
	ok := `{"protocolVersion":1,"outcome":{"kind":"certified","detail":"d","round":1},"verdict":"certified","failureCode":"","stageId":"stg_1","existing":false,"counters":{"rounds":1,"reviewRounds":1,"repairs":0},"calls":12}`
	r, err := DecodeTeamResult([]byte(ok))
	require.NoError(t, err)
	require.Equal(t, "stg_1", r.StageID)
	require.Equal(t, 12, r.Calls)
	for name, doc := range map[string]string{
		"duplicate":         strings.Replace(ok, `"calls":12`, `"calls":12,"calls":13`, 1),
		"null stage":        strings.Replace(ok, `"stageId":"stg_1"`, `"stageId":null`, 1),
		"unknown member":    strings.Replace(ok, `"calls":12`, `"calls":12,"budget":{}`, 1),
		"partial counters":  strings.Replace(ok, `"repairs":0`, `"other":0`, 1),
		"no outcome detail": strings.Replace(ok, `"detail":"d",`, ``, 1),
		"oversize":          strings.Replace(ok, `"detail":"d"`, `"detail":"`+strings.Repeat("d", MaxResultBytes)+`"`, 1),
	} {
		_, err := DecodeTeamResult([]byte(doc))
		var v *Violation
		require.ErrorAs(t, err, &v, name)
	}
}
