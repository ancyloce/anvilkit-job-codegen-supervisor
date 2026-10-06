// Package protocol is the supervisor's side of the codegen Job's process
// protocol (urn:anvilkit:codegen-protocol:v1, owned by the contracts
// repository at jobs/codegen/protocol.schema.json; the copy under
// contract/ is verified against that source by tools/sync-protocol.sh and
// by the tests here): newline-delimited JSON on the trusted coordinator's
// stdio. The supervisor decodes run-candidate requests and the
// coordinator's team result strictly — one object, no duplicate or unknown
// member, no null, no trailing data, bounded size — and encodes the
// candidate-ended and refused answers. It deliberately does not link the
// contracts' Go module: that module embeds the job profiles, which pin this
// image's own digest.
package protocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
	"unicode/utf8"
)

const (
	// Version is the protocolVersion every message carries.
	Version = 1
	// MaxLineBytes bounds one protocol line, its newline included.
	MaxLineBytes = 65536
	// MaxResultBytes bounds the team result document.
	MaxResultBytes = 262144
	// MaxRound is the highest round number.
	MaxRound = 64
	// maxReason bounds a refusal's reason (characters).
	maxReason = 300
)

// Message types.
const (
	TypeRunCandidate   = "run-candidate"
	TypeCandidateEnded = "candidate-ended"
	TypeRefused        = "refused"
)

// Stop reasons of a candidate-ended answer.
const (
	StopExited   = "exited"
	StopTimeout  = "timeout"
	StopCanceled = "canceled"
)

// Refusal codes. CandidateNotRun and StopNotEstablished are final for the
// launch: nothing is sealed or submitted after them and no round runs.
const (
	RefusedRoundNotNew        = "ROUND_NOT_NEW"
	RefusedRoundDirInvalid    = "ROUND_DIR_INVALID"
	RefusedTeamEnded          = "TEAM_ENDED"
	RefusedCandidateNotRun    = "CANDIDATE_NOT_RUN"
	RefusedStopNotEstablished = "STOP_NOT_ESTABLISHED"
)

// StopReasons, RefusalCodes, OutcomeKinds and Verdicts are the schema's
// enumerations (checked against the contract by the tests).
var (
	StopReasons  = []string{StopExited, StopTimeout, StopCanceled}
	RefusalCodes = []string{RefusedRoundNotNew, RefusedRoundDirInvalid, RefusedTeamEnded, RefusedCandidateNotRun, RefusedStopNotEstablished}
	OutcomeKinds = []string{"certified", "repairable", "invalid", "infrastructure_failed", "validation_unavailable", "budget_exhausted", "deadline", "model_denied", "effect_uncertain", "canceled", "failed"}
	Verdicts     = []string{"certified", "repairable", "invalid", "infrastructure_failed", "canceled"}
)

var (
	roundDirPattern    = regexp.MustCompile(`^(?:/(?:[A-Za-z0-9_-]|\.[A-Za-z0-9_-]|\.\.[A-Za-z0-9._-])[A-Za-z0-9._-]*)*/round/(?:[1-9]|[1-5][0-9]|6[0-4])$`)
	failureCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	stageIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	signalPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9 ]{0,47}$`)
)

// Violation is a message outside the protocol. It ends the protocol: the
// supervisor answers nothing and stops the coordinator.
type Violation struct{ Reason string }

func (v *Violation) Error() string { return "protocol violation: " + v.Reason }

func violation(format string, args ...any) error {
	return &Violation{Reason: fmt.Sprintf(format, args...)}
}

// Request is a run-candidate request.
type Request struct {
	Type            string `json:"type"`
	ProtocolVersion int    `json:"protocolVersion"`
	RequestID       int    `json:"requestId"`
	Round           int    `json:"round"`
	RoundDir        string `json:"roundDir"`
}

// CandidateEnded answers a request after the candidate ended and its stop
// was confirmed. Exit is null when a signal ended the leader (Signal then
// names it).
type CandidateEnded struct {
	Type               string `json:"type"`
	ProtocolVersion    int    `json:"protocolVersion"`
	RequestID          int    `json:"requestId"`
	Round              int    `json:"round"`
	Stop               string `json:"stop"`
	Exit               *int   `json:"exit"`
	Signal             string `json:"signal,omitempty"`
	DescendantsStopped int    `json:"descendantsStopped"`
	StartedAt          string `json:"startedAt"`
	EndedAt            string `json:"endedAt"`
}

// Refused answers a request whose round did not run, or whose outcome
// cannot be established.
type Refused struct {
	Type            string `json:"type"`
	ProtocolVersion int    `json:"protocolVersion"`
	RequestID       int    `json:"requestId"`
	Round           int    `json:"round"`
	Code            string `json:"code"`
	Reason          string `json:"reason"`
}

// Ended builds a candidate-ended answer.
func Ended(req Request, stop string, exit *int, signal string, stopped int, started, ended time.Time) CandidateEnded {
	a := CandidateEnded{Type: TypeCandidateEnded, ProtocolVersion: Version, RequestID: req.RequestID, Round: req.Round, Stop: stop, Exit: exit, DescendantsStopped: stopped, StartedAt: timestamp(started), EndedAt: timestamp(ended)}
	if exit == nil {
		a.Signal = signal
		if !signalPattern.MatchString(a.Signal) {
			a.Signal = "unknown signal"
		}
	}
	return a
}

// Refuse builds a refused answer; the reason is bounded and never empty.
func Refuse(req Request, code, reason string) Refused {
	if reason == "" {
		reason = code
	}
	if utf8.RuneCountInString(reason) > maxReason {
		reason = string([]rune(reason)[:maxReason])
	}
	return Refused{Type: TypeRefused, ProtocolVersion: Version, RequestID: req.RequestID, Round: req.Round, Code: code, Reason: reason}
}

func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// WriteAnswer writes one answer line.
func WriteAnswer(w io.Writer, answer any) error {
	switch answer.(type) {
	case CandidateEnded, Refused:
	default:
		return fmt.Errorf("protocol: %T is not an answer", answer)
	}
	raw, err := json.Marshal(answer)
	if err != nil {
		return err
	}
	if len(raw)+1 > MaxLineBytes {
		return fmt.Errorf("protocol: answer of %d bytes exceeds the line bound", len(raw)+1)
	}
	_, err = w.Write(append(raw, '\n'))
	return err
}

// Reader reads run-candidate requests, one per line.
type Reader struct{ r *bufio.Reader }

// NewReader reads requests from r (the coordinator's stdout).
func NewReader(r io.Reader) *Reader { return &Reader{r: bufio.NewReaderSize(r, MaxLineBytes)} }

// Next returns the next request; io.EOF when the channel closed at a line
// boundary, a *Violation for anything that is not a valid request line.
func (r *Reader) Next() (Request, error) {
	line, err := r.r.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		return Request{}, violation("a line exceeds %d bytes", MaxLineBytes)
	case errors.Is(err, io.EOF) && len(line) == 0:
		return Request{}, io.EOF
	case errors.Is(err, io.EOF):
		return Request{}, violation("the channel closed inside a line")
	case err != nil:
		return Request{}, err
	}
	return DecodeRequest(line[:len(line)-1])
}

// DecodeRequest decodes one request line (without its newline).
func DecodeRequest(line []byte) (Request, error) {
	var req Request
	if err := decodeStrict(line, &req); err != nil {
		return Request{}, err
	}
	switch {
	case req.Type != TypeRunCandidate:
		return Request{}, violation("type %q is not a request", req.Type)
	case req.ProtocolVersion != Version:
		return Request{}, violation("protocolVersion %d is not %d", req.ProtocolVersion, Version)
	case req.RequestID < 1 || req.RequestID > 2147483647:
		return Request{}, violation("requestId %d is outside 1..2147483647", req.RequestID)
	case req.Round < 1 || req.Round > MaxRound:
		return Request{}, violation("round %d is outside 1..%d", req.Round, MaxRound)
	case len(req.RoundDir) > 4096 || !roundDirPattern.MatchString(req.RoundDir):
		return Request{}, violation("roundDir is not an absolute clean round directory")
	}
	return req, nil
}

// TeamResult is the coordinator's result document (team/result.json).
type TeamResult struct {
	ProtocolVersion int       `json:"protocolVersion"`
	Outcome         Outcome   `json:"outcome"`
	Verdict         string    `json:"verdict"`
	FailureCode     string    `json:"failureCode"`
	StageID         string    `json:"stageId"`
	Existing        bool      `json:"existing"`
	Counters        *Counters `json:"counters"`
	Calls           int       `json:"calls"`
	Error           string    `json:"error"`
}

// Outcome is the team outcome class.
type Outcome struct {
	Kind        string `json:"kind"`
	FailureCode string `json:"failureCode"`
	Detail      string `json:"detail"`
	Round       int    `json:"round"`
}

// Counters are the rounds, review rounds and repairs of the run.
type Counters struct {
	Rounds       int `json:"rounds"`
	ReviewRounds int `json:"reviewRounds"`
	Repairs      int `json:"repairs"`
}

// DecodeTeamResult decodes and checks the team result document.
func DecodeTeamResult(raw []byte) (TeamResult, error) {
	if len(raw) > MaxResultBytes {
		return TeamResult{}, violation("the team result exceeds %d bytes", MaxResultBytes)
	}
	var members map[string]json.RawMessage
	if err := decodeStrict(raw, &members); err != nil {
		return TeamResult{}, err
	}
	var r TeamResult
	if err := decodeStrict(raw, &r); err != nil {
		return TeamResult{}, err
	}
	for _, name := range []string{"protocolVersion", "outcome", "verdict", "failureCode"} {
		if _, ok := members[name]; !ok {
			return TeamResult{}, violation("the team result has no %s", name)
		}
	}
	var outcome map[string]json.RawMessage
	if err := json.Unmarshal(members["outcome"], &outcome); err != nil {
		return TeamResult{}, violation("outcome: %v", err)
	}
	for _, name := range []string{"kind", "detail"} {
		if _, ok := outcome[name]; !ok {
			return TeamResult{}, violation("outcome has no %s", name)
		}
	}
	_, hasRound := outcome["round"]
	_, hasOutcomeCode := outcome["failureCode"]
	switch {
	case r.ProtocolVersion != Version:
		return TeamResult{}, violation("protocolVersion %d is not %d", r.ProtocolVersion, Version)
	case !contains(OutcomeKinds, r.Outcome.Kind):
		return TeamResult{}, violation("outcome kind %q is not a team outcome", r.Outcome.Kind)
	case hasOutcomeCode && !failureCodePattern.MatchString(r.Outcome.FailureCode):
		return TeamResult{}, violation("outcome failureCode %q is not a failure code", r.Outcome.FailureCode)
	case utf8.RuneCountInString(r.Outcome.Detail) > 1000:
		return TeamResult{}, violation("outcome detail exceeds 1000 characters")
	case hasRound && (r.Outcome.Round < 1 || r.Outcome.Round > MaxRound):
		return TeamResult{}, violation("outcome round %d is outside 1..%d", r.Outcome.Round, MaxRound)
	case !contains(Verdicts, r.Verdict):
		return TeamResult{}, violation("verdict %q is not a team verdict", r.Verdict)
	case r.FailureCode != "" && !failureCodePattern.MatchString(r.FailureCode):
		return TeamResult{}, violation("failureCode %q is not a failure code", r.FailureCode)
	case hasMember(members, "stageId") && !stageIDPattern.MatchString(r.StageID):
		return TeamResult{}, violation("stageId %q is not an id", r.StageID)
	case r.Counters != nil && !r.Counters.within():
		return TeamResult{}, violation("counters are outside 0..%d", MaxRound)
	case r.Calls < 0 || r.Calls > 1000000:
		return TeamResult{}, violation("calls %d is outside 0..1000000", r.Calls)
	case utf8.RuneCountInString(r.Error) > 1000:
		return TeamResult{}, violation("error exceeds 1000 characters")
	case r.Verdict == "certified" && (r.FailureCode != "" || r.StageID == ""):
		return TeamResult{}, violation("a certified result names its stage and no failure code")
	}
	if hasMember(members, "counters") {
		var counters map[string]json.RawMessage
		_ = json.Unmarshal(members["counters"], &counters)
		for _, name := range []string{"rounds", "reviewRounds", "repairs"} {
			if _, ok := counters[name]; !ok {
				return TeamResult{}, violation("counters have no %s", name)
			}
		}
	}
	return r, nil
}

func (c Counters) within() bool {
	for _, n := range []int{c.Rounds, c.ReviewRounds, c.Repairs} {
		if n < 0 || n > MaxRound {
			return false
		}
	}
	return true
}

func hasMember(m map[string]json.RawMessage, name string) bool { _, ok := m[name]; return ok }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// decodeStrict decodes one JSON object into v: valid UTF-8, no duplicate
// member name at any depth, no null except for the named top-level members,
// no member v does not declare, nothing after the object.
func decodeStrict(raw []byte, v any, nullable ...string) error {
	if !utf8.Valid(raw) {
		return violation("not UTF-8")
	}
	if err := checkMembers(raw, nullable); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return violation("%v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return violation("trailing data after the object")
	}
	return nil
}

// checkMembers walks the document's tokens: an object at the top, unique
// member names in every object, no null value but for the nullable
// top-level members.
func checkMembers(raw []byte, nullable []string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	first, err := dec.Token()
	if err != nil {
		return violation("%v", err)
	}
	if d, ok := first.(json.Delim); !ok || d != '{' {
		return violation("not a JSON object")
	}
	type frame struct {
		object bool
		names  map[string]bool
		key    bool   // the next token of an object is a member name
		member string // the member whose value comes next
	}
	stack := []*frame{{object: true, names: map[string]bool{}, key: true}}
	for len(stack) > 0 {
		tok, err := dec.Token()
		if err != nil {
			return violation("%v", err)
		}
		top := stack[len(stack)-1]
		if top.object && top.key {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				continue
			}
			name, _ := tok.(string)
			if top.names[name] {
				return violation("duplicate member %q", name)
			}
			top.names[name], top.key, top.member = true, false, name
			continue
		}
		if top.object {
			top.key = true
		}
		switch t := tok.(type) {
		case nil:
			if !(len(stack) == 1 && contains(nullable, top.member)) {
				return violation("null is not a value of member %q", top.member)
			}
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, &frame{object: true, names: map[string]bool{}, key: true})
			case '[':
				stack = append(stack, &frame{})
			case ']':
				stack = stack[:len(stack)-1]
			}
		}
	}
	return nil
}
