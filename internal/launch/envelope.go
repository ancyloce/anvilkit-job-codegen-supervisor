// Package launch holds the launch inputs of one codegen Job: the typed
// launch envelope of the jobs contract (contracts/jobs
// job.schema.json#/$defs/launchEnvelope), read with a strict, structural
// check, and the inputs it binds — protected fixtures of the image and
// artifacts loaded through the access sidecar — staged into the
// candidate-readable input directory against their digests. The trusted
// harness deliberately does not link the
// contracts' jobschema package: that package embeds profiles.json, which
// records this image's own digest, and an image whose bytes depend on its
// own digest can never be pinned. The sidecar validates the same envelope
// and Control validates every manifest and profile against the schema.
package launch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

var (
	idPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	sequencePattern    = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)
	launchKeyPattern   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	inputNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	componentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	puckTypePattern    = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,63}$`)
	jobKinds           = map[string]bool{"codegen": true, "validator": true, "preview": true, "parser": true, "migration": true}
)

// Input is one typed input: a name bound to a digest and, optionally, an
// opaque handle.
type Input struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Handle string `json:"handle,omitempty"`
}

// Component is what a launch certifies or produces (P0.8), optional in the
// envelope: the source revision it binds, always, and the allocated
// identity — componentId, puckType and packageName, all three or none (a
// generation names them from its brief; a preview or release launch names
// the revision alone). The supervisor only checks its shape; the team
// coordinator binds it to the brief and a validator certifies against it.
type Component struct {
	ComponentID    *string `json:"componentId,omitempty"`
	PuckType       *string `json:"puckType,omitempty"`
	PackageName    *string `json:"packageName,omitempty"`
	SourceRevision string  `json:"sourceRevision"`
}

// Envelope is the launch envelope.
type Envelope struct {
	SchemaVersion   int        `json:"schemaVersion"`
	LaunchID        string     `json:"launchId"`
	LaunchKey       string     `json:"launchKey"`
	OperationID     string     `json:"operationId"`
	AttemptID       string     `json:"attemptId"`
	ProfileID       string     `json:"profileId"`
	ProfileRevision string     `json:"profileRevision"`
	JobKind         string     `json:"jobKind"`
	ExecutionEpoch  string     `json:"executionEpoch"`
	LaunchEpoch     string     `json:"launchEpoch"`
	Deadline        string     `json:"deadline"`
	Component       *Component `json:"component,omitempty"`
	Inputs          []Input    `json:"inputs"`
}

// Parse decodes and checks an envelope; unknown fields are refused.
func Parse(raw []byte) (Envelope, error) {
	var e Envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Envelope{}, fmt.Errorf("launch envelope: %v", err)
	}
	if dec.More() {
		return Envelope{}, fmt.Errorf("launch envelope: trailing data")
	}
	if e.SchemaVersion != 1 {
		return Envelope{}, fmt.Errorf("launch envelope: schemaVersion %d is not 1", e.SchemaVersion)
	}
	for name, v := range map[string]string{"launchId": e.LaunchID, "operationId": e.OperationID, "attemptId": e.AttemptID, "profileId": e.ProfileID} {
		if len(v) == 0 || len(v) > 128 || !idPattern.MatchString(v) {
			return Envelope{}, fmt.Errorf("launch envelope: %s %q is not an id", name, v)
		}
	}
	if !launchKeyPattern.MatchString(e.LaunchKey) {
		return Envelope{}, fmt.Errorf("launch envelope: launchKey %q is not a DNS label", e.LaunchKey)
	}
	for name, v := range map[string]string{"profileRevision": e.ProfileRevision, "executionEpoch": e.ExecutionEpoch, "launchEpoch": e.LaunchEpoch} {
		if !sequencePattern.MatchString(v) {
			return Envelope{}, fmt.Errorf("launch envelope: %s %q is not a sequence", name, v)
		}
	}
	if !jobKinds[e.JobKind] {
		return Envelope{}, fmt.Errorf("launch envelope: jobKind %q unknown", e.JobKind)
	}
	if _, err := e.DeadlineTime(); err != nil {
		return Envelope{}, err
	}
	if err := checkComponent(raw, e.Component); err != nil {
		return Envelope{}, err
	}
	if len(e.Inputs) > 64 {
		return Envelope{}, fmt.Errorf("launch envelope: more than 64 inputs")
	}
	seen := map[string]bool{}
	for _, in := range e.Inputs {
		if !inputNamePattern.MatchString(in.Name) || !digestPattern.MatchString(in.Digest) || len(in.Handle) > 256 || seen[in.Name] {
			return Envelope{}, fmt.Errorf("launch envelope: input %q is not a typed input", in.Name)
		}
		seen[in.Name] = true
	}
	return e, nil
}

// checkComponent holds the optional component to the contract: an object
// (an explicit null is not an absent member) with its sourceRevision, and
// the identity members all three or none, each of its form. Unknown
// members inside it are refused by the strict decoder.
func checkComponent(raw []byte, c *Component) error {
	if c == nil {
		var presence struct {
			Component json.RawMessage `json:"component"`
		}
		if err := json.Unmarshal(raw, &presence); err == nil && presence.Component != nil {
			return fmt.Errorf("launch envelope: component is not an object")
		}
		return nil
	}
	if !sequencePattern.MatchString(c.SourceRevision) {
		return fmt.Errorf("launch envelope: component.sourceRevision %q is not a sequence", c.SourceRevision)
	}
	named := 0
	for _, m := range []*string{c.ComponentID, c.PuckType, c.PackageName} {
		if m != nil {
			named++
		}
	}
	switch {
	case named == 0:
		return nil
	case named != 3:
		return fmt.Errorf("launch envelope: component names componentId, puckType and packageName all three or none")
	case !componentIDPattern.MatchString(*c.ComponentID):
		return fmt.Errorf("launch envelope: component.componentId %q is not a component id", *c.ComponentID)
	case !puckTypePattern.MatchString(*c.PuckType):
		return fmt.Errorf("launch envelope: component.puckType %q is not a Puck type", *c.PuckType)
	}
	if n := utf8.RuneCountInString(*c.PackageName); n < 1 || n > 214 {
		return fmt.Errorf("launch envelope: component.packageName is not 1 to 214 characters")
	}
	return nil
}

// DeadlineTime parses the RFC 3339 UTC deadline.
func (e Envelope) DeadlineTime() (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, e.Deadline)
	if err != nil || t.Location() != time.UTC {
		return time.Time{}, fmt.Errorf("launch envelope: deadline %q is not an RFC 3339 UTC timestamp", e.Deadline)
	}
	return t, nil
}
