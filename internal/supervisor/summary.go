package supervisor

import (
	"encoding/json"
	"os"
	"time"
)

// Summary is what the supervisor leaves in the termination message:
// controlled identities and outcomes, nothing the candidate wrote.
type Summary struct {
	Outcome        string            `json:"outcome"`
	Verdict        string            `json:"verdict,omitempty"`
	FailureCode    string            `json:"failureCode,omitempty"`
	StageID        string            `json:"stageId,omitempty"`
	ResultHandle   string            `json:"resultHandle,omitempty"`
	EvidenceHandle string            `json:"evidenceHandle,omitempty"`
	Duplicate      *DuplicateCheck   `json:"duplicateSubmission,omitempty"`
	CandidateExit  *int              `json:"candidateExit,omitempty"`
	CandidateStop  string            `json:"candidateStop,omitempty"`
	Probes         map[string]string `json:"probes,omitempty"`
	Resources      string            `json:"trustedResources,omitempty"`
	Team           *TeamSummary      `json:"team,omitempty"`
	Error          string            `json:"error,omitempty"`
}

// TeamSummary is the coordinator's account of a team run (P12) as the
// termination message carries it: controlled identities, counts and
// outcome classes only.
type TeamSummary struct {
	Outcome      string `json:"outcome"`
	Rounds       int    `json:"rounds"`
	ReviewRounds int    `json:"reviewRounds"`
	Repairs      int    `json:"repairs"`
	Calls        int    `json:"calls"`
	Existing     bool   `json:"existingStage,omitempty"`
	Error        string `json:"error,omitempty"`
}

// DuplicateCheck records the second, deliberate submission of the same
// result: acceptance must be idempotent (same stage, existing), never a
// second stage.
type DuplicateCheck struct {
	Existing  bool `json:"existing"`
	SameStage bool `json:"sameStage"`
}

// Evidence is the trusted observer's report of the fixed task, uploaded as
// an evidence artifact and bound by the accepted stage.
type Evidence struct {
	SchemaVersion   int    `json:"schemaVersion"`
	LaunchID        string `json:"launchId"`
	AttemptID       string `json:"attemptId"`
	CandidateExit   *int   `json:"candidateExit"`
	CandidateSignal string `json:"candidateSignal,omitempty"`
	// CandidateStop is why candidate execution ended ("exited", "timeout",
	// "canceled") and DescendantsStopped how many of its processes the
	// stop had to signal; both are established by the supervisor's own
	// confirmation that nothing of the candidate still runs.
	CandidateStop      string            `json:"candidateStop"`
	DescendantsStopped int               `json:"descendantsStopped"`
	OutputFiles        []string          `json:"outputFiles"`
	Refused            map[string]string `json:"refusedEntries,omitempty"`
	Probes             json.RawMessage   `json:"probes,omitempty"`
	ResourcesDigest    string            `json:"trustedResourcesDigest"`
	ResourcesIntact    bool              `json:"trustedResourcesIntact"`
	ExpectedDigest     string            `json:"expectedResultDigest"`
	ObservedDigest     string            `json:"observedResultDigest,omitempty"`
	StartedAt          time.Time         `json:"startedAt"`
	CandidateStarted   *time.Time        `json:"candidateStartedAt,omitempty"`
	CandidateEnded     *time.Time        `json:"candidateEndedAt,omitempty"`
}

// terminate writes the termination message (bounded: the probe outcomes
// are dropped first) and logs the launch's end.
func (s *Supervisor) terminate(summary *Summary) {
	raw, err := json.Marshal(summary)
	if err != nil {
		return
	}
	if len(raw) > 4000 {
		summary.Probes = nil
		raw, _ = json.Marshal(summary)
	}
	if err := os.WriteFile(s.Config.Paths.TerminationLog, raw, 0o600); err != nil {
		s.Log.Warn("termination message not written", "error", err.Error())
	}
	s.Log.Info("launch finished", "outcome", summary.Outcome, "verdict", summary.Verdict, "stageId", summary.StageID, "resourcesDigest", summary.Resources)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
