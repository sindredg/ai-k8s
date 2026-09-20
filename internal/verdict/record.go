// Package verdict holds the triage verdict contract: four values, the record that carries one, and the schema that enforces the split between them.
package verdict

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sindredg/ai-k8s/internal/corpus"
)

// SchemaVersion is bumped when a field changes meaning. A reader checks it before trusting a record.
const SchemaVersion = "triage.v1"

// Value is the closed set of four verdicts. The spelling is a cross-repository contract:
// triage.tf alerts on jsonPayload.verdict != "accepted", so any other spelling pages the owner.
type Value string

const (
	Accepted             Value = "accepted"
	ContradictsDecision  Value = "contradicts_decision"
	New                  Value = "new"
	InsufficientEvidence Value = "insufficient_evidence"
)

// CorpusMatch records what deterministic resolution returned, as a field rather than a judgement the model makes.
type CorpusMatch string

const (
	MatchMatched CorpusMatch = "matched"
	MatchNone    CorpusMatch = "none"
)

// SettledBy says which half of the worker produced the verdict, which is the number Phase 15 publishes.
const (
	SettledByRules = "rules"
	SettledByModel = "model"
)

// Citation is one resolved corpus entry. Summary and Source come from the corpus, never from the caller.
type Citation struct {
	ID      corpus.ID `json:"id"`
	Summary string    `json:"summary,omitempty"`
	Source  string    `json:"source,omitempty"`
}

// FindingRef is what the record keeps of the finding. The metric extracts category and severity from here.
type FindingRef struct {
	CanonicalName string `json:"canonical_name"`
	Name          string `json:"name"`
	Category      string `json:"category"`
	ResourceName  string `json:"resource_name"`
	Severity      string `json:"severity"`
	State         string `json:"state"`
	EventTime     string `json:"event_time"`
	Class         string `json:"finding_class"`
	Digest        string `json:"digest"`
}

// ToolCall is empty in Phase 15 and present anyway, so Phase 17 adds a trace without bumping the schema version.
type ToolCall struct {
	Name   string `json:"name"`
	Result string `json:"result"`
}

// Provenance is what makes a verdict reproducible. The model fields stay empty until Increment 2.
type Provenance struct {
	CorpusCommit string `json:"corpus_commit"`
	AgentCommit  string `json:"agent_commit"`
	ImageDigest  string `json:"image_digest"`
	Model        string `json:"model,omitempty"`
	ModelParams  string `json:"model_params,omitempty"`
	PromptDigest string `json:"prompt_digest,omitempty"`
	InputTokens  int    `json:"input_tokens,omitempty"`
	OutputTokens int    `json:"output_tokens,omitempty"`
	CostEstimate string `json:"cost_estimate,omitempty"`
}

// Record is one verdict. It is written to the ledger and emitted as the log entry the alert policy reads.
type Record struct {
	SchemaVersion     string      `json:"schema_version"`
	Verdict           Value       `json:"verdict"`
	Finding           FindingRef  `json:"finding"`
	CorpusMatch       CorpusMatch `json:"corpus_match"`
	Citations         []Citation  `json:"citations"`
	Reasoning         string      `json:"reasoning"`
	MissingEvidence   []string    `json:"missing_evidence"`
	RecommendedAction string      `json:"recommended_action,omitempty"`
	Confidence        string      `json:"confidence,omitempty"`
	SettledBy         string      `json:"settled_by"`
	ToolCalls         []ToolCall  `json:"tool_calls"`
	Provenance        Provenance  `json:"provenance"`
}

// MarshalJSON writes the list fields as [] rather than null, so a reader never has to tell the two apart.
func (r Record) MarshalJSON() ([]byte, error) {
	type alias Record // Sheds the method, so this does not recurse.
	out := alias(r)
	if out.Citations == nil {
		out.Citations = []Citation{}
	}
	if out.MissingEvidence == nil {
		out.MissingEvidence = []string{}
	}
	if out.ToolCalls == nil {
		out.ToolCalls = []ToolCall{}
	}
	return json.Marshal(out)
}

// Validate enforces the verdict contract. Output that does not validate is rejected rather than parsed for meaning.
func (r Record) Validate() error {
	var problems []string

	if strings.TrimSpace(r.SchemaVersion) == "" {
		problems = append(problems, "no schema_version")
	}
	if strings.TrimSpace(r.SettledBy) == "" {
		problems = append(problems, "does not say whether rules or the model settled it")
	}
	if strings.TrimSpace(r.Finding.Digest) == "" {
		problems = append(problems, "no digest of the finding body")
	}
	if strings.TrimSpace(r.Finding.Category) == "" {
		problems = append(problems, "no finding category, which the metric extracts as a label")
	}
	if strings.TrimSpace(r.Finding.Severity) == "" {
		problems = append(problems, "no finding severity, which the metric extracts as a label")
	}

	switch r.Verdict {
	case Accepted, ContradictsDecision:
		if len(r.Citations) == 0 {
			problems = append(problems, fmt.Sprintf("%s cites nothing, and it asserts something about a recorded decision", r.Verdict))
		}
		if r.CorpusMatch != MatchMatched {
			problems = append(problems, fmt.Sprintf("%s requires corpus_match: matched", r.Verdict))
		}
	case New:
		if r.CorpusMatch != MatchNone {
			problems = append(problems, "new requires corpus_match: none recorded explicitly")
		}
		if len(r.Citations) > 0 {
			problems = append(problems, "new cites a corpus entry, so resolution found a match and the verdict is not new")
		}
	case InsufficientEvidence:
		if len(r.MissingEvidence) == 0 {
			problems = append(problems, "insufficient_evidence lists no missing evidence")
		}
	default:
		problems = append(problems, fmt.Sprintf("verdict %q is outside the closed set", r.Verdict))
	}

	if len(problems) > 0 {
		return fmt.Errorf("verdict record is invalid: %s", strings.Join(problems, "; "))
	}
	return nil
}

// ResolveCitations replaces every citation with the corpus entry it names. A citation that does not
// resolve is an error, which is what stops injected text manufacturing evidence.
func (r *Record) ResolveCitations(idx *corpus.Index) error {
	var unresolved []string
	for i, c := range r.Citations {
		e, ok := idx.Lookup(c.ID)
		if !ok {
			unresolved = append(unresolved, string(c.ID))
			continue
		}
		r.Citations[i] = Citation{ID: e.ID, Summary: e.Summary, Source: e.Source}
	}
	if len(unresolved) > 0 {
		return fmt.Errorf("citations do not resolve: %s", strings.Join(unresolved, ", "))
	}
	return nil
}
