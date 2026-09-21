package verdict

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sindredg/ai-k8s/internal/corpus"
)

func TestTheFourValuesAreSpelledExactlyAsTheAlertFilterReadsThem(t *testing.T) {
	// terraform/modules/observability/triage.tf filters on jsonPayload.verdict != "accepted".
	// Any other spelling matches that filter and pages the platform owner.
	cases := map[Value]string{
		Accepted:             "accepted",
		ContradictsDecision:  "contradicts_decision",
		New:                  "new",
		InsufficientEvidence: "insufficient_evidence",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("verdict spelled %q, want %q", got, want)
		}
	}
}

func TestTheVerdictFieldSerializesAsAPlainString(t *testing.T) {
	r := validRecord(Accepted)
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal returned %v", err)
	}
	if !strings.Contains(string(body), `"verdict":"accepted"`) {
		t.Errorf("record does not carry the verdict where the metric extracts it: %s", body)
	}
}

func TestTheRecordCarriesTheLabelsTheMetricExtracts(t *testing.T) {
	body, err := json.Marshal(validRecord(New))
	if err != nil {
		t.Fatalf("Marshal returned %v", err)
	}
	var payload struct {
		Verdict string `json:"verdict"`
		Finding struct {
			Category string `json:"category"`
			Severity string `json:"severity"`
		} `json:"finding"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("Unmarshal returned %v", err)
	}
	if payload.Verdict == "" || payload.Finding.Category == "" || payload.Finding.Severity == "" {
		t.Errorf("label extractors read verdict, finding.category and finding.severity; got %+v", payload)
	}
}

func citation(id corpus.ID) Citation {
	return Citation{ID: id, Summary: "a summary", Source: "a source"}
}

func validRecord(v Value) Record {
	r := Record{
		SchemaVersion: SchemaVersion,
		Verdict:       v,
		Finding: FindingRef{
			CanonicalName: "projects/421458901689/sources/s/locations/global/findings/e5d7b4",
			Name:          "organizations/o/sources/s/locations/global/findings/e5d7b4",
			Category:      "BINARY_AUTHORIZATION_DISABLED",
			ResourceName:  "//container.googleapis.com/projects/p/locations/l/clusters/k8-lab",
			Severity:      "MEDIUM",
			State:         "ACTIVE",
			EventTime:     "2026-09-19T22:05:22.735Z",
			Class:         "MISCONFIGURATION",
			Digest:        "sha256:abc",
		},
		SettledBy:   SettledByRules,
		Reasoning:   "Resolution matched the corpus.",
		CorpusMatch: MatchMatched,
		Citations:   []Citation{citation(corpus.ThreatID(10))},
		Provenance:  Provenance{CorpusCommit: "c", AgentCommit: "a", ImageDigest: "sha256:i"},
	}
	switch v {
	case New:
		r.CorpusMatch = MatchNone
		r.Citations = nil
	case InsufficientEvidence:
		r.CorpusMatch = MatchNone
		r.Citations = nil
		r.MissingEvidence = []string{"the finding body does not say whether admission refused the request"}
	}
	return r
}

func TestValidateAcceptsEachWellFormedVerdict(t *testing.T) {
	for _, v := range []Value{Accepted, ContradictsDecision, New, InsufficientEvidence} {
		if err := validRecord(v).Validate(); err != nil {
			t.Errorf("Validate rejected a well-formed %q record: %v", v, err)
		}
	}
}

func TestValidateRejectsAVerdictOutsideTheClosedSet(t *testing.T) {
	r := validRecord(Accepted)
	r.Verdict = "Accepted"
	if err := r.Validate(); err == nil {
		t.Fatal("Validate accepted a verdict spelled outside the closed set")
	}
}

func TestValidateRejectsAcceptedWithNoCitation(t *testing.T) {
	r := validRecord(Accepted)
	r.Citations = nil
	if err := r.Validate(); err == nil {
		t.Fatal("Validate accepted an accepted verdict citing nothing")
	}
}

func TestValidateRejectsContradictsDecisionWithNoCitation(t *testing.T) {
	r := validRecord(ContradictsDecision)
	r.Citations = nil
	if err := r.Validate(); err == nil {
		t.Fatal("Validate accepted a contradicts_decision verdict citing nothing")
	}
}

func TestValidateRejectsNewWhenResolutionReturnedAMatch(t *testing.T) {
	r := validRecord(New)
	r.CorpusMatch = MatchMatched
	if err := r.Validate(); err == nil {
		t.Fatal("Validate accepted a new verdict when resolution found a match")
	}
}

func TestValidateRejectsNewCarryingACitation(t *testing.T) {
	r := validRecord(New)
	r.Citations = []Citation{citation(corpus.ThreatID(10))}
	if err := r.Validate(); err == nil {
		t.Fatal("Validate accepted a new verdict citing a corpus entry")
	}
}

func TestValidateRequiresNewToRecordCorpusMatchNoneExplicitly(t *testing.T) {
	r := validRecord(New)
	r.CorpusMatch = ""
	if err := r.Validate(); err == nil {
		t.Fatal("Validate accepted a new verdict that does not record corpus_match: none")
	}
}

func TestValidateRejectsInsufficientEvidenceWithNoMissingEvidence(t *testing.T) {
	r := validRecord(InsufficientEvidence)
	r.MissingEvidence = nil
	if err := r.Validate(); err == nil {
		t.Fatal("Validate accepted insufficient_evidence listing nothing missing")
	}
}

func TestValidateRejectsARecordWithNoSchemaVersion(t *testing.T) {
	r := validRecord(Accepted)
	r.SchemaVersion = ""
	if err := r.Validate(); err == nil {
		t.Fatal("Validate accepted a record with no schema version")
	}
}

func TestValidateRejectsARecordWithNoFindingDigest(t *testing.T) {
	r := validRecord(Accepted)
	r.Finding.Digest = ""
	if err := r.Validate(); err == nil {
		t.Fatal("Validate accepted a record carrying no digest of the finding body")
	}
}

func TestValidateRejectsARecordThatDoesNotSayWhatSettledIt(t *testing.T) {
	r := validRecord(Accepted)
	r.SettledBy = ""
	if err := r.Validate(); err == nil {
		t.Fatal("Validate accepted a record that does not say whether rules or the model settled it")
	}
}

func TestToolCallsSerializeAsAnEmptyListRatherThanNull(t *testing.T) {
	// Phase 15 makes no tool calls. The field is present so Phase 17 does not bump the schema version.
	body, err := json.Marshal(validRecord(Accepted))
	if err != nil {
		t.Fatalf("Marshal returned %v", err)
	}
	if !strings.Contains(string(body), `"tool_calls":[]`) {
		t.Errorf("record does not carry an empty tool_calls list: %s", body)
	}
}

func TestResolveCitationsRejectsACitationThatDoesNotResolve(t *testing.T) {
	idx := corpus.NewIndex()
	if err := idx.Add(corpus.Entry{ID: corpus.ThreatID(10), Summary: "s", Source: "src"}); err != nil {
		t.Fatalf("Add returned %v", err)
	}
	r := validRecord(Accepted)
	r.Citations = []Citation{citation(corpus.DecisionID("invented-by-the-model"))}

	err := r.ResolveCitations(idx)
	if err == nil {
		t.Fatal("ResolveCitations accepted a citation that does not resolve")
	}
	if !strings.Contains(err.Error(), "decision:invented-by-the-model") {
		t.Errorf("error %q does not name the unresolved citation", err)
	}
}

func TestResolveCitationsFillsSummaryAndSourceFromTheCorpus(t *testing.T) {
	idx := corpus.NewIndex()
	if err := idx.Add(corpus.Entry{ID: corpus.ThreatID(10), Summary: "No provenance or signing.", Source: "threat-model.md#findings"}); err != nil {
		t.Fatalf("Add returned %v", err)
	}
	r := validRecord(Accepted)
	r.Citations = []Citation{{ID: corpus.ThreatID(10)}}

	if err := r.ResolveCitations(idx); err != nil {
		t.Fatalf("ResolveCitations returned %v", err)
	}
	if r.Citations[0].Summary != "No provenance or signing." {
		t.Errorf("Summary = %q, want it taken from the corpus rather than from the caller", r.Citations[0].Summary)
	}
	if r.Citations[0].Source != "threat-model.md#findings" {
		t.Errorf("Source = %q, want it taken from the corpus", r.Citations[0].Source)
	}
}

func TestTheModelCannotSettleAFindingAsAccepted(t *testing.T) {
	r := Record{
		SchemaVersion: SchemaVersion, Verdict: Accepted, SettledBy: SettledByModel, CorpusMatch: MatchMatched,
		Citations: []Citation{{ID: "threat:10"}},
		Finding:   FindingRef{Digest: "sha256:d", Category: "C", Severity: "LOW"},
	}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "never settles a finding as accepted") {
		t.Fatalf("got %v", err)
	}
	r.SettledBy = SettledByRules
	if err := r.Validate(); err != nil {
		t.Fatalf("the same record settled by rules is valid, got %v", err)
	}
}

func TestAContradictionOnAnUnmatchedFindingStandsOnItsCitations(t *testing.T) {
	r := Record{
		SchemaVersion: SchemaVersion, Verdict: ContradictsDecision, SettledBy: SettledByModel, CorpusMatch: MatchNone,
		Citations: []Citation{{ID: "control:pod-security-restricted"}},
		Finding:   FindingRef{Digest: "sha256:d", Category: "C", Severity: "LOW"},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("got %v", err)
	}
	r.Citations = nil
	if err := r.Validate(); err == nil {
		t.Fatal("a contradiction citing nothing validated")
	}
}
