package verdict

import (
	"strings"
	"testing"

	"github.com/sindredg/ai-k8s/internal/corpus"
	"github.com/sindredg/ai-k8s/internal/scc"
)

const cluster = "//container.googleapis.com/projects/p/locations/europe-north1-a/clusters/k8-lab"

func pricedIndex(t *testing.T) *corpus.Index {
	t.Helper()
	idx := corpus.NewIndex()
	for _, e := range []corpus.Entry{
		{ID: corpus.ThreatID(10), Summary: "No provenance, SBOM, signature, or admission policy. Accepted for now.", Source: "threat-model.md#findings"},
		{ID: corpus.CheckovID("CKV_GCP_66", "module.gke.google_container_cluster.main"), Summary: "CKV_GCP_66 is accepted.", Source: ".checkov.baseline"},
	} {
		if err := idx.Add(e); err != nil {
			t.Fatalf("Add returned %v", err)
		}
	}
	idx.Mapping = map[string][]corpus.Pairing{
		"BINARY_AUTHORIZATION_DISABLED": {{
			Resource: cluster,
			Cite:     []corpus.ID{corpus.ThreatID(10), corpus.CheckovID("CKV_GCP_66", "module.gke.google_container_cluster.main")},
			Why:      "Binary Authorization is off on this cluster, accepted as finding 10.",
		}},
	}
	if err := idx.Validate(); err != nil {
		t.Fatalf("Validate returned %v", err)
	}
	return idx
}

func finding(category, resource string) *scc.Envelope {
	return &scc.Envelope{
		Digest: "sha256:abc",
		Finding: scc.Finding{
			CanonicalName: "projects/421458901689/sources/s/locations/global/findings/e5d7b4",
			Name:          "organizations/o/sources/s/locations/global/findings/e5d7b4",
			Category:      category,
			ResourceName:  resource,
			Severity:      "MEDIUM",
			State:         "ACTIVE",
			EventTime:     "2026-09-19T22:05:22.735Z",
			FindingClass:  "MISCONFIGURATION",
		},
	}
}

func testProvenance() Provenance {
	return Provenance{CorpusCommit: "c0ffee", AgentCommit: "beef", ImageDigest: "sha256:img"}
}

func TestClassifyAcceptsAFindingTheCorpusPrices(t *testing.T) {
	r := Classify(finding("BINARY_AUTHORIZATION_DISABLED", cluster), pricedIndex(t), testProvenance())

	if r.Verdict != Accepted {
		t.Errorf("Verdict = %q, want accepted", r.Verdict)
	}
	if r.CorpusMatch != MatchMatched {
		t.Errorf("CorpusMatch = %q, want matched", r.CorpusMatch)
	}
	if len(r.Citations) != 2 {
		t.Errorf("cited %d entries, want 2", len(r.Citations))
	}
	if err := r.Validate(); err != nil {
		t.Errorf("Classify produced a record that does not validate: %v", err)
	}
}

func TestClassifyFillsCitationsFromTheCorpusNotTheFinding(t *testing.T) {
	r := Classify(finding("BINARY_AUTHORIZATION_DISABLED", cluster), pricedIndex(t), testProvenance())
	for _, c := range r.Citations {
		if c.Summary == "" || c.Source == "" {
			t.Errorf("citation %q carries no summary or source", c.ID)
		}
	}
}

func TestClassifyCallsAnUnmatchedFindingNew(t *testing.T) {
	r := Classify(finding("PRIMITIVE_ROLES_USED", cluster), pricedIndex(t), testProvenance())

	if r.Verdict != New {
		t.Errorf("Verdict = %q, want new", r.Verdict)
	}
	if r.CorpusMatch != MatchNone {
		t.Errorf("CorpusMatch = %q, want none recorded explicitly", r.CorpusMatch)
	}
	if len(r.Citations) != 0 {
		t.Errorf("a new verdict cited %d entries, want 0", len(r.Citations))
	}
	if err := r.Validate(); err != nil {
		t.Errorf("Classify produced a record that does not validate: %v", err)
	}
}

func TestClassifyCallsAKnownCategoryOnAnotherResourceNew(t *testing.T) {
	// The corpus prices Binary Authorization on one cluster. Another cluster is not covered by it.
	other := "//container.googleapis.com/projects/p/locations/europe-north1-a/clusters/someone-elses"
	r := Classify(finding("BINARY_AUTHORIZATION_DISABLED", other), pricedIndex(t), testProvenance())

	if r.Verdict != New {
		t.Errorf("Verdict = %q, want new; a decision about one resource does not cover another", r.Verdict)
	}
}

func TestClassifyRecordsThatRulesSettledIt(t *testing.T) {
	r := Classify(finding("BINARY_AUTHORIZATION_DISABLED", cluster), pricedIndex(t), testProvenance())
	if r.SettledBy != SettledByRules {
		t.Errorf("SettledBy = %q, want %q; Increment 1 calls no model", r.SettledBy, SettledByRules)
	}
}

func TestClassifyCarriesTheDigestAndProvenance(t *testing.T) {
	r := Classify(finding("BINARY_AUTHORIZATION_DISABLED", cluster), pricedIndex(t), testProvenance())
	if r.Finding.Digest != "sha256:abc" {
		t.Errorf("Digest = %q, want the digest of the finding body", r.Finding.Digest)
	}
	if r.Provenance.CorpusCommit != "c0ffee" || r.Provenance.AgentCommit != "beef" {
		t.Errorf("Provenance = %+v, want the commits the image was built from", r.Provenance)
	}
	if r.Provenance.Model != "" {
		t.Errorf("Model = %q, want empty; Increment 1 calls no model", r.Provenance.Model)
	}
}

func TestClassifyNeverEmitsContradictsDecisionWithoutAModel(t *testing.T) {
	// Deterministic resolution establishes that a decision covers this resource, never that it fails to hold.
	// Increment 2 is what can return contradicts_decision, and this records that boundary.
	for _, category := range []string{"BINARY_AUTHORIZATION_DISABLED", "PRIMITIVE_ROLES_USED"} {
		if got := Classify(finding(category, cluster), pricedIndex(t), testProvenance()).Verdict; got == ContradictsDecision {
			t.Errorf("Classify returned contradicts_decision for %q with no model", category)
		}
	}
}

func TestInsufficientListsWhatIsMissingAndValidates(t *testing.T) {
	env := finding("BINARY_AUTHORIZATION_DISABLED", cluster)
	r := Insufficient(env, []string{"the finding body does not say whether admission refused the request"}, testProvenance())

	if r.Verdict != InsufficientEvidence {
		t.Errorf("Verdict = %q, want insufficient_evidence", r.Verdict)
	}
	if len(r.MissingEvidence) != 1 {
		t.Errorf("MissingEvidence = %v, want the one thing that is missing", r.MissingEvidence)
	}
	if err := r.Validate(); err != nil {
		t.Errorf("Insufficient produced a record that does not validate: %v", err)
	}
}

func TestInsufficientValidatesEvenWhenTheFindingBarelyParsed(t *testing.T) {
	// A message missing category and severity still has to produce a record the metric can label.
	env := &scc.Envelope{Digest: "sha256:abc", Finding: scc.Finding{CanonicalName: "projects/p/findings/x"}}
	r := Insufficient(env, []string{"category", "severity"}, testProvenance())

	if err := r.Validate(); err != nil {
		t.Fatalf("Insufficient produced a record that does not validate: %v", err)
	}
	if r.Finding.Category != UnparseableCategory {
		t.Errorf("Category = %q, want %q", r.Finding.Category, UnparseableCategory)
	}
	if !strings.HasPrefix(r.Finding.Severity, "SEVERITY_") {
		t.Errorf("Severity = %q, want a Security Command Center severity spelling", r.Finding.Severity)
	}
}

func TestInsufficientRefusesAnEmptyMissingList(t *testing.T) {
	// The caller must say what is missing. A silent abstention is the failure this verdict exists to make visible.
	r := Insufficient(finding("X", cluster), nil, testProvenance())
	if err := r.Validate(); err == nil {
		t.Fatal("Insufficient with nothing missing produced a record that validates")
	}
}
