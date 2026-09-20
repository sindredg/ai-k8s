package corpus

import (
	"strings"
	"testing"
)

func TestLoadThreatModelReadsTheFindingsTableOnly(t *testing.T) {
	idx := NewIndex()
	if err := LoadThreatModel(idx, "testdata/threat-model.md"); err != nil {
		t.Fatalf("LoadThreatModel returned %v", err)
	}

	// The trust boundaries table above Findings is also numbered, and must not be read as findings.
	if len(idx.Entries) != 3 {
		t.Errorf("loaded %d entries, want 3", len(idx.Entries))
	}
	for _, id := range []ID{ThreatID(1), ThreatID(10), ThreatID(11)} {
		if _, ok := idx.Lookup(id); !ok {
			t.Errorf("entry %q is missing", id)
		}
	}
}

func TestLoadThreatModelCarriesTheFindingAndItsStatus(t *testing.T) {
	idx := NewIndex()
	if err := LoadThreatModel(idx, "testdata/threat-model.md"); err != nil {
		t.Fatalf("LoadThreatModel returned %v", err)
	}
	e, _ := idx.Lookup(ThreatID(10))
	if !strings.Contains(e.Summary, "No provenance, SBOM, signature, or admission policy") {
		t.Errorf("Summary = %q, want the finding text", e.Summary)
	}
	if !strings.Contains(e.Summary, "Accepted for now") {
		t.Errorf("Summary = %q, want the status, because an accepted finding reads differently from a closed one", e.Summary)
	}
}

func TestLoadThreatModelRejectsAFileWithNoFindingsTable(t *testing.T) {
	if err := LoadThreatModel(NewIndex(), "testdata/threat-model-no-table.md"); err == nil {
		t.Fatal("LoadThreatModel accepted a threat model carrying no findings table")
	}
}

func TestLoadDecisionsAnchorsEachHeading(t *testing.T) {
	idx := NewIndex()
	if err := LoadDecisions(idx, "testdata/decisions.md"); err != nil {
		t.Fatalf("LoadDecisions returned %v", err)
	}
	for _, id := range []ID{
		DecisionID("agent-namespace"),
		DecisionID("agent-permission-boundary"),
		DecisionID("project-focus"),
	} {
		if _, ok := idx.Lookup(id); !ok {
			t.Errorf("entry %q is missing", id)
		}
	}
}

func TestLoadDecisionsUsesTheDecisionLineAsTheSummary(t *testing.T) {
	idx := NewIndex()
	if err := LoadDecisions(idx, "testdata/decisions.md"); err != nil {
		t.Fatalf("LoadDecisions returned %v", err)
	}
	e, _ := idx.Lookup(DecisionID("agent-permission-boundary"))
	if e.Summary != "The triage worker holds four grants and nothing else." {
		t.Errorf("Summary = %q, want the Decision line with its label stripped", e.Summary)
	}
}

func TestLoadDecisionsSkipsAHeadingCarryingNoDecision(t *testing.T) {
	idx := NewIndex()
	if err := LoadDecisions(idx, "testdata/decisions.md"); err != nil {
		t.Fatalf("LoadDecisions returned %v", err)
	}
	if _, ok := idx.Lookup(DecisionID("deferred-decision-records")); ok {
		t.Error("a heading with no Decision line became a citable entry")
	}
	if len(idx.Entries) != 3 {
		t.Errorf("loaded %d entries, want 3", len(idx.Entries))
	}
}

func TestLoadDecisionsReportsWhatItSkipped(t *testing.T) {
	idx := NewIndex()
	if err := LoadDecisions(idx, "testdata/decisions.md"); err != nil {
		t.Fatalf("LoadDecisions returned %v", err)
	}
	if got := idx.SkippedDecisions; len(got) != 1 || got[0] != "Deferred decision records" {
		t.Errorf("SkippedDecisions = %v, want the one heading with no Decision line", got)
	}
}

func TestAnchorMatchesGitHubHeadingSlugs(t *testing.T) {
	cases := map[string]string{
		"Agent permission boundary":      "agent-permission-boundary",
		"The human merge boundary":       "the-human-merge-boundary",
		"sky resource size":              "sky-resource-size",
		"Pod Security Standards":         "pod-security-standards",
		"Read-only root filesystem":      "read-only-root-filesystem",
		"Terraform state and automation": "terraform-state-and-automation",
	}
	for heading, want := range cases {
		if got := Anchor(heading); got != want {
			t.Errorf("Anchor(%q) = %q, want %q", heading, got, want)
		}
	}
}
