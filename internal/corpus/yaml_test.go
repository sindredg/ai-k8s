package corpus

import (
	"strings"
	"testing"
)

func TestLoadControlsAddsOneEntryPerSlug(t *testing.T) {
	idx := NewIndex()
	if err := LoadControls(idx, "testdata/controls.yaml"); err != nil {
		t.Fatalf("LoadControls returned %v", err)
	}
	if len(idx.Entries) != 2 {
		t.Errorf("loaded %d entries, want 2", len(idx.Entries))
	}
	e, ok := idx.Lookup(ControlID("pod-security-restricted"))
	if !ok {
		t.Fatal("control:pod-security-restricted is missing")
	}
	if !strings.Contains(e.Summary, "restricted standard at admission") {
		t.Errorf("Summary = %q, want the statement", e.Summary)
	}
	if !strings.Contains(e.Source, "phase-15-scc-triage.md") {
		t.Errorf("Source = %q, want the worklog that proved the control", e.Source)
	}
}

func TestLoadControlsRejectsAControlWithNoProof(t *testing.T) {
	err := LoadControls(NewIndex(), "testdata/controls-no-proof.yaml")
	if err == nil {
		t.Fatal("LoadControls accepted a control with no proof")
	}
	if !strings.Contains(err.Error(), "unproven-control") {
		t.Errorf("error %q does not name the control", err)
	}
}

func TestLoadControlsRejectsAControlWithNoStatement(t *testing.T) {
	if err := LoadControls(NewIndex(), "testdata/controls-no-statement.yaml"); err == nil {
		t.Fatal("LoadControls accepted a control asserting nothing")
	}
}

func TestLoadMappingReadsCategoriesAndPairings(t *testing.T) {
	idx := NewIndex()
	if err := LoadMapping(idx, "testdata/mapping.yaml"); err != nil {
		t.Fatalf("LoadMapping returned %v", err)
	}
	if len(idx.Mapping) != 2 {
		t.Errorf("loaded %d categories, want 2", len(idx.Mapping))
	}
	pairings := idx.Mapping["BINARY_AUTHORIZATION_DISABLED"]
	if len(pairings) != 1 {
		t.Fatalf("loaded %d pairings, want 1", len(pairings))
	}
	if got := pairings[0].Resource; !strings.HasSuffix(got, "/clusters/k8-lab") {
		t.Errorf("Resource = %q, want the finding resourceName", got)
	}
	if len(pairings[0].Cite) != 2 {
		t.Errorf("loaded %d citations, want 2", len(pairings[0].Cite))
	}
}

func TestLoadMappingKeepsACategoryMappedToNothing(t *testing.T) {
	idx := NewIndex()
	if err := LoadMapping(idx, "testdata/mapping.yaml"); err != nil {
		t.Fatalf("LoadMapping returned %v", err)
	}
	if _, ok := idx.Mapping["PRIMITIVE_ROLES_USED"]; !ok {
		t.Error("a category mapped to nothing was dropped; the empty list is the record that it was reviewed")
	}
}

func TestLoadMappingThenValidateRejectsAPairingWithNoJustification(t *testing.T) {
	idx := NewIndex()
	if err := idx.Add(entry(ThreatID(10))); err != nil {
		t.Fatalf("Add returned %v", err)
	}
	if err := LoadMapping(idx, "testdata/mapping-no-why.yaml"); err != nil {
		t.Fatalf("LoadMapping returned %v", err)
	}
	if err := idx.Validate(); err == nil {
		t.Fatal("Validate accepted a mapping whose pairing has no why")
	}
}

func TestLoadMappingRejectsAnUnknownField(t *testing.T) {
	if err := LoadControls(NewIndex(), "testdata/mapping.yaml"); err == nil {
		t.Fatal("LoadControls accepted a mapping file; strict decoding should reject the unknown key")
	}
}
