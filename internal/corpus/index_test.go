package corpus

import (
	"strings"
	"testing"
)

func entry(id ID) Entry {
	return Entry{ID: id, Summary: "a summary", Source: "a source"}
}

func TestAddRejectsAnIDCollision(t *testing.T) {
	idx := NewIndex()
	id := DecisionID("agent-namespace")
	if err := idx.Add(entry(id)); err != nil {
		t.Fatalf("first Add returned %v", err)
	}
	err := idx.Add(entry(id))
	if err == nil {
		t.Fatal("Add accepted a colliding id")
	}
	if !strings.Contains(err.Error(), string(id)) {
		t.Errorf("collision error %q does not name the id", err)
	}
}

func TestAddRejectsAMalformedID(t *testing.T) {
	idx := NewIndex()
	if err := idx.Add(entry("cve:CVE-2026-1234")); err == nil {
		t.Fatal("Add accepted an id with no known kind")
	}
}

func TestAddRejectsAnEntryWithNoSummary(t *testing.T) {
	idx := NewIndex()
	e := entry(ThreatID(11))
	e.Summary = ""
	if err := idx.Add(e); err == nil {
		t.Fatal("Add accepted an entry with no summary")
	}
}

func TestAddRecordsTheKindFromTheID(t *testing.T) {
	idx := NewIndex()
	if err := idx.Add(entry(ThreatID(11))); err != nil {
		t.Fatalf("Add returned %v", err)
	}
	got, ok := idx.Lookup(ThreatID(11))
	if !ok {
		t.Fatal("Lookup did not find the entry just added")
	}
	if got.Kind != KindThreat {
		t.Errorf("Kind = %q, want %q", got.Kind, KindThreat)
	}
}

func TestLookupReportsAnUnknownID(t *testing.T) {
	idx := NewIndex()
	if _, ok := idx.Lookup(ThreatID(99)); ok {
		t.Error("Lookup found an id that was never added")
	}
}

func validPairing() Pairing {
	return Pairing{
		Resource: "//container.googleapis.com/projects/p/locations/l/clusters/k8-lab",
		Cite:     []ID{ThreatID(10)},
		Why:      "The threat model finding names this cluster.",
	}
}

func indexWithThreat10(t *testing.T) *Index {
	t.Helper()
	idx := NewIndex()
	if err := idx.Add(entry(ThreatID(10))); err != nil {
		t.Fatalf("Add returned %v", err)
	}
	return idx
}

func TestValidateRejectsAPairingCitingAnUnknownID(t *testing.T) {
	idx := indexWithThreat10(t)
	p := validPairing()
	p.Cite = []ID{ThreatID(10), DecisionID("does-not-exist")}
	idx.Mapping = map[string][]Pairing{"BINARY_AUTHORIZATION_DISABLED": {p}}

	err := idx.Validate()
	if err == nil {
		t.Fatal("Validate accepted a citation that does not resolve")
	}
	if !strings.Contains(err.Error(), "decision:does-not-exist") {
		t.Errorf("error %q does not name the unresolved citation", err)
	}
}

func TestValidateRejectsAPairingWithNoJustification(t *testing.T) {
	idx := indexWithThreat10(t)
	p := validPairing()
	p.Why = "   "
	idx.Mapping = map[string][]Pairing{"BINARY_AUTHORIZATION_DISABLED": {p}}

	if err := idx.Validate(); err == nil {
		t.Fatal("Validate accepted a pairing with no justification")
	}
}

func TestValidateRejectsAPairingWithNoResource(t *testing.T) {
	idx := indexWithThreat10(t)
	p := validPairing()
	p.Resource = ""
	idx.Mapping = map[string][]Pairing{"BINARY_AUTHORIZATION_DISABLED": {p}}

	if err := idx.Validate(); err == nil {
		t.Fatal("Validate accepted a pairing naming no resource")
	}
}

func TestValidateRejectsAPairingCitingNothing(t *testing.T) {
	idx := indexWithThreat10(t)
	p := validPairing()
	p.Cite = nil
	idx.Mapping = map[string][]Pairing{"BINARY_AUTHORIZATION_DISABLED": {p}}

	if err := idx.Validate(); err == nil {
		t.Fatal("Validate accepted a pairing citing nothing")
	}
}

func TestValidateAcceptsACategoryMappedToNoPairings(t *testing.T) {
	idx := indexWithThreat10(t)
	idx.Mapping = map[string][]Pairing{"PRIMITIVE_ROLES_USED": {}}

	if err := idx.Validate(); err != nil {
		t.Errorf("Validate rejected a category with zero pairings: %v", err)
	}
}

func TestValidateAcceptsAWellFormedMapping(t *testing.T) {
	idx := indexWithThreat10(t)
	idx.Mapping = map[string][]Pairing{"BINARY_AUTHORIZATION_DISABLED": {validPairing()}}

	if err := idx.Validate(); err != nil {
		t.Errorf("Validate rejected a well-formed mapping: %v", err)
	}
}

func TestValidateRejectsAnEmptyCategory(t *testing.T) {
	idx := indexWithThreat10(t)
	idx.Mapping = map[string][]Pairing{"": {validPairing()}}

	if err := idx.Validate(); err == nil {
		t.Fatal("Validate accepted a mapping keyed on an empty category")
	}
}
