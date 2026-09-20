package corpus

import (
	"strings"
	"testing"
)

func testSources() Sources {
	return Sources{
		CheckovBaseline: "testdata/checkov.baseline",
		ThreatModel:     "testdata/threat-model.md",
		Decisions:       "testdata/decisions.md",
		Controls:        "testdata/controls.yaml",
		Mapping:         "testdata/mapping-resolvable.yaml",
	}
}

func TestCompileLoadsEverySource(t *testing.T) {
	idx, err := Compile(testSources())
	if err != nil {
		t.Fatalf("Compile returned %v", err)
	}

	// 3 checkov, 3 threat model, 3 decisions, 2 controls.
	want := map[Kind]int{KindCheckov: 3, KindThreat: 3, KindDecision: 3, KindControl: 2}
	got := map[Kind]int{}
	for _, e := range idx.Entries {
		got[e.Kind]++
	}
	for kind, n := range want {
		if got[kind] != n {
			t.Errorf("loaded %d %s entries, want %d", got[kind], kind, n)
		}
	}
}

func TestCompileValidatesTheMappingAgainstTheEntries(t *testing.T) {
	s := testSources()
	s.Mapping = "testdata/mapping-unresolvable.yaml"

	_, err := Compile(s)
	if err == nil {
		t.Fatal("Compile accepted a mapping citing an id that does not exist")
	}
	if !strings.Contains(err.Error(), "does not resolve") {
		t.Errorf("error %q does not say the citation failed to resolve", err)
	}
}

func TestCompileReportsWhatItLoaded(t *testing.T) {
	idx, err := Compile(testSources())
	if err != nil {
		t.Fatalf("Compile returned %v", err)
	}
	report := idx.Report()

	for _, want := range []string{"checkov", "threat", "decision", "control", "Deferred decision records"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report does not mention %q:\n%s", want, report)
		}
	}
}

func TestCompileFailsOnAMissingSource(t *testing.T) {
	s := testSources()
	s.Decisions = "testdata/there-is-no-decisions-file"
	if _, err := Compile(s); err == nil {
		t.Fatal("Compile accepted a source path that does not exist")
	}
}

func TestCompiledIndexRoundTripsThroughJSON(t *testing.T) {
	// The worker reads the index the build emitted, so what corpusc writes must resolve identically.
	idx, err := Compile(testSources())
	if err != nil {
		t.Fatalf("Compile returned %v", err)
	}
	body, err := idx.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned %v", err)
	}

	back, err := Unmarshal(body)
	if err != nil {
		t.Fatalf("Unmarshal returned %v", err)
	}
	if len(back.Entries) != len(idx.Entries) {
		t.Errorf("round trip carried %d entries, want %d", len(back.Entries), len(idx.Entries))
	}
	if got := back.Resolve("BINARY_AUTHORIZATION_DISABLED", theCluster); len(got) != 1 {
		t.Errorf("the round-tripped index resolved %d citations, want 1", len(got))
	}
}

func TestUnmarshalRejectsAnIndexWhoseMappingNoLongerResolves(t *testing.T) {
	// A tampered or truncated index must not reach the worker as a usable corpus.
	body := []byte(`{"entries":{},"mapping":{"X":[{"resource":"r","cite":["threat:1"],"why":"w"}]}}`)
	if _, err := Unmarshal(body); err == nil {
		t.Fatal("Unmarshal accepted an index whose mapping does not resolve")
	}
}
