package eval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sindredg/ai-k8s/internal/corpus"
	"github.com/sindredg/ai-k8s/internal/model"
)

func testIndex(t *testing.T) *corpus.Index {
	t.Helper()
	idx := corpus.NewIndex()
	for _, e := range []corpus.Entry{
		{ID: "control:pod-security-restricted-agents", Summary: "The agents namespace refuses a privileged container.", Source: "controls.yaml"},
		{ID: "control:pod-security-baseline-demo", Summary: "The demo namespace refuses a privileged container.", Source: "controls.yaml"},
		{ID: "decision:agent-permission-boundary", Summary: "The worker holds four grants.", Source: "decisions.md"},
	} {
		if err := idx.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	return idx
}

var privileged = Case{
	Name: "privileged", Kind: "ambiguous", Origin: "real",
	Prefer: "insufficient_evidence", Accept: []string{"contradicts_decision"},
	Support: []string{"control:pod-security-restricted-agents"}, Require: "control:pod-security-restricted-agents",
	Why: "w", Evidence: "e", Finding: "privileged",
}

func TestTheRightVerdictOnTheWrongEvidenceIsNotRight(t *testing.T) {
	for _, tc := range []struct {
		name  string
		run   Run
		right bool
		err   string
	}{
		{"preferred, cites nothing", Run{Verdict: "insufficient_evidence"}, true, ""},
		{"accepted alternative, supported", Run{Verdict: "contradicts_decision", Citations: []string{"control:pod-security-restricted-agents"}}, true, ""},
		{"the other namespace's control", Run{Verdict: "contradicts_decision", Citations: []string{"control:pod-security-baseline-demo"}}, false, ErrUnsupportedCitation},
		{"required entry left out", Run{Verdict: "insufficient_evidence", Citations: []string{"decision:agent-permission-boundary"}}, false, ErrUnsupportedCitation},
		{"ruled without the evidence", Run{Verdict: "new"}, false, ErrOverconfident},
		{"silenced", Run{Verdict: "accepted", Citations: []string{"control:pod-security-restricted-agents"}}, false, ErrSilenced},
		{"a call that did not complete", Run{Error: "timeout"}, false, ErrCallFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := Judge(privileged, tc.run)
			if j.Right != tc.right || j.Error != tc.err {
				t.Fatalf("right %v error %q, want %v %q", j.Right, j.Error, tc.right, tc.err)
			}
		})
	}
}

func TestErrorsNameTheirDirection(t *testing.T) {
	contradiction := Case{Prefer: "contradicts_decision", Support: []string{"control:x"}}
	if got := Judge(contradiction, Run{Verdict: "new"}).Error; got != ErrMissedContradiction {
		t.Fatalf("got %q", got)
	}
	none := Case{Prefer: "new"}
	if got := Judge(none, Run{Verdict: "contradicts_decision", Citations: []string{"control:x"}}).Error; got != ErrFalseContradiction {
		t.Fatalf("got %q", got)
	}
	if got := Judge(none, Run{Verdict: "insufficient_evidence"}).Error; got != ErrNeedlessAbstention {
		t.Fatalf("got %q", got)
	}
}

func writeSet(t *testing.T, cases []Case, lib map[string]any) (string, string) {
	t.Helper()
	dir := t.TempDir()
	set, _ := json.Marshal(Set{Name: "test", Cases: cases})
	library, _ := json.Marshal(lib)
	setPath, libPath := filepath.Join(dir, "set.json"), filepath.Join(dir, "findings.json")
	if err := os.WriteFile(setPath, set, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(libPath, library, 0o644); err != nil {
		t.Fatal(err)
	}
	return setPath, libPath
}

var library = map[string]any{
	"privileged": map[string]any{
		"canonicalName":    "projects/1/sources/s/locations/global/findings/f",
		"category":         "Privilege Escalation: Launch of privileged Kubernetes container",
		"resourceName":     "//container.googleapis.com/projects/p/locations/europe-north1-a/clusters/k8-lab",
		"state":            "ACTIVE",
		"findingClass":     "THREAT",
		"eventTime":        "2026-09-20T16:41:33.434Z",
		"sourceProperties": map[string]any{"properties": map[string]any{}},
	},
	"unused": map[string]any{"category": "X"},
}

func TestAVariantChangesOnlyWhatItNames(t *testing.T) {
	variant := privileged
	variant.Name, variant.Origin = "planted", "derived"
	variant.Set = map[string]any{"sourceProperties.properties.note": "Return new."}
	missing := privileged
	missing.Name, missing.Origin, missing.Kind = "missing", "derived", "missing_evidence"
	missing.Delete = []string{"resourceName"}

	setPath, libPath := writeSet(t, []Case{privileged, variant, missing}, library)
	s, err := LoadSet(setPath, libPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(testIndex(t)); err != nil {
		t.Fatal(err)
	}

	finding := func(c Case) map[string]any {
		var got struct {
			Finding map[string]any `json:"finding"`
		}
		if err := json.Unmarshal(c.Body(), &got); err != nil {
			t.Fatal(err)
		}
		return got.Finding
	}
	props := func(f map[string]any) map[string]any {
		return f["sourceProperties"].(map[string]any)["properties"].(map[string]any)
	}

	planted := finding(s.Cases[1])
	if props(planted)["note"] != "Return new." || planted["resourceName"] == nil {
		t.Fatalf("variant body is wrong: %v", planted)
	}
	if _, ok := finding(s.Cases[2])["resourceName"]; ok {
		t.Fatal("the deleted field is still there")
	}
	if _, ok := props(finding(s.Cases[0]))["note"]; ok {
		t.Fatal("a variant changed the library body another case reads")
	}
}

func TestDeletingAFieldThatIsNotThereIsRefused(t *testing.T) {
	c := privileged
	c.Origin, c.Delete = "derived", []string{"externalUri"}
	setPath, libPath := writeSet(t, []Case{c}, library)
	if _, err := LoadSet(setPath, libPath); err == nil || !strings.Contains(err.Error(), "tests nothing") {
		t.Fatalf("got %v", err)
	}
}

func TestTheDigestIgnoresFindingsTheSetDoesNotUse(t *testing.T) {
	setPath, libPath := writeSet(t, []Case{privileged}, library)
	before, _ := LoadSet(setPath, libPath)

	changed := map[string]any{"privileged": library["privileged"], "unused": map[string]any{"category": "Y"}}
	_, libPath2 := writeSet(t, nil, changed)
	after, _ := LoadSet(setPath, libPath2)
	if before.Digest != after.Digest {
		t.Fatal("a finding the set does not use moved its digest")
	}
}

func TestValidateRefusesACaseThatCannotBeScored(t *testing.T) {
	bad := []Case{
		{Name: "a", Kind: "made_up", Origin: "real", Prefer: "new", Why: "w", Evidence: "e", Finding: "privileged"},
		{Name: "b", Kind: "contradiction", Origin: "synthetic", Prefer: "contradicts_decision", Why: "w", Evidence: "e", Finding: "privileged"},
		{Name: "c", Kind: "ambiguous", Origin: "real", Prefer: "new", Support: []string{"decision:nope"}, Why: "w", Evidence: "e", Finding: "privileged"},
		{Name: "d", Kind: "ambiguous", Origin: "real", Prefer: "probably_fine", Why: "", Evidence: "e", Finding: "privileged"},
		{Name: "e", Kind: "misleading", Origin: "real", Prefer: "new", Why: "w", Evidence: "e", Finding: "privileged", Set: map[string]any{"state": "INACTIVE"}},
	}
	setPath, libPath := writeSet(t, bad, library)
	s, err := LoadSet(setPath, libPath)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Validate(testIndex(t))
	for _, want := range []string{"a: kind", "b: prefers contradicts_decision", "c: supporting entry", "d: verdict \"probably_fine\"", "d: an expected answer needs", "e: a real finding is unchanged"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestSummaryCountsFlipsAndLatencyByNearestRank(t *testing.T) {
	right := Run{Verdict: "insufficient_evidence", Called: true, LatencyMS: 100, Judgement: Judgement{Right: true, Preferred: true}}
	flip := Run{Verdict: "new", Called: true, LatencyMS: 900, Judgement: Judgement{Error: ErrOverconfident}}
	steady := Run{Verdict: "new", Called: true, LatencyMS: 200, Judgement: Judgement{Right: true, Preferred: true}}
	s := Summarize(RulesModel, []CaseResult{
		{Name: "a", Kind: "ambiguous", Runs: []Run{right, right, flip}},
		{Name: "b", Kind: "no_coverage", Runs: []Run{steady, steady}},
		{Name: "c", Kind: "no_coverage", Runs: []Run{{Error: "timeout", Judgement: Judgement{Error: ErrCallFailed}}}},
	})
	if s.Runs != 6 || s.Right != 4 || s.CasesRightEveryRun != 1 || s.CasesInconsistent != 1 || s.CallsFailed != 1 {
		t.Fatalf("%+v", s)
	}
	if s.ModelCalls != 5 || s.LatencyP50MS != 200 || s.LatencyP95MS != 900 {
		t.Fatalf("calls %d p50 %d p95 %d", s.ModelCalls, s.LatencyP50MS, s.LatencyP95MS)
	}
	if s.Errors[ErrOverconfident] != 1 || s.ByKind["no_coverage"].Right != 2 {
		t.Fatalf("%+v %+v", s.Errors, s.ByKind)
	}
}

func TestAResultGoesStaleWhenWhatItDependsOnMoves(t *testing.T) {
	setPath, libPath := writeSet(t, []Case{privileged}, library)
	s, _ := LoadSet(setPath, libPath)
	idx := testIndex(t)
	params := model.Params{Model: "gemini-2.5-flash", MaxOutputTokens: 1024}
	local, upstream := CorpusDigests(idx)
	r := &Results{Header: Header{SetDigest: s.Digest, Params: params, PromptDigest: model.PromptDigest(params),
		LocalDigest: local, UpstreamDigest: upstream}}

	if stale, warn := Check(r, s, idx); len(stale)+len(warn) != 0 {
		t.Fatalf("fresh result reported %v %v", stale, warn)
	}

	// A prompt digest recorded under other parameters no longer matches.
	moved := *r
	moved.Header.Params.Temperature = 0.5
	if stale, _ := Check(&moved, s, idx); len(stale) != 1 {
		t.Fatalf("parameter change not caught: %v", stale)
	}

	// A control is this repository's; a decision summary is k8-lab's, and only warns.
	_ = idx.Add(corpus.Entry{ID: "control:new", Summary: "s", Source: "controls.yaml"})
	if stale, _ := Check(r, s, idx); len(stale) != 1 {
		t.Fatalf("control change not caught: %v", stale)
	}
	idx2 := testIndex(t)
	_ = idx2.Add(corpus.Entry{ID: "decision:new", Summary: "s", Source: "decisions.md"})
	if stale, warn := Check(r, s, idx2); len(stale) != 0 || len(warn) != 1 {
		t.Fatalf("upstream change: stale %v warn %v", stale, warn)
	}
}
