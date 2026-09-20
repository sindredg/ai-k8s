package corpus

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Sources are the five files the corpus is compiled from. The first three live in k8-lab; the last two are the agent's own.
type Sources struct {
	CheckovBaseline string
	ThreatModel     string
	Decisions       string
	Controls        string
	Mapping         string
}

// Compile reads every source and validates the result. It fails on a malformed entry, an id
// collision, a mapping citing an id that does not exist, or a mapping without its justification.
// Failing here fails the build rather than the worker, which is the point of compiling at build time.
func Compile(s Sources) (*Index, error) {
	idx := NewIndex()

	steps := []struct {
		name string
		load func(*Index, string) error
		path string
	}{
		{"checkov baseline", LoadCheckov, s.CheckovBaseline},
		{"threat model", LoadThreatModel, s.ThreatModel},
		{"decisions", LoadDecisions, s.Decisions},
		{"controls", LoadControls, s.Controls},
		{"mapping", LoadMapping, s.Mapping},
	}
	for _, step := range steps {
		if step.path == "" {
			return nil, fmt.Errorf("no path given for the %s", step.name)
		}
		if err := step.load(idx, step.path); err != nil {
			return nil, fmt.Errorf("%s: %w", step.name, err)
		}
	}

	if err := idx.Validate(); err != nil {
		return nil, err
	}
	return idx, nil
}

// Marshal encodes the index for the image. The worker reads this and never reads a corpus source.
func (idx *Index) Marshal() ([]byte, error) {
	return json.MarshalIndent(idx, "", "  ")
}

// Unmarshal reads a compiled index and revalidates it, so a tampered or truncated file is refused rather than used.
func Unmarshal(body []byte) (*Index, error) {
	idx := NewIndex()
	if err := json.Unmarshal(body, idx); err != nil {
		return nil, fmt.Errorf("parse the compiled corpus: %w", err)
	}
	if idx.Entries == nil {
		idx.Entries = map[ID]Entry{}
	}
	if idx.Mapping == nil {
		idx.Mapping = map[string][]Pairing{}
	}
	if err := idx.Validate(); err != nil {
		return nil, err
	}
	return idx, nil
}

// Report says what was loaded, in one block the build prints. A number nobody can see is not evidence.
func (idx *Index) Report() string {
	byKind := map[Kind]int{}
	for _, e := range idx.Entries {
		byKind[e.Kind]++
	}

	kinds := make([]string, 0, len(byKind))
	for k, n := range byKind {
		kinds = append(kinds, fmt.Sprintf("  %-9s %d", k, n))
	}
	sort.Strings(kinds)

	pairings, categories := 0, 0
	for _, ps := range idx.Mapping {
		categories++
		pairings += len(ps)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "corpus entries: %d\n", len(idx.Entries))
	b.WriteString(strings.Join(kinds, "\n"))
	fmt.Fprintf(&b, "\nmapping: %d categories, %d pairings\n", categories, pairings)
	if len(idx.SkippedDecisions) > 0 {
		fmt.Fprintf(&b, "decisions headings carrying no Decision line, skipped: %s\n", strings.Join(idx.SkippedDecisions, ", "))
	}
	return b.String()
}
