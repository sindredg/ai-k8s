package corpus

import (
	"fmt"
	"sort"
	"strings"
)

// Entry is one citable record. Summary is what it says; Source is where a reader finds it.
type Entry struct {
	ID      ID     `json:"id"`
	Kind    Kind   `json:"kind"`
	Summary string `json:"summary"`
	Source  string `json:"source"`

	// AppliesTo is set on controls alone: the resource names the control holds for, each a prefix of a
	// Security Command Center resource name. A contradiction stands only on a control that applies.
	AppliesTo []string `json:"applies_to,omitempty"`
}

// Pairing binds one Security Command Center category to corpus entries, for one concrete resource.
// Resource is the finding's resourceName verbatim, because a decision about one resource does not cover another.
type Pairing struct {
	Resource string `json:"resource"`
	Cite     []ID   `json:"cite"`
	Why      string `json:"why"`
}

// Index is the compiled corpus. corpusc emits one; the worker reads one and never writes.
type Index struct {
	Entries map[ID]Entry         `json:"entries"`
	Mapping map[string][]Pairing `json:"mapping"`

	// SkippedDecisions names decisions.md headings carrying no Decision line, so corpusc reports them rather than dropping them.
	SkippedDecisions []string `json:"skipped_decisions,omitempty"`
}

func NewIndex() *Index {
	return &Index{Entries: map[ID]Entry{}, Mapping: map[string][]Pairing{}}
}

// Add records an entry, rejecting a malformed id, an empty summary, or a collision with an id already present.
func (idx *Index) Add(e Entry) error {
	kind, err := ParseID(e.ID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(e.Summary) == "" {
		return fmt.Errorf("corpus entry %q has no summary", e.ID)
	}
	if _, seen := idx.Entries[e.ID]; seen {
		return fmt.Errorf("corpus id collision on %q", e.ID)
	}
	e.Kind = kind
	idx.Entries[e.ID] = e
	return nil
}

// Lookup resolves a citation. Resolution is an exact match and nothing else.
func (idx *Index) Lookup(id ID) (Entry, bool) {
	e, ok := idx.Entries[id]
	return e, ok
}

// Validate checks the mapping against the entries. corpusc fails the build on any error it returns.
func (idx *Index) Validate() error {
	var problems []string

	categories := make([]string, 0, len(idx.Mapping))
	for c := range idx.Mapping {
		categories = append(categories, c)
	}
	sort.Strings(categories)

	for _, category := range categories {
		if strings.TrimSpace(category) == "" {
			problems = append(problems, "a mapping is keyed on an empty category")
			continue
		}
		for i, p := range idx.Mapping[category] {
			where := fmt.Sprintf("%s[%d]", category, i)
			if strings.TrimSpace(p.Resource) == "" {
				problems = append(problems, fmt.Sprintf("%s names no resource", where))
			}
			if strings.TrimSpace(p.Why) == "" {
				problems = append(problems, fmt.Sprintf("%s has no justification", where))
			}
			if len(p.Cite) == 0 {
				problems = append(problems, fmt.Sprintf("%s cites nothing", where))
			}
			for _, id := range p.Cite {
				if _, ok := idx.Lookup(id); !ok {
					problems = append(problems, fmt.Sprintf("%s cites %q, which does not resolve", where, id))
				}
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("corpus mapping is invalid:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}
