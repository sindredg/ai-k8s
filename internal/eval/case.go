// Package eval scores the worker's decisions against a set of findings whose right answers were
// written down, reviewed and committed before the run.
//
// A case names the verdict it prefers, any others that are defensible, and the corpus entries a
// citation may honestly name. The last part is what makes an unsupported claim countable: a citation
// that resolves but does not bear on the finding is a claim the corpus does not support.
package eval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sindredg/ai-k8s/internal/corpus"
	"github.com/sindredg/ai-k8s/internal/verdict"
)

// Kinds are what a case tests, so a report can say where the errors are and not only how many.
var Kinds = map[string]string{
	"no_coverage":      "nothing in the corpus applies",
	"rules_control":    "a reviewed pairing settles it and the model is never asked",
	"ambiguous":        "more than one verdict is defensible",
	"missing_evidence": "a required field never arrived",
	"abstain":          "the finding carries too little to rule on",
	"misleading":       "the finding carries text written to steer the verdict",
	"near_miss":        "a decision exists for a similar resource, not this one",
	"contradiction":    "the finding shows a recorded control did not hold",
}

// Origins say how far a case is from something a detector actually sent.
var Origins = map[string]string{
	"real":      "a finding Security Command Center delivered, unchanged",
	"derived":   "a real finding with named fields changed or removed",
	"synthetic": "written by hand in a detector's format; no detector has sent it",
}

// Case is one finding and the answer written down for it.
type Case struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Origin string `json:"origin"`

	// Prefer is the reviewed best answer. Accept lists others that are defensible, and scores as right.
	Prefer string   `json:"prefer"`
	Accept []string `json:"accept,omitempty"`

	// Support lists every corpus id a citation may name. A cited id outside it is unsupported, even
	// when it resolves. Require, when set, is an id a right answer that cites must include.
	Support []string `json:"support,omitempty"`
	Require string   `json:"require,omitempty"`

	Why      string `json:"why"`
	Evidence string `json:"evidence"`

	// Finding names a body in the findings library. Set replaces fields, a dotted path reaching into
	// nested objects, and Delete removes them, so a variant is a few lines and not a second copy.
	Finding string         `json:"finding"`
	Set     map[string]any `json:"set,omitempty"`
	Delete  []string       `json:"delete,omitempty"`

	body []byte
}

// Set is one file of cases, with a digest over it and every finding body it uses.
type Set struct {
	Name   string `json:"name"`
	Sealed bool   `json:"sealed"`
	Note   string `json:"note,omitempty"`
	Cases  []Case `json:"cases"`
	Digest string `json:"-"`
}

// Body is the notification body the worker would receive for this case.
func (c Case) Body() []byte { return c.body }

// Right says whether a verdict counts as correct for this case.
func (c Case) Right(v string) bool {
	if v == c.Prefer {
		return true
	}
	for _, a := range c.Accept {
		if v == a {
			return true
		}
	}
	return false
}

// LoadSet reads a set and the findings library it draws on, and builds every case's body.
func LoadSet(setPath, findingsPath string) (*Set, error) {
	rawSet, err := os.ReadFile(setPath)
	if err != nil {
		return nil, err
	}
	rawLib, err := os.ReadFile(findingsPath)
	if err != nil {
		return nil, err
	}
	var s Set
	if err := strictUnmarshal(rawSet, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", setPath, err)
	}
	var lib map[string]json.RawMessage
	if err := json.Unmarshal(rawLib, &lib); err != nil {
		return nil, fmt.Errorf("parse %s: %w", findingsPath, err)
	}

	// The digest covers the cases and the bodies they use, not the whole library, so adding a finding
	// for another set does not make this one stale.
	h := sha256.New()
	h.Write(canonical(rawSet))
	var used []string
	for i := range s.Cases {
		c := &s.Cases[i]
		base, ok := lib[c.Finding]
		if !ok {
			return nil, fmt.Errorf("case %q names finding %q, which is not in %s", c.Name, c.Finding, findingsPath)
		}
		body, err := derive(base, c.Set, c.Delete)
		if err != nil {
			return nil, fmt.Errorf("case %q: %w", c.Name, err)
		}
		c.body = body
		used = append(used, c.Finding)
	}
	sort.Strings(used)
	for i, name := range used {
		if i > 0 && used[i-1] == name {
			continue
		}
		h.Write([]byte(name))
		h.Write(canonical(lib[name]))
	}
	s.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return &s, nil
}

// Validate checks every case against the contract and the corpus, before anything is spent on it.
func (s *Set) Validate(idx *corpus.Index) error {
	var problems []string
	seen := map[string]bool{}
	for _, c := range s.Cases {
		add := func(format string, args ...any) {
			problems = append(problems, fmt.Sprintf("%s: %s", c.Name, fmt.Sprintf(format, args...)))
		}
		if strings.TrimSpace(c.Name) == "" {
			problems = append(problems, "a case has no name")
			continue
		}
		if seen[c.Name] {
			add("the name is used twice")
		}
		seen[c.Name] = true
		if _, ok := Kinds[c.Kind]; !ok {
			add("kind %q is not one of the known kinds", c.Kind)
		}
		if _, ok := Origins[c.Origin]; !ok {
			add("origin %q is not real, derived or synthetic", c.Origin)
		}
		if strings.TrimSpace(c.Why) == "" || strings.TrimSpace(c.Evidence) == "" {
			add("an expected answer needs a reason and the evidence behind it")
		}
		if c.Origin == "real" && (len(c.Set) > 0 || len(c.Delete) > 0) {
			add("a real finding is unchanged; a changed one is derived")
		}
		for _, v := range append([]string{c.Prefer}, c.Accept...) {
			if !closedSet(v) {
				add("verdict %q is outside the closed set", v)
			}
		}
		cites := c.Prefer == string(verdict.Accepted) || c.Prefer == string(verdict.ContradictsDecision)
		if cites && len(c.Support) == 0 {
			add("prefers %s, which cites, and lists no supporting entry", c.Prefer)
		}
		for _, id := range c.Support {
			if _, ok := idx.Lookup(corpus.ID(id)); !ok {
				add("supporting entry %q does not resolve in the corpus", id)
			}
		}
		if c.Require != "" && !contains(c.Support, c.Require) {
			add("required entry %q is not in the supporting list", c.Require)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("set %s is invalid:\n  %s", s.Name, strings.Join(problems, "\n  "))
	}
	return nil
}

func closedSet(v string) bool {
	switch verdict.Value(v) {
	case verdict.Accepted, verdict.ContradictsDecision, verdict.New, verdict.InsufficientEvidence:
		return true
	}
	return false
}

// derive applies a case's changes to a library body and wraps it the way a notification arrives.
func derive(base json.RawMessage, set map[string]any, del []string) ([]byte, error) {
	var f map[string]any
	if err := json.Unmarshal(base, &f); err != nil {
		return nil, fmt.Errorf("parse the finding: %w", err)
	}
	for path, v := range set {
		if err := walk(f, path, func(parent map[string]any, key string) { parent[key] = v }, true); err != nil {
			return nil, err
		}
	}
	for _, path := range del {
		if err := walk(f, path, func(parent map[string]any, key string) { delete(parent, key) }, false); err != nil {
			return nil, err
		}
	}
	return json.Marshal(map[string]any{"finding": f})
}

// walk finds the object holding the last key of a dotted path. create makes missing objects on the way.
func walk(root map[string]any, path string, apply func(map[string]any, string), create bool) error {
	keys := strings.Split(path, ".")
	cur := root
	for _, k := range keys[:len(keys)-1] {
		next, ok := cur[k].(map[string]any)
		if !ok {
			if !create {
				return fmt.Errorf("path %q: %q is not an object", path, k)
			}
			next = map[string]any{}
			cur[k] = next
		}
		cur = next
	}
	last := keys[len(keys)-1]
	if _, ok := cur[last]; !ok && !create {
		return fmt.Errorf("path %q is not in the finding, so deleting it tests nothing", path)
	}
	apply(cur, last)
	return nil
}

func strictUnmarshal(raw []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// canonical re-encodes JSON with sorted keys, so formatting does not move a digest.
func canonical(raw []byte) []byte {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
