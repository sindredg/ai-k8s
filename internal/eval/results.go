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
	"github.com/sindredg/ai-k8s/internal/model"
)

// Header is everything a result depends on. When any of it moves, the result describes a system
// that no longer exists, and Check says so.
type Header struct {
	Set       string `json:"set"`
	Sealed    bool   `json:"sealed"`
	SetDigest string `json:"set_digest"`

	Model        string       `json:"model"`
	ModelVersion string       `json:"model_version,omitempty"`
	Location     string       `json:"location"`
	Params       model.Params `json:"params"`
	PromptDigest string       `json:"prompt_digest"`

	// LocalDigest covers what this repository contributes to the corpus: the mapping and the controls.
	// UpstreamDigest covers what k8-lab contributes: the checkov baseline, threat model and decisions.
	LocalDigest    string `json:"local_corpus_digest"`
	UpstreamDigest string `json:"upstream_corpus_digest"`

	AgentCommit  string `json:"agent_commit"`
	CorpusCommit string `json:"corpus_commit"`
	Repeats      int    `json:"repeats"`
	RanAt        string `json:"ran_at"`
}

// Results is one committed evaluation.
type Results struct {
	Header    Header                  `json:"header"`
	Summaries []Summary               `json:"summaries"`
	Cases     map[string][]CaseResult `json:"cases"`
}

// ReadResults loads a committed result.
func ReadResults(path string) (*Results, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Results
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &r, nil
}

// CorpusDigests splits the corpus by where it comes from, over exactly what the model is shown.
func CorpusDigests(idx *corpus.Index) (local, upstream string) {
	type shown struct {
		ID      corpus.ID   `json:"id"`
		Kind    corpus.Kind `json:"kind"`
		Summary string      `json:"summary"`
	}
	var mine, theirs []shown
	for _, e := range idx.Entries {
		s := shown{e.ID, e.Kind, e.Summary}
		if strings.HasPrefix(string(e.ID), "control:") {
			mine = append(mine, s)
		} else {
			theirs = append(theirs, s)
		}
	}
	for _, list := range [][]shown{mine, theirs} {
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	}
	return digestOf(struct {
		Mapping  map[string][]corpus.Pairing `json:"mapping"`
		Controls []shown                     `json:"controls"`
	}{idx.Mapping, mine}), digestOf(theirs)
}

func digestOf(v any) string {
	b, err := json.Marshal(v) // Map keys are sorted, so this is canonical.
	if err != nil {
		panic(fmt.Sprintf("marshal a digest input: %v", err))
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Check compares a committed result with the tree it sits in. Stale means the result no longer
// describes this code, so the evaluation has to run again before its numbers are quoted.
//
// A change in this repository is stale. A change in k8-lab's half of the corpus is a warning,
// because this repository's CI cannot stop k8-lab editing decisions.md, and failing here for it would
// fail every unrelated pull request. The warning is the prompt to rerun.
func Check(r *Results, s *Set, idx *corpus.Index) (stale, warn []string) {
	h := r.Header
	if h.SetDigest != s.Digest {
		stale = append(stale, fmt.Sprintf("the %s cases or their findings changed since the run", s.Name))
	}
	if got := model.PromptDigest(h.Params); got != h.PromptDigest {
		stale = append(stale, "the instruction, the output schema or the parameters changed since the run")
	}
	local, upstream := CorpusDigests(idx)
	if local != h.LocalDigest {
		stale = append(stale, "mapping.yaml or controls.yaml changed since the run")
	}
	if upstream != h.UpstreamDigest {
		warn = append(warn, "k8-lab's half of the corpus changed since the run, so the model is now shown different summaries")
	}
	return stale, warn
}
