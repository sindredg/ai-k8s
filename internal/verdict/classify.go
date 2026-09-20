package verdict

import (
	"fmt"
	"strings"

	"github.com/sindredg/ai-k8s/internal/corpus"
	"github.com/sindredg/ai-k8s/internal/scc"
)

// UnparseableCategory labels a finding the worker could not read a category out of. The metric needs a label, and an empty one hides the failure.
const UnparseableCategory = "UNPARSEABLE_FINDING"

const severityUnspecified = "SEVERITY_UNSPECIFIED"

// Classify settles a finding against the corpus without calling a model. A resolved match is accepted;
// anything unmatched is new. contradicts_decision needs a judgement that deterministic resolution
// cannot make, so Increment 1 never returns it.
func Classify(env *scc.Envelope, idx *corpus.Index, prov Provenance) Record {
	r := baseRecord(env, prov)
	resolved := idx.Resolve(env.Finding.Category, env.Finding.ResourceName)

	if len(resolved) == 0 {
		r.Verdict = New
		r.CorpusMatch = MatchNone
		r.Reasoning = fmt.Sprintf("No corpus entry pairs category %s with this resource, so nothing here prices it.", env.Finding.Category)
		r.RecommendedAction = "Decide about this finding and record the decision, then add the pairing to mapping.yaml."
		return r
	}

	r.Verdict = Accepted
	r.CorpusMatch = MatchMatched
	for _, e := range resolved {
		r.Citations = append(r.Citations, Citation{ID: e.ID, Summary: e.Summary, Source: e.Source})
	}
	r.Reasoning = fmt.Sprintf("Resolution matched %d corpus entries for category %s on this resource.", len(resolved), env.Finding.Category)
	r.RecommendedAction = "None. The finding names something this repository already decided about and priced."
	return r
}

// Insufficient records a refusal to rule, naming what was missing. The worker calls this, never the model.
func Insufficient(env *scc.Envelope, missing []string, prov Provenance) Record {
	r := baseRecord(env, prov)
	r.Verdict = InsufficientEvidence
	r.CorpusMatch = MatchNone
	r.MissingEvidence = missing
	r.Reasoning = "The worker refused to rule. What is missing is listed rather than guessed at."
	r.RecommendedAction = "Read the finding by hand, then either fix the worker or extend the corpus."
	return r
}

// baseRecord fills what every verdict carries, defaulting the two fields the metric turns into labels.
func baseRecord(env *scc.Envelope, prov Provenance) Record {
	f := env.Finding

	category := strings.TrimSpace(f.Category)
	if category == "" {
		category = UnparseableCategory
	}
	severity := strings.TrimSpace(f.Severity)
	if severity == "" {
		severity = severityUnspecified
	}
	digest := env.Digest
	if digest == "" {
		digest = "sha256:unavailable"
	}

	return Record{
		SchemaVersion: SchemaVersion,
		SettledBy:     SettledByRules,
		Finding: FindingRef{
			CanonicalName: f.CanonicalName,
			Name:          f.Name,
			Category:      category,
			ResourceName:  f.ResourceName,
			Severity:      severity,
			State:         f.State,
			EventTime:     f.EventTime,
			Class:         f.FindingClass,
			Digest:        digest,
		},
		Provenance: prov,
	}
}
