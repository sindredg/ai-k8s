package eval

import (
	"math"
	"sort"

	"github.com/sindredg/ai-k8s/internal/verdict"
)

// Systems are the two ways a finding can be settled. Rules alone is the baseline the model has to beat.
const (
	RulesOnly  = "rules"
	RulesModel = "rules+model"
)

// Run is one decision on one case.
type Run struct {
	Verdict   string   `json:"verdict,omitempty"`
	Citations []string `json:"citations,omitempty"`
	SettledBy string   `json:"settled_by,omitempty"`
	Called    bool     `json:"called"`
	Refusal   string   `json:"refusal,omitempty"`
	// Error is a call that did not complete. The worker leaves such a message unacknowledged.
	Error        string   `json:"error,omitempty"`
	LatencyMS    int64    `json:"latency_ms,omitempty"`
	InputTokens  int      `json:"input_tokens,omitempty"`
	OutputTokens int      `json:"output_tokens,omitempty"`
	CostUSD      float64  `json:"cost_usd,omitempty"`
	Reasoning    string   `json:"reasoning,omitempty"`
	Missing      []string `json:"missing_evidence,omitempty"`

	Judgement Judgement `json:"judgement"`
}

// Judgement is one run held against the answer written for its case.
type Judgement struct {
	Right     bool `json:"right"`
	Preferred bool `json:"preferred"`
	// Unsupported lists cited ids that resolve and are not in the case's supporting list.
	Unsupported []string `json:"unsupported,omitempty"`
	// MissingRequired is a right verdict that cites and leaves out the entry the case requires.
	MissingRequired bool `json:"missing_required,omitempty"`
	// Error names the kind of mistake, so a report can say which way the system fails.
	Error string `json:"error,omitempty"`
}

// Error kinds, ordered from the one that matters most.
const (
	ErrSilenced            = "silenced"             // accepted when it should not be: nobody is told
	ErrMissedContradiction = "missed_contradiction" // a control did not hold, and the verdict does not say so
	ErrOverconfident       = "overconfident"        // ruled when the evidence was not there
	ErrFalseContradiction  = "false_contradiction"  // says a decision does not hold when it does
	ErrNeedlessAbstention  = "needless_abstention"  // refused when it could have ruled
	ErrUnsupportedCitation = "unsupported_citation" // the right verdict, standing on the wrong evidence
	ErrCallFailed          = "call_failed"
	ErrOther               = "other"
)

// Judge holds one run against its case.
func Judge(c Case, r Run) Judgement {
	if r.Error != "" {
		return Judgement{Error: ErrCallFailed}
	}
	j := Judgement{Right: c.Right(r.Verdict), Preferred: r.Verdict == c.Prefer}
	for _, id := range r.Citations {
		if !contains(c.Support, id) {
			j.Unsupported = append(j.Unsupported, id)
		}
	}
	if j.Right && c.Require != "" && len(r.Citations) > 0 && !contains(r.Citations, c.Require) {
		j.MissingRequired = true
	}
	// A right verdict standing on the wrong evidence is not right. The citation is the claim.
	if j.Right && (len(j.Unsupported) > 0 || j.MissingRequired) {
		j.Right, j.Preferred = false, false
		j.Error = ErrUnsupportedCitation
		return j
	}
	if !j.Right {
		j.Error = errorKind(c, r.Verdict)
	}
	return j
}

func errorKind(c Case, got string) string {
	switch {
	case got == string(verdict.Accepted):
		return ErrSilenced
	case c.Prefer == string(verdict.ContradictsDecision) && got != string(verdict.ContradictsDecision):
		return ErrMissedContradiction
	case c.Prefer == string(verdict.InsufficientEvidence) && got != string(verdict.InsufficientEvidence):
		return ErrOverconfident
	case got == string(verdict.ContradictsDecision):
		return ErrFalseContradiction
	case got == string(verdict.InsufficientEvidence):
		return ErrNeedlessAbstention
	}
	return ErrOther
}

// CaseResult is every run of one case under one system.
type CaseResult struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Origin string   `json:"origin"`
	Prefer string   `json:"prefer"`
	Accept []string `json:"accept,omitempty"`
	Runs   []Run    `json:"runs"`
}

// Modal is the most frequent verdict across runs and the share of runs that returned it.
func (cr CaseResult) Modal() (string, float64) {
	counts := map[string]int{}
	n := 0
	for _, r := range cr.Runs {
		if r.Error != "" {
			continue
		}
		counts[r.Verdict]++
		n++
	}
	if n == 0 {
		return "", 0
	}
	best, bestN := "", -1
	for v, k := range counts {
		if k > bestN || (k == bestN && v < best) {
			best, bestN = v, k
		}
	}
	return best, float64(bestN) / float64(n)
}

// Summary is one system over one set.
type Summary struct {
	System string `json:"system"`
	Cases  int    `json:"cases"`
	Runs   int    `json:"runs"`

	Right       int `json:"right"`
	Preferred   int `json:"preferred"`
	Unsupported int `json:"runs_with_unsupported_citations"`
	CallsFailed int `json:"calls_failed"`

	// CasesRightEveryRun counts cases right on every run, which is the number a reader can rely on.
	CasesRightEveryRun int `json:"cases_right_every_run"`
	// CasesInconsistent counts cases whose verdict differed between runs.
	CasesInconsistent int `json:"cases_inconsistent"`

	Errors map[string]int   `json:"errors"`
	ByKind map[string]Tally `json:"by_kind"`

	ModelCalls   int     `json:"model_calls"`
	LatencyP50MS int64   `json:"latency_p50_ms"`
	LatencyP95MS int64   `json:"latency_p95_ms"`
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
}

// Tally is right runs out of all runs.
type Tally struct {
	Right int `json:"right"`
	Runs  int `json:"runs"`
}

// Summarize totals one system's results.
func Summarize(system string, results []CaseResult) Summary {
	s := Summary{System: system, Cases: len(results), Errors: map[string]int{}, ByKind: map[string]Tally{}}
	var latencies []int64
	for _, cr := range results {
		allRight := len(cr.Runs) > 0
		verdicts := map[string]bool{}
		for _, r := range cr.Runs {
			s.Runs++
			t := s.ByKind[cr.Kind]
			t.Runs++
			j := r.Judgement
			if j.Right {
				s.Right++
				t.Right++
			} else {
				allRight = false
			}
			s.ByKind[cr.Kind] = t
			if j.Preferred {
				s.Preferred++
			}
			if len(j.Unsupported) > 0 {
				s.Unsupported++
			}
			if j.Error != "" {
				s.Errors[j.Error]++
			}
			if r.Error != "" {
				s.CallsFailed++
				continue
			}
			verdicts[r.Verdict] = true
			if r.Called {
				s.ModelCalls++
				latencies = append(latencies, r.LatencyMS)
				s.InputTokens += r.InputTokens
				s.OutputTokens += r.OutputTokens
				s.CostUSD += r.CostUSD
			}
		}
		if allRight {
			s.CasesRightEveryRun++
		}
		if len(verdicts) > 1 {
			s.CasesInconsistent++
		}
	}
	s.LatencyP50MS = percentile(latencies, 0.50)
	s.LatencyP95MS = percentile(latencies, 0.95)
	return s
}

// percentile uses the nearest rank, which is honest about how few samples there are.
func percentile(xs []int64, p float64) int64 {
	if len(xs) == 0 {
		return 0
	}
	sorted := append([]int64(nil), xs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	rank := int(math.Ceil(p*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	return sorted[rank]
}
