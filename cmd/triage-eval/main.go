// Command triage-eval scores the worker's decisions on a fixed set of findings, rules alone against
// rules plus the model, and checks whether a committed result still describes the code.
//
// It decides through worker.Decide, the function the worker itself calls, with the same checks and
// budgets. It writes nothing to the ledger and publishes nothing, and its spend ceiling lives in
// memory, so it is safe to run from a workstation with application default credentials.
//
// Three modes:
//
//	triage-eval -set eval/dev.json -corpus corpus.json -project P -out eval/results/dev.json
//	triage-eval -set eval/dev.json -corpus corpus.json                # rules alone, no credential
//	triage-eval -set eval/dev.json -corpus corpus.json -check eval/results/dev.json
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sindredg/ai-k8s/internal/corpus"
	"github.com/sindredg/ai-k8s/internal/eval"
	"github.com/sindredg/ai-k8s/internal/gcp"
	"github.com/sindredg/ai-k8s/internal/ledger"
	"github.com/sindredg/ai-k8s/internal/model"
	"github.com/sindredg/ai-k8s/internal/scc"
	"github.com/sindredg/ai-k8s/internal/verdict"
	"github.com/sindredg/ai-k8s/internal/worker"
)

// The worker's defaults, so the evaluation asks the question the deployment asks.
const (
	maxInputTokens  = 16384
	maxOutputTokens = 1024
	priceIn         = 0.30
	priceOut        = 2.50
)

type options struct {
	set, findings, corpus string
	project, location     string
	modelID               string
	repeats               int
	ceiling               float64
	out, check            string
	agentCommit           string
	corpusCommit          string
}

func main() {
	var o options
	flag.StringVar(&o.set, "set", "eval/dev.json", "the cases, with their expected answers")
	flag.StringVar(&o.findings, "findings", "eval/findings.json", "the finding bodies the cases draw on")
	flag.StringVar(&o.corpus, "corpus", "", "the compiled corpus, as corpusc writes it")
	flag.StringVar(&o.project, "project", "", "the project the model is billed to; empty scores the rules alone")
	flag.StringVar(&o.location, "location", "europe-north1", "the Vertex AI region")
	flag.StringVar(&o.modelID, "model", "gemini-2.5-flash", "the publisher model")
	flag.IntVar(&o.repeats, "repeats", 5, "how many times each case is asked, to measure whether the answer holds")
	flag.Float64Var(&o.ceiling, "ceiling-usd", 1.50, "the most this run may reserve, at the worst case per call")
	flag.StringVar(&o.out, "out", "", "write the scored results here as JSON")
	flag.StringVar(&o.check, "check", "", "compare this committed result with the tree, and fail when it is stale")
	flag.StringVar(&o.agentCommit, "agent-commit", "", "the ai-k8s commit being scored, recorded in the result")
	flag.StringVar(&o.corpusCommit, "corpus-commit", "", "the k8-lab commit the corpus was compiled from")
	flag.Parse()

	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "triage-eval:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	if o.corpus == "" {
		return errors.New("-corpus is required")
	}
	body, err := os.ReadFile(o.corpus)
	if err != nil {
		return err
	}
	idx, err := corpus.Unmarshal(body)
	if err != nil {
		return err
	}
	set, err := eval.LoadSet(o.set, o.findings)
	if err != nil {
		return err
	}
	if err := set.Validate(idx); err != nil {
		return err
	}

	if o.check != "" {
		return check(o.check, set, idx)
	}

	ctx := context.Background()
	systems := map[string][]eval.CaseResult{eval.RulesOnly: decideAll(ctx, set, idx, nil, nil, 1)}

	header := eval.Header{Set: set.Name, Sealed: set.Sealed, SetDigest: set.Digest, AgentCommit: o.agentCommit,
		CorpusCommit: o.corpusCommit, RanAt: time.Now().UTC().Format(time.RFC3339)}
	header.LocalDigest, header.UpstreamDigest = eval.CorpusDigests(idx)

	if o.project != "" {
		vertex, err := gcp.NewVertex(ctx, o.project, o.location, o.modelID, 30*time.Second)
		if err != nil {
			return err
		}
		clock := &timed{inner: vertex}
		params := model.Params{Model: o.modelID, Temperature: 0, MaxOutputTokens: maxOutputTokens, ThinkingBudget: 0}
		settler := &model.Settler{
			Caller:         clock,
			Params:         params,
			Index:          idx,
			MaxInputTokens: maxInputTokens,
			Prices:         model.Prices{InputPerMillion: priceIn, OutputPerMillion: priceOut},
			Spend:          model.NewSpend(newMemStore(), o.ceiling, nil),
		}
		systems[eval.RulesModel] = decideAll(ctx, set, idx, settler, clock, o.repeats)
		header.Model, header.Location, header.Params = o.modelID, o.location, params
		header.PromptDigest = model.PromptDigest(params)
		header.Repeats = o.repeats
		header.ModelVersion = clock.version
	}

	results := &eval.Results{Header: header, Cases: systems}
	for _, name := range []string{eval.RulesOnly, eval.RulesModel} {
		if crs, ok := systems[name]; ok {
			results.Summaries = append(results.Summaries, eval.Summarize(name, crs))
		}
	}
	report(os.Stdout, set, results)

	if o.out != "" {
		encoded, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(o.out, append(encoded, '\n'), 0o644)
	}
	return nil
}

// decideAll runs every case through worker.Decide, repeats times. A nil settler is the rules alone.
func decideAll(ctx context.Context, set *eval.Set, idx *corpus.Index, s *model.Settler, clock *timed, repeats int) []eval.CaseResult {
	var out []eval.CaseResult
	for _, c := range set.Cases {
		cr := eval.CaseResult{Name: c.Name, Kind: c.Kind, Origin: c.Origin, Prefer: c.Prefer, Accept: c.Accept}
		for i := 0; i < repeats; i++ {
			r := decideOne(ctx, c, idx, s, clock)
			r.Judgement = eval.Judge(c, r)
			cr.Runs = append(cr.Runs, r)
		}
		out = append(out, cr)
	}
	return out
}

func decideOne(ctx context.Context, c eval.Case, idx *corpus.Index, s *model.Settler, clock *timed) eval.Run {
	env, parseErr := scc.Parse(c.Body())
	if env == nil || strings.TrimSpace(env.Finding.CanonicalName) == "" {
		// The worker refuses this message for the dead letter topic, where nothing rules on it.
		return eval.Run{Error: "unreadable, dead-lettered by the worker"}
	}
	if clock != nil {
		clock.last = 0
	}
	record, outcome, err := worker.Decide(ctx, idx, s, env, parseErr, verdict.Provenance{})
	if err != nil {
		return eval.Run{Error: err.Error()}
	}
	r := eval.Run{
		Verdict: string(record.Verdict), SettledBy: record.SettledBy, Called: outcome.Called,
		Refusal: string(outcome.Refusal), Reasoning: record.Reasoning, Missing: record.MissingEvidence,
	}
	for _, cite := range record.Citations {
		r.Citations = append(r.Citations, string(cite.ID))
	}
	if outcome.Called {
		r.InputTokens, r.OutputTokens = record.Provenance.InputTokens, record.Provenance.OutputTokens
		r.CostUSD = s.Prices.Cost(r.InputTokens, r.OutputTokens)
		r.LatencyMS = clock.last.Milliseconds()
	}
	return r
}

func check(path string, set *eval.Set, idx *corpus.Index) error {
	r, err := eval.ReadResults(path)
	if err != nil {
		return err
	}
	stale, warn := eval.Check(r, set, idx)
	for _, w := range warn {
		fmt.Printf("::warning::%s: %s. Rerun the evaluation before quoting its numbers.\n", path, w)
	}
	if len(stale) > 0 {
		return fmt.Errorf("%s is stale, so rerun the evaluation and commit the result:\n  %s", path, strings.Join(stale, "\n  "))
	}
	fmt.Printf("%s describes this tree (run %s, %s)\n", path, r.Header.RanAt, r.Header.Model)
	return nil
}

// report prints one line per case, then the two systems side by side.
func report(w io.Writer, set *eval.Set, r *eval.Results) {
	fmt.Fprintf(w, "%s: %d cases, sealed=%v\n\n", set.Name, len(set.Cases), set.Sealed)
	withModel := r.Cases[eval.RulesModel]
	for i, rules := range r.Cases[eval.RulesOnly] {
		expect := rules.Prefer
		if len(rules.Accept) > 0 {
			expect += " (or " + strings.Join(rules.Accept, ", ") + ")"
		}
		line := fmt.Sprintf("%-62s %-16s expect %-52s rules %s", rules.Name, rules.Kind, expect, mark(rules.Runs[0]))
		if withModel != nil {
			line += "   model " + tallyRuns(withModel[i].Runs)
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%-12s %6s %6s %9s %11s %12s %12s %7s %7s %9s\n",
		"system", "runs", "right", "preferred", "unsupported", "inconsistent", "right_always", "p50_ms", "p95_ms", "cost_usd")
	for _, s := range r.Summaries {
		fmt.Fprintf(w, "%-12s %6d %6d %9d %11d %12d %12s %7d %7d %9.4f\n",
			s.System, s.Runs, s.Right, s.Preferred, s.Unsupported, s.CasesInconsistent,
			fmt.Sprintf("%d/%d", s.CasesRightEveryRun, s.Cases), s.LatencyP50MS, s.LatencyP95MS, s.CostUSD)
		if len(s.Errors) > 0 {
			var kinds []string
			for k, n := range s.Errors {
				kinds = append(kinds, fmt.Sprintf("%s %d", k, n))
			}
			sort.Strings(kinds)
			fmt.Fprintf(w, "%-12s errors: %s\n", "", strings.Join(kinds, ", "))
		}
	}
}

func mark(r eval.Run) string {
	if r.Error != "" {
		return "ERROR " + r.Error
	}
	m := "WRONG"
	if r.Judgement.Right {
		m = "right"
	}
	s := m + " " + r.Verdict
	if len(r.Judgement.Unsupported) > 0 {
		s += " unsupported " + strings.Join(r.Judgement.Unsupported, ",")
	}
	return s
}

// tallyRuns reads like "insufficient_evidence x4, contradicts_decision x1 (4/5 right)".
func tallyRuns(runs []eval.Run) string {
	counts := map[string]int{}
	right := 0
	for _, r := range runs {
		k := r.Verdict
		if r.Error != "" {
			k = "error"
		} else if len(r.Judgement.Unsupported) > 0 {
			k += "[unsupported]"
		}
		counts[k]++
		if r.Judgement.Right {
			right++
		}
	}
	var parts []string
	for k, n := range counts {
		parts = append(parts, fmt.Sprintf("%s x%d", k, n))
	}
	sort.Strings(parts)
	return fmt.Sprintf("%s (%d/%d right)", strings.Join(parts, ", "), right, len(runs))
}

// timed measures each call and keeps the model version the endpoint reports.
type timed struct {
	inner   model.Caller
	last    time.Duration
	version string
}

func (t *timed) Generate(ctx context.Context, p model.Prompt, params model.Params) (model.Reply, error) {
	start := time.Now()
	reply, err := t.inner.Generate(ctx, p, params)
	t.last = time.Since(start)
	if reply.Usage.ModelVersion != "" {
		t.version = reply.Usage.ModelVersion
	}
	return reply, err
}

// memStore holds the run's spend reservations, so the ceiling is enforced without touching the ledger.
type memStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newMemStore() *memStore { return &memStore{objects: map[string][]byte{}} }

func (m *memStore) Create(_ context.Context, name string, body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objects[name]; ok {
		return ledger.ErrExists
	}
	m.objects[name] = body
	return nil
}

func (m *memStore) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for n := range m.objects {
		if strings.HasPrefix(n, prefix) {
			names = append(names, n)
		}
	}
	return names, nil
}

func (m *memStore) Read(_ context.Context, name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[name]
	if !ok {
		return nil, ledger.ErrNotFound
	}
	return b, nil
}
