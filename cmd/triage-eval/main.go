// Command triage-eval runs the model half of the worker over a fixed set of findings and scores it.
//
// It uses the same settler, checks and budgets the worker does, against a set whose expected answers
// were written down before the run. It writes nothing to the ledger and publishes nothing, and its
// spend ceiling lives in memory, so it is safe to run from a workstation with application default
// credentials. The point is the one question the live worker cannot answer on demand: whether the
// model changes an outcome the rules would have reached anyway.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sindredg/ai-k8s/internal/corpus"
	"github.com/sindredg/ai-k8s/internal/gcp"
	"github.com/sindredg/ai-k8s/internal/ledger"
	"github.com/sindredg/ai-k8s/internal/model"
	"github.com/sindredg/ai-k8s/internal/scc"
	"github.com/sindredg/ai-k8s/internal/verdict"
)

// Case is one finding and the answer written down for it before the run.
type Case struct {
	Name string `json:"name"`
	// Expect lists the verdicts that count as right. More than one means the call is a judgement.
	Expect []string `json:"expect"`
	// Cite, when set, is an id a right answer must cite.
	Cite    string          `json:"cite,omitempty"`
	Why     string          `json:"why"`
	Finding json.RawMessage `json:"finding"`
}

// Result is one scored case.
type Result struct {
	Name      string   `json:"name"`
	Expect    []string `json:"expect"`
	Got       string   `json:"got"`
	Citations []string `json:"citations"`
	Right     bool     `json:"right"`
	Reasoning string   `json:"reasoning"`
	Missing   []string `json:"missing_evidence"`
	Tokens    string   `json:"tokens"`
	Cost      string   `json:"cost"`
}

func main() {
	set := flag.String("set", "eval/phase15.json", "the cases, with their expected answers")
	corpusPath := flag.String("corpus", "", "the compiled corpus, as corpusc writes it")
	project := flag.String("project", "", "the project the model is billed to")
	location := flag.String("location", "europe-north1", "the Vertex AI region")
	modelID := flag.String("model", "gemini-2.5-flash", "the publisher model")
	ceiling := flag.Float64("ceiling-usd", 0.25, "the most this run may reserve")
	out := flag.String("out", "", "write the scored results here as JSON")
	flag.Parse()

	if err := run(*set, *corpusPath, *project, *location, *modelID, *ceiling, *out); err != nil {
		fmt.Fprintln(os.Stderr, "triage-eval:", err)
		os.Exit(1)
	}
}

func run(setPath, corpusPath, project, location, modelID string, ceiling float64, outPath string) error {
	if corpusPath == "" || project == "" {
		return fmt.Errorf("-corpus and -project are required")
	}
	body, err := os.ReadFile(corpusPath)
	if err != nil {
		return err
	}
	idx, err := corpus.Unmarshal(body)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(setPath)
	if err != nil {
		return err
	}
	var cases []Case
	if err := json.Unmarshal(raw, &cases); err != nil {
		return fmt.Errorf("parse %s: %w", setPath, err)
	}

	ctx := context.Background()
	caller, err := gcp.NewVertex(ctx, project, location, modelID, 30*time.Second)
	if err != nil {
		return err
	}
	settler := &model.Settler{
		Caller:         caller,
		Params:         model.Params{Model: modelID, MaxOutputTokens: 1024},
		Index:          idx,
		MaxInputTokens: 16384,
		Prices:         model.Prices{InputPerMillion: 0.30, OutputPerMillion: 2.50},
		Spend:          model.NewSpend(newMemStore(), ceiling, nil),
	}

	var results []Result
	right := 0
	for _, c := range cases {
		r, err := score(ctx, settler, idx, c)
		if err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		if r.Right {
			right++
		}
		results = append(results, r)
		mark := "WRONG"
		if r.Right {
			mark = "right"
		}
		fmt.Printf("%-5s %-44s expect %-40s got %-22s cites %v\n", mark, c.Name, strings.Join(c.Expect, "|"), r.Got, r.Citations)
	}
	fmt.Printf("\n%d of %d right\n", right, len(cases))

	if outPath != "" {
		encoded, _ := json.MarshalIndent(results, "", "  ")
		return os.WriteFile(outPath, encoded, 0o644)
	}
	return nil
}

// score asks about one finding the way the worker would. A finding the rules match never reaches the
// model, so it is scored as the rules settle it.
func score(ctx context.Context, s *model.Settler, idx *corpus.Index, c Case) (Result, error) {
	env, err := scc.Parse([]byte(`{"finding":` + string(c.Finding) + `}`))
	if err != nil {
		return Result{}, err
	}
	record := verdict.Classify(env, idx, verdict.Provenance{})
	if record.Verdict == verdict.New {
		out, err := s.Settle(ctx, env, verdict.Provenance{})
		if err != nil {
			return Result{}, err
		}
		record = out.Record
	}

	r := Result{
		Name: c.Name, Expect: c.Expect, Got: string(record.Verdict),
		Reasoning: record.Reasoning, Missing: record.MissingEvidence,
		Tokens: fmt.Sprintf("%d/%d", record.Provenance.InputTokens, record.Provenance.OutputTokens),
		Cost:   record.Provenance.CostEstimate,
	}
	for _, cite := range record.Citations {
		r.Citations = append(r.Citations, string(cite.ID))
	}
	for _, e := range c.Expect {
		if e == r.Got {
			r.Right = true
		}
	}
	if r.Right && c.Cite != "" {
		r.Right = false
		for _, id := range r.Citations {
			if id == c.Cite {
				r.Right = true
			}
		}
	}
	return r, nil
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
