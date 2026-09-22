package model

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/sindredg/ai-k8s/internal/corpus"
	"github.com/sindredg/ai-k8s/internal/scc"
	"github.com/sindredg/ai-k8s/internal/verdict"
)

// Refusal names why the worker ruled insufficient_evidence around the model. Empty when it did not.
type Refusal string

const (
	RefusedBudget      Refusal = "budget"
	RefusedCeiling     Refusal = "ceiling"
	RejectedOutput     Refusal = "invalid_output"
	RejectedCitation   Refusal = "unresolved_citation"
	RejectedAcceptance Refusal = "model_accepted"
)

// Outcome is one settled finding. Called says whether money was spent on it.
type Outcome struct {
	Record  verdict.Record
	Called  bool
	Refusal Refusal
}

// Settler asks the model about one unmatched finding and checks everything it says.
type Settler struct {
	Caller         Caller
	Params         Params
	Index          *corpus.Index
	MaxInputTokens int
	Prices         Prices
	Spend          *Spend
}

// answer is the output schema, decoded strictly. Anything outside it is a rejected reply.
type answer struct {
	Verdict           string   `json:"verdict"`
	Citations         []string `json:"citations"`
	Reasoning         string   `json:"reasoning"`
	MissingEvidence   []string `json:"missing_evidence"`
	RecommendedAction string   `json:"recommended_action"`
	Confidence        string   `json:"confidence"`
}

// Settle returns a verdict for a finding the mapping did not match. An error means the call did not
// complete, a timeout or a refused permission, and the caller leaves the message unacknowledged.
// Everything the model gets wrong is a verdict instead: insufficient_evidence, naming what went wrong.
func (s *Settler) Settle(ctx context.Context, env *scc.Envelope, prov verdict.Provenance) (Outcome, error) {
	prompt, err := BuildPrompt(env.Finding, s.Index)
	if err != nil {
		return Outcome{}, err
	}

	// Refuse before spending anything, rather than truncating a finding the model would then misread.
	if est := EstimateTokens(prompt); est > s.MaxInputTokens {
		return refuse(env, prov, RefusedBudget, false, fmt.Sprintf(
			"the input is an estimated %d tokens, over the budget of %d, and was refused rather than truncated", est, s.MaxInputTokens)), nil
	}

	worst := s.Prices.Cost(s.MaxInputTokens, s.Params.MaxOutputTokens)
	ok, total, err := s.Spend.Reserve(ctx, env.Finding.Key(), worst)
	if err != nil {
		return Outcome{}, err
	}
	if !ok {
		return refuse(env, prov, RefusedCeiling, false, fmt.Sprintf(
			"the daily model spend ceiling of %s USD is reached, with %.4f USD reserved today, so the model was not called",
			strconv.FormatFloat(s.Spend.Ceiling(), 'f', -1, 64), total)), nil
	}

	reply, err := s.Caller.Generate(ctx, prompt, s.Params)
	if err != nil {
		return Outcome{}, fmt.Errorf("call the model: %w", err)
	}

	prov = s.stamp(prov, reply)
	out := Outcome{Called: true}

	if reply.Usage.InputTokens > s.MaxInputTokens {
		return s.rejected(env, prov, RefusedBudget, fmt.Sprintf(
			"the model reports %d input tokens, over the budget of %d", reply.Usage.InputTokens, s.MaxInputTokens)), nil
	}
	if reply.ToolCalls > 0 {
		return s.rejected(env, prov, RejectedOutput, fmt.Sprintf("the model made %d tool calls, and the tool budget is zero", reply.ToolCalls)), nil
	}
	if reply.FinishReason != "STOP" {
		return s.rejected(env, prov, RejectedOutput, fmt.Sprintf("the model output did not finish cleanly: finish reason %q", reply.FinishReason)), nil
	}

	var a answer
	dec := json.NewDecoder(bytes.NewReader([]byte(reply.Text)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return s.rejected(env, prov, RejectedOutput, "the model output did not validate against the schema: "+err.Error()), nil
	}

	record := verdict.Base(env, prov)
	record.SettledBy = verdict.SettledByModel
	record.Reasoning = strings.TrimSpace(a.Reasoning)
	record.RecommendedAction = strings.TrimSpace(a.RecommendedAction)
	record.Confidence = a.Confidence
	record.CorpusMatch = verdict.MatchNone // What deterministic resolution found, whatever the model says.

	switch verdict.Value(a.Verdict) {
	case verdict.New:
		if len(a.Citations) > 0 {
			return s.rejected(env, prov, RejectedOutput, "the model called the finding new and cited corpus entries anyway"), nil
		}
		record.Verdict = verdict.New
	case verdict.ContradictsDecision:
		record.Verdict = verdict.ContradictsDecision
		for _, id := range a.Citations {
			record.Citations = append(record.Citations, verdict.Citation{ID: corpus.ID(id)})
		}
		if err := record.ResolveCitations(s.Index); err != nil {
			return s.rejected(env, prov, RejectedCitation, "the model "+err.Error()), nil
		}
	case verdict.InsufficientEvidence:
		record.Verdict = verdict.InsufficientEvidence
		record.MissingEvidence = a.MissingEvidence
	case verdict.Accepted:
		return s.rejected(env, prov, RejectedAcceptance, "the model returned accepted, which only the reviewed mapping may do"), nil
	default:
		return s.rejected(env, prov, RejectedOutput, fmt.Sprintf("the model returned verdict %q, outside the closed set", a.Verdict)), nil
	}

	if err := record.Validate(); err != nil {
		return s.rejected(env, prov, RejectedOutput, "the model output did not validate: "+err.Error()), nil
	}
	out.Record = record
	return out, nil
}

// stamp records what makes the verdict reproducible and what it cost.
func (s *Settler) stamp(prov verdict.Provenance, reply Reply) verdict.Provenance {
	prov.Model = s.Params.Model
	if reply.Usage.ModelVersion != "" {
		prov.Model += "@" + reply.Usage.ModelVersion
	}
	prov.ModelParams = s.Params.String()
	prov.PromptDigest = PromptDigest(s.Params)
	prov.InputTokens = reply.Usage.InputTokens
	prov.OutputTokens = reply.Usage.OutputTokens
	prov.CostEstimate = fmt.Sprintf("%.6f USD", s.Prices.Cost(reply.Usage.InputTokens, reply.Usage.OutputTokens))
	return prov
}

// rejected is a refusal after the model was paid for, so the record carries the model and its cost.
func (s *Settler) rejected(env *scc.Envelope, prov verdict.Provenance, why Refusal, detail string) Outcome {
	return refuse(env, prov, why, true, detail)
}

func refuse(env *scc.Envelope, prov verdict.Provenance, why Refusal, called bool, detail string) Outcome {
	r := verdict.Insufficient(env, []string{detail}, prov)
	if called {
		r.SettledBy = verdict.SettledByModel
	}
	return Outcome{Record: r, Called: called, Refusal: why}
}
