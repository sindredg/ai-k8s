package worker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/sindredg/ai-k8s/internal/ledger"
	"github.com/sindredg/ai-k8s/internal/model"
	"github.com/sindredg/ai-k8s/internal/verdict"
)

// scriptedModel answers every call the same way, and counts the calls.
type scriptedModel struct {
	verdict string
	err     error
	calls   int
}

func (s *scriptedModel) Generate(context.Context, model.Prompt, model.Params) (model.Reply, error) {
	s.calls++
	if s.err != nil {
		return model.Reply{}, s.err
	}
	text, _ := json.Marshal(map[string]any{
		"verdict": s.verdict, "citations": []string{}, "reasoning": "r", "missing_evidence": []string{"a fact"},
		"recommended_action": "a", "confidence": "low",
	})
	return model.Reply{Text: string(text), FinishReason: "STOP", Usage: model.Usage{InputTokens: 9000, OutputTokens: 100}}, nil
}

func withModel(t *testing.T, w *Worker, store *fakeStore, m *scriptedModel) {
	t.Helper()
	w.Model = &model.Settler{
		Caller:         m,
		Params:         model.Params{Model: "gemini-2.5-flash", MaxOutputTokens: 1024},
		Index:          w.Index,
		MaxInputTokens: 16384,
		Prices:         model.Prices{InputPerMillion: 0.30, OutputPerMillion: 2.50},
		Spend:          model.NewSpend(store, 1, nil),
	}
}

func TestTheModelIsAskedOnlyAboutWhatTheRulesLeftUnmatched(t *testing.T) {
	w, store, notifier := newTestWorker(t)
	m := &scriptedModel{verdict: "new"}
	withModel(t, w, store, m)

	matched := handle(t, w, envelopeAs("aaaa", "BINARY_AUTHORIZATION_DISABLED", cluster, "MISCONFIGURATION", "A description."))
	if m.calls != 0 || !matched.acked {
		t.Fatalf("a matched finding reached the model: %d calls", m.calls)
	}

	unmatched := handle(t, w, envelopeAs("bbbb", "PRIMITIVE_ROLES_USED", cluster, "MISCONFIGURATION", "A description."))
	if m.calls != 1 || !unmatched.acked {
		t.Fatalf("calls %d, acked %v", m.calls, unmatched.acked)
	}
	last := notifier.emitted[len(notifier.emitted)-1]
	if last.SettledBy != verdict.SettledByModel || last.Provenance.CostEstimate == "" {
		t.Fatalf("the notification does not carry the model's verdict and cost: %+v", last)
	}

	c := w.Counters.Snapshot()
	if c.SettledByRules != 1 || c.SettledByModel != 1 || c.ModelCalls != 1 {
		t.Fatalf("counters: %+v", c)
	}
}

func TestAModelCallThatDoesNotCompleteLeavesTheMessageAndTheLedgerAlone(t *testing.T) {
	for name, err := range map[string]error{
		"timeout":    context.DeadlineExceeded,
		"permission": errors.New("generateContent returned 403: PERMISSION_DENIED"),
	} {
		t.Run(name, func(t *testing.T) {
			w, store, notifier := newTestWorker(t)
			withModel(t, w, store, &scriptedModel{err: err})

			msg := handle(t, w, envelope("PRIMITIVE_ROLES_USED", cluster, "MISCONFIGURATION"))
			if msg.acked || !msg.nacked {
				t.Fatalf("acked %v, nacked %v", msg.acked, msg.nacked)
			}
			if store.has(ledger.Received) || store.has(ledger.Classified) || len(notifier.emitted) != 0 {
				t.Fatal("a failed call reached the ledger or the owner")
			}
			if c := w.Counters.Snapshot(); c.ModelErrors != 1 || c.Failed != 1 {
				t.Fatalf("counters: %+v", c)
			}
		})
	}
}

func TestAModelRefusalIsARecordedVerdictThatNotifies(t *testing.T) {
	w, store, notifier := newTestWorker(t)
	withModel(t, w, store, &scriptedModel{verdict: "accepted"})

	msg := handle(t, w, envelope("PRIMITIVE_ROLES_USED", cluster, "MISCONFIGURATION"))
	if !msg.acked || len(notifier.emitted) != 1 {
		t.Fatalf("acked %v, notified %d", msg.acked, len(notifier.emitted))
	}
	if got := notifier.emitted[0].Verdict; got != verdict.InsufficientEvidence {
		t.Fatalf("got %s", got)
	}
	if c := w.Counters.Snapshot(); c.ModelOutputRejected != 1 {
		t.Fatalf("counters: %+v", c)
	}
}
