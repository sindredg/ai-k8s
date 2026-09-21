// Package worker pulls findings, settles them against the corpus, records the verdict and notifies.
//
// The ordering is the one the idempotency decision fixes: record before notifying, notify before
// acknowledging. A crash between inference and persistence re-infers, which costs a fraction of a
// cent. A crash between persistence and notification re-notifies without paying for inference again.
// Duplicate email is accepted. A missed notification is not.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/sindredg/ai-k8s/internal/corpus"
	"github.com/sindredg/ai-k8s/internal/ledger"
	"github.com/sindredg/ai-k8s/internal/model"
	"github.com/sindredg/ai-k8s/internal/notify"
	"github.com/sindredg/ai-k8s/internal/scc"
	"github.com/sindredg/ai-k8s/internal/verdict"
)

// Message is one Pub/Sub delivery. Ack and Nack are the only two outcomes.
type Message interface {
	Body() []byte
	Ack()
	Nack()
}

// Notifier emits the log entry the alert policy reads.
type Notifier interface {
	Emit(ctx context.Context, r verdict.Record) error
}

// Worker settles one message at a time. The Pub/Sub client calls Handle concurrently.
type Worker struct {
	Index      *corpus.Index
	Ledger     *ledger.Ledger
	Notifier   Notifier
	Provenance verdict.Provenance
	Log        *slog.Logger
	Counters   Counters

	// Model settles what the rules left unmatched. Nil runs the rules alone, which is Increment 1.
	Model *model.Settler

	// CrashAt names the boundary a drill stops the worker at. Empty everywhere but a drill.
	CrashAt ledger.State

	// Exit is os.Exit unless a test replaces it. Nothing in production sets it.
	Exit func(int)
}

func (w *Worker) logger() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.Default()
}

// Handle triages one delivery and decides whether to acknowledge it.
func (w *Worker) Handle(ctx context.Context, m Message) {
	w.Counters.Add(func(c *Counts) { c.Received++ })

	env, parseErr := scc.Parse(m.Body())

	// Nothing usable came out of the body, so there is no key to record it under and no verdict to
	// write. Refusing the message sends it to the dead letter topic, where it stays readable.
	if env == nil || strings.TrimSpace(env.Finding.CanonicalName) == "" {
		w.Counters.Add(func(c *Counts) { c.Unreadable++ })
		w.logger().Error("message is unreadable, refusing it for the dead letter topic", "error", parseErr)
		m.Nack()
		return
	}

	// Phase 15 triages misconfiguration, external exposure and threat. The vulnerability volume is
	// counted here and acknowledged, so it is recorded rather than left to redeliver until it dead-letters.
	if parseErr == nil && !scc.InScope(env.Finding.FindingClass) {
		w.Counters.Add(func(c *Counts) { c.VulnerabilitiesSkipped++ })
		m.Ack()
		return
	}

	if err := w.triage(ctx, env, parseErr, m); err != nil {
		w.Counters.Add(func(c *Counts) { c.Failed++ })
		w.logger().Error("triage failed, leaving the message unacknowledged", "key", env.Finding.Key(), "error", err)
		m.Nack()
	}
}

// triage runs the state machine. Every error path leaves the message unacknowledged and the ledger readable.
func (w *Worker) triage(ctx context.Context, env *scc.Envelope, parseErr error, m Message) error {
	key := env.Finding.Key()

	state, seen, err := w.resume(ctx, key, env)
	if err != nil {
		return err
	}
	if seen && state == ledger.Acknowledged {
		m.Ack() // Nothing left to do. Drop the message.
		return nil
	}

	record, err := w.recordFor(ctx, key, state, seen, env, parseErr)
	if err != nil {
		return err
	}

	// The verdict is durable and nothing has been notified yet.
	w.crashIf(ledger.NotificationAttempted)

	if notify.Notifies(record.Verdict) && state.Before(ledger.NotificationAttempted) {
		if err := w.Ledger.Write(ctx, key, ledger.NotificationAttempted, mustJSON(record)); err != nil && !errors.Is(err, ledger.ErrExists) {
			return fmt.Errorf("record the notification attempt: %w", err)
		}
		state = ledger.NotificationAttempted
	}

	if notify.Notifies(record.Verdict) {
		if err := w.Notifier.Emit(ctx, record); err != nil {
			return fmt.Errorf("emit the verdict: %w", err)
		}
		w.Counters.Add(func(c *Counts) { c.NotificationsSent++ })
	}

	// The owner has been told and the message is still outstanding.
	w.crashIf(ledger.Acknowledged)

	m.Ack()
	if err := w.Ledger.Write(ctx, key, ledger.Acknowledged, mustJSON(record)); err != nil && !errors.Is(err, ledger.ErrExists) {
		// The message is already acknowledged, so this cannot be retried by redelivery. Record it loudly.
		w.logger().Error("acknowledged the message but could not record it", "key", key, "error", err)
	}
	return nil
}

// resume reads how far this finding already got, and records drift when the key matches and the digest does not.
func (w *Worker) resume(ctx context.Context, key string, env *scc.Envelope) (ledger.State, bool, error) {
	state, seen, err := w.Ledger.Furthest(ctx, key)
	if err != nil {
		return "", false, err
	}
	if !seen {
		return "", false, nil
	}

	w.Counters.Add(func(c *Counts) { c.Redelivered++ })

	// A redelivery whose key matches and whose digest differs is recorded as drift without inference.
	if previous, err := w.Ledger.Read(ctx, key, ledger.Received); err == nil {
		var stored verdict.Record
		if json.Unmarshal(previous, &stored) == nil && stored.Finding.Digest != "" && stored.Finding.Digest != env.Digest {
			w.Counters.Add(func(c *Counts) { c.Drift++ })
			w.logger().Warn("the finding body moved without advancing its event time",
				"key", key, "recorded_digest", stored.Finding.Digest, "delivered_digest", env.Digest)
		}
	}
	return state, true, nil
}

// recordFor produces the verdict, reusing the one already classified rather than settling it twice.
func (w *Worker) recordFor(ctx context.Context, key string, state ledger.State, seen bool, env *scc.Envelope, parseErr error) (verdict.Record, error) {
	if seen && !state.Before(ledger.Classified) {
		stored, err := w.Ledger.Read(ctx, key, ledger.Classified)
		if err != nil {
			return verdict.Record{}, fmt.Errorf("read the classified record: %w", err)
		}
		var record verdict.Record
		if err := json.Unmarshal(stored, &record); err != nil {
			return verdict.Record{}, fmt.Errorf("parse the classified record: %w", err)
		}
		return record, nil
	}

	record, err := w.settle(ctx, env, parseErr)
	if err != nil {
		return verdict.Record{}, err
	}
	if err := record.Validate(); err != nil {
		// Output that does not validate is rejected rather than read for meaning.
		record = verdict.Insufficient(env, []string{"the verdict record did not validate: " + err.Error()}, w.Provenance)
		if err := record.Validate(); err != nil {
			return verdict.Record{}, fmt.Errorf("even the refusal does not validate: %w", err)
		}
	}

	// The finding is settled and nothing is on record yet.
	w.crashIf(ledger.Received)

	// received is written first, before anything else, so the digest is on record for the next delivery.
	if !seen {
		if err := w.Ledger.Write(ctx, key, ledger.Received, mustJSON(record)); err != nil && !errors.Is(err, ledger.ErrExists) {
			return verdict.Record{}, fmt.Errorf("record receipt: %w", err)
		}
	}
	if err := w.Ledger.Write(ctx, key, ledger.Classified, mustJSON(record)); err != nil && !errors.Is(err, ledger.ErrExists) {
		return verdict.Record{}, fmt.Errorf("record the verdict: %w", err)
	}

	w.count(record)
	return record, nil
}

// settle runs the rules, and asks the model only about a complete finding they left unmatched. A call
// that does not complete is an error: nothing is on record yet, and the message goes back unacknowledged.
func (w *Worker) settle(ctx context.Context, env *scc.Envelope, parseErr error) (verdict.Record, error) {
	record := w.classify(env, parseErr)
	if w.Model == nil || parseErr != nil || record.Verdict != verdict.New {
		return record, nil
	}

	outcome, err := w.Model.Settle(ctx, env, w.Provenance)
	if err != nil {
		w.Counters.Add(func(c *Counts) { c.ModelErrors++ })
		return verdict.Record{}, err
	}
	w.Counters.Add(func(c *Counts) {
		if outcome.Called {
			c.ModelCalls++
		}
		switch outcome.Refusal {
		case model.RefusedBudget:
			c.RefusedBudget++
		case model.RefusedCeiling:
			c.RefusedCeiling++
		case model.RejectedOutput, model.RejectedCitation, model.RejectedAcceptance:
			c.ModelOutputRejected++
		}
	})
	return outcome.Record, nil
}

// classify settles the finding, or refuses to when a required field never arrived.
func (w *Worker) classify(env *scc.Envelope, parseErr error) verdict.Record {
	if parseErr != nil {
		return verdict.Insufficient(env, []string{parseErr.Error()}, w.Provenance)
	}
	return verdict.Classify(env, w.Index, w.Provenance)
}

func (w *Worker) count(r verdict.Record) {
	w.Counters.Add(func(c *Counts) {
		switch r.SettledBy {
		case verdict.SettledByRules:
			c.SettledByRules++
		case verdict.SettledByModel:
			c.SettledByModel++
		}
		switch r.Verdict {
		case verdict.Accepted:
			c.Accepted++
		case verdict.ContradictsDecision:
			c.ContradictsDecision++
		case verdict.New:
			c.New++
		case verdict.InsufficientEvidence:
			c.InsufficientEvidence++
		}
	})
}

// mustJSON encodes a record that has already validated, so a failure here is a programming error.
func mustJSON(r verdict.Record) []byte {
	body, err := json.Marshal(r)
	if err != nil {
		panic(fmt.Sprintf("marshal a validated verdict record: %v", err))
	}
	return body
}
