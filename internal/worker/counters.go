package worker

import "sync"

// Counts is what the worker reports about a run. The rules-settled number is the one Phase 15 publishes.
type Counts struct {
	Received               int `json:"received"`
	Unreadable             int `json:"unreadable"`
	VulnerabilitiesSkipped int `json:"vulnerabilities_skipped"`
	Redelivered            int `json:"redelivered"`
	Drift                  int `json:"drift"`
	SettledByRules         int `json:"settled_by_rules"`
	SettledByModel         int `json:"settled_by_model"`
	Accepted               int `json:"accepted"`
	ContradictsDecision    int `json:"contradicts_decision"`
	New                    int `json:"new"`
	InsufficientEvidence   int `json:"insufficient_evidence"`
	NotificationsSent      int `json:"notifications_sent"`
	Failed                 int `json:"failed"`

	// The model's half. A call is money spent; an error is a call that did not complete.
	ModelCalls          int `json:"model_calls"`
	ModelErrors         int `json:"model_errors"`
	ModelOutputRejected int `json:"model_output_rejected"`
	RefusedBudget       int `json:"refused_budget"`
	RefusedCeiling      int `json:"refused_ceiling"`
}

// Counters is a Counts guarded for the concurrent receive the Pub/Sub client runs.
type Counters struct {
	mu sync.Mutex
	c  Counts
}

// Add applies one change under the lock.
func (c *Counters) Add(f func(*Counts)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(&c.c)
}

// Snapshot returns a copy safe to read and print.
func (c *Counters) Snapshot() Counts {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.c
}
