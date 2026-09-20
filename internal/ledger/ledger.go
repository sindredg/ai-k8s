// Package ledger records what happened to each finding, append-only, in an object store.
//
// The ledger is the replay source Phase 18 rebuilds from, so nothing here overwrites or deletes.
// Every write uses a create-only precondition, which is what lets the worker hold no delete permission.
package ledger

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrExists reports that the object is already there. On a redelivery that is the signal, not a failure.
var ErrExists = errors.New("ledger object already exists")

// ErrNotFound reports that no object is stored under that name.
var ErrNotFound = errors.New("ledger object not found")

// State is how far a finding got. A finding's current state is the furthest state present under its key.
type State string

const (
	Received              State = "received"
	Classified            State = "classified"
	NotificationAttempted State = "notification_attempted"
	Acknowledged          State = "acknowledged"
)

// order fixes the sequence the idempotency decision records.
var order = []State{Received, Classified, NotificationAttempted, Acknowledged}

// Before reports whether s comes earlier in the state machine than other.
func (s State) Before(other State) bool {
	return s.rank() < other.rank()
}

func (s State) rank() int {
	for i, known := range order {
		if s == known {
			return i
		}
	}
	return -1
}

// Store is the object store the ledger writes through. Create must refuse an object that exists,
// and Read must return ErrNotFound rather than an empty body for one that does not.
type Store interface {
	Create(ctx context.Context, name string, body []byte) error
	List(ctx context.Context, prefix string) ([]string, error)
	Read(ctx context.Context, name string) ([]byte, error)
}

// Ledger writes one object per finding state, under one prefix per key.
type Ledger struct {
	store Store
}

func New(store Store) *Ledger { return &Ledger{store: store} }

// objectName is the one place the object layout is decided.
func objectName(key string, state State) string {
	return fmt.Sprintf("%s/%s.json", key, state)
}

// Write creates the object for one state. It returns ErrExists when the state is already recorded,
// so two workers on the same message produce one object and one loser that reads it.
func (l *Ledger) Write(ctx context.Context, key string, state State, body []byte) error {
	if state.rank() < 0 {
		return fmt.Errorf("ledger: %q is not a state", state)
	}
	return l.store.Create(ctx, objectName(key, state), body)
}

// Furthest returns the furthest state recorded under a key, and whether anything is recorded at all.
func (l *Ledger) Furthest(ctx context.Context, key string) (State, bool, error) {
	prefix := key + "/"
	names, err := l.store.List(ctx, prefix)
	if err != nil {
		return "", false, fmt.Errorf("ledger: list %s: %w", prefix, err)
	}

	furthest, found := State(""), false
	for _, name := range names {
		tail := strings.TrimPrefix(name, prefix)
		if strings.Contains(tail, "/") {
			continue // Belongs to a deeper prefix, not to this key.
		}
		state := State(strings.TrimSuffix(tail, ".json"))
		if state.rank() < 0 {
			continue // Not a state this worker writes.
		}
		if !found || furthest.Before(state) {
			furthest, found = state, true
		}
	}
	return furthest, found, nil
}

// Read returns the object recorded for one state, or ErrNotFound.
func (l *Ledger) Read(ctx context.Context, key string, state State) ([]byte, error) {
	return l.store.Read(ctx, objectName(key, state))
}
