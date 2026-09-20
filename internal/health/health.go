// Package health answers the kubelet's two probes.
//
// The worker serves no traffic, so without this a wedged Receive loop is invisible: the process
// stays up and triages nothing, which is the failure a security tool can least afford.
package health

import (
	"net/http"
	"sync"
	"time"
)

// State tracks whether the pull loop started and when it last saw a message.
type State struct {
	mu        sync.Mutex
	started   bool
	lastSeen  time.Time
	idleLimit time.Duration

	// now is swapped in tests. Nothing else replaces it.
	now func() time.Time
}

// New returns a state that reports not live once idleLimit passes with no message. Zero disables the deadline.
func New(idleLimit time.Duration) *State {
	return &State{idleLimit: idleLimit, now: time.Now}
}

// Started marks the pull loop as running, which is what readiness reports.
func (s *State) Started() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = true
	s.lastSeen = s.now()
}

// Seen records that a message arrived. The loop is working, whatever the verdict was.
func (s *State) Seen() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSeen = s.now()
}

// Ready reports whether the worker is pulling. It is false while the clients are still opening.
func (s *State) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

// Live reports whether the loop is still moving. It stays true during startup, so liveness does not
// kill the Pod while readiness is legitimately false, and true on an idle subscription until the
// budget passes, because a quiet hour is the normal state rather than a wedged worker.
func (s *State) Live() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started || s.idleLimit <= 0 {
		return true
	}
	return s.now().Sub(s.lastSeen) < s.idleLimit
}

// Handler serves the two probe paths and nothing else.
func (s *State) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		answer(w, s.Live())
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		answer(w, s.Ready())
	})
	return mux
}

func answer(w http.ResponseWriter, ok bool) {
	if !ok {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
