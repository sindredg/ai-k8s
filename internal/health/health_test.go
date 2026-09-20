package health

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReadyIsFalseUntilThePullLoopStarts(t *testing.T) {
	s := New(time.Minute)
	if s.Ready() {
		t.Error("the worker reported ready before it started pulling")
	}
	s.Started()
	if !s.Ready() {
		t.Error("the worker did not report ready after it started pulling")
	}
}

func TestLiveIsFalseWhenNothingHasBeenSeenForTooLong(t *testing.T) {
	// A wedged Receive loop is otherwise invisible: the process is up and triages nothing.
	s := New(time.Minute)
	s.Started()
	s.Seen()

	s.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if s.Live() {
		t.Error("the worker reported live after twice the idle budget with no message")
	}
}

func TestLiveStaysTrueWhileMessagesArrive(t *testing.T) {
	s := New(time.Minute)
	s.Started()

	s.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	s.Seen() // A message arrived late, which is the loop working rather than wedged.
	if !s.Live() {
		t.Error("the worker reported not live although a message just arrived")
	}
}

func TestLiveIsTrueBeforeAnyMessageArrives(t *testing.T) {
	// An idle subscription is the normal state. Findings arrive in bursts, and a quiet
	// hour is not a wedged worker, so the clock starts when the loop does.
	s := New(time.Minute)
	s.Started()
	if !s.Live() {
		t.Error("the worker reported not live before any finding had arrived")
	}
}

func TestLiveIsTrueBeforeTheLoopStarts(t *testing.T) {
	// Startup opens three clients. Liveness must not kill the Pod while readiness is still false.
	s := New(time.Minute)
	if !s.Live() {
		t.Error("the worker reported not live during startup")
	}
}

func TestAnIdleBudgetOfZeroDisablesTheDeadline(t *testing.T) {
	s := New(0)
	s.Started()
	s.now = func() time.Time { return time.Now().Add(72 * time.Hour) }
	if !s.Live() {
		t.Error("an idle budget of zero still expired")
	}
}

func TestHandlerAnswersTheTwoPaths(t *testing.T) {
	s := New(time.Minute)
	h := s.Handler()

	cases := []struct {
		path string
		want int
	}{
		{"/healthz", http.StatusOK},                // Live during startup.
		{"/readyz", http.StatusServiceUnavailable}, // Not ready until the loop starts.
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		if rec.Code != c.want {
			t.Errorf("GET %s = %d, want %d", c.path, rec.Code, c.want)
		}
	}

	s.Started()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /readyz after start = %d, want 200", rec.Code)
	}
}

func TestHandlerRefusesAnythingElse(t *testing.T) {
	// The probe server is reachable from the kubelet and serves two paths, not a surface.
	rec := httptest.NewRecorder()
	New(time.Minute).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET / = %d, want 404", rec.Code)
	}
}
