package ledger

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// memStore is a create-only object store, which is the one property the ledger rests on.
type memStore struct {
	objects map[string][]byte
	creates int
}

func newMemStore() *memStore { return &memStore{objects: map[string][]byte{}} }

func (m *memStore) Create(_ context.Context, name string, body []byte) error {
	m.creates++
	if _, exists := m.objects[name]; exists {
		return ErrExists
	}
	m.objects[name] = body
	return nil
}

func (m *memStore) Read(_ context.Context, name string) ([]byte, error) {
	body, ok := m.objects[name]
	if !ok {
		return nil, ErrNotFound
	}
	return body, nil
}

func (m *memStore) List(_ context.Context, prefix string) ([]string, error) {
	var names []string
	for name := range m.objects {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names, nil
}

const key = "projects/421458901689/sources/s/locations/global/findings/e5d7b4/2026-09-19T22:05:22.735Z/ACTIVE"

func TestWritePutsEachStateUnderTheKeyPrefix(t *testing.T) {
	store := newMemStore()
	l := New(store)

	if err := l.Write(context.Background(), key, Received, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("Write returned %v", err)
	}

	names, _ := store.List(context.Background(), "")
	if len(names) != 1 {
		t.Fatalf("wrote %d objects, want 1", len(names))
	}
	if !strings.HasPrefix(names[0], key+"/") {
		t.Errorf("object %q is not under the key prefix %q", names[0], key)
	}
	if !strings.Contains(names[0], string(Received)) {
		t.Errorf("object %q does not name its state", names[0])
	}
}

func TestWriteIsCreateOnly(t *testing.T) {
	store := newMemStore()
	l := New(store)
	ctx := context.Background()

	if err := l.Write(ctx, key, Received, []byte(`{"first":true}`)); err != nil {
		t.Fatalf("first Write returned %v", err)
	}
	err := l.Write(ctx, key, Received, []byte(`{"second":true}`))
	if !errors.Is(err, ErrExists) {
		t.Fatalf("second Write returned %v, want ErrExists", err)
	}

	// The loser reads the record rather than replacing it. Nothing in the ledger is ever overwritten.
	names, _ := store.List(ctx, "")
	if got := string(store.objects[names[0]]); got != `{"first":true}` {
		t.Errorf("object body = %s, want the first write preserved", got)
	}
}

func TestFurthestReturnsTheFurthestStatePresent(t *testing.T) {
	store := newMemStore()
	l := New(store)
	ctx := context.Background()

	for _, s := range []State{Received, Classified} {
		if err := l.Write(ctx, key, s, []byte(`{}`)); err != nil {
			t.Fatalf("Write(%q) returned %v", s, err)
		}
	}

	got, ok, err := l.Furthest(ctx, key)
	if err != nil {
		t.Fatalf("Furthest returned %v", err)
	}
	if !ok {
		t.Fatal("Furthest found nothing after two writes")
	}
	if got != Classified {
		t.Errorf("Furthest = %q, want %q", got, Classified)
	}
}

func TestFurthestIgnoresTheOrderStatesWereWrittenIn(t *testing.T) {
	store := newMemStore()
	l := New(store)
	ctx := context.Background()

	// A crash and a resume can write a later state before an earlier one is retried.
	for _, s := range []State{NotificationAttempted, Received} {
		if err := l.Write(ctx, key, s, []byte(`{}`)); err != nil {
			t.Fatalf("Write(%q) returned %v", s, err)
		}
	}

	got, _, err := l.Furthest(ctx, key)
	if err != nil {
		t.Fatalf("Furthest returned %v", err)
	}
	if got != NotificationAttempted {
		t.Errorf("Furthest = %q, want %q", got, NotificationAttempted)
	}
}

func TestFurthestReportsAnUnseenKey(t *testing.T) {
	l := New(newMemStore())
	_, ok, err := l.Furthest(context.Background(), key)
	if err != nil {
		t.Fatalf("Furthest returned %v", err)
	}
	if ok {
		t.Error("Furthest found a state for a key nothing was written under")
	}
}

func TestFurthestIgnoresAnObjectItDoesNotRecognize(t *testing.T) {
	store := newMemStore()
	store.objects[key+"/something-else.json"] = []byte(`{}`)
	l := New(store)

	_, ok, err := l.Furthest(context.Background(), key)
	if err != nil {
		t.Fatalf("Furthest returned %v", err)
	}
	if ok {
		t.Error("Furthest read an object whose name is not a state")
	}
}

func TestFurthestDoesNotMatchAKeyThatMerelySharesAPrefix(t *testing.T) {
	store := newMemStore()
	l := New(store)
	ctx := context.Background()

	// Two events on one finding: ACTIVE and ACTIVE_LATER share every character up to the state.
	if err := l.Write(ctx, key+"_LATER", Acknowledged, []byte(`{}`)); err != nil {
		t.Fatalf("Write returned %v", err)
	}

	_, ok, err := l.Furthest(ctx, key)
	if err != nil {
		t.Fatalf("Furthest returned %v", err)
	}
	if ok {
		t.Error("Furthest matched a different key sharing a prefix")
	}
}

func TestStatesAreOrderedAsTheDecisionRecordsThem(t *testing.T) {
	want := []State{Received, Classified, NotificationAttempted, Acknowledged}
	for i := 1; i < len(want); i++ {
		if !want[i-1].Before(want[i]) {
			t.Errorf("%q is not before %q", want[i-1], want[i])
		}
	}
	if Acknowledged.Before(Received) {
		t.Error("acknowledged sorts before received")
	}
}

func TestStateSpellingsAreTheOnesTheDecisionRecords(t *testing.T) {
	cases := map[State]string{
		Received:              "received",
		Classified:            "classified",
		NotificationAttempted: "notification_attempted",
		Acknowledged:          "acknowledged",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("state spelled %q, want %q", got, want)
		}
	}
}
