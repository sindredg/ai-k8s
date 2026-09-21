package model

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/sindredg/ai-k8s/internal/ledger"
)

// Prices are USD per million tokens. They are an estimate, set from the published price list.
type Prices struct {
	InputPerMillion  float64
	OutputPerMillion float64
}

// Cost is the estimated charge for one call.
func (p Prices) Cost(inputTokens, outputTokens int) float64 {
	return float64(inputTokens)*p.InputPerMillion/1e6 + float64(outputTokens)*p.OutputPerMillion/1e6
}

// Spend holds the daily ceiling. Every call reserves its worst case in the ledger bucket before it is
// made, so the ceiling holds across restarts and crash loops, and actual spend is at most what is
// reserved. A budget alert is not a limit: it arrives after the money is spent.
type Spend struct {
	store   ledger.Store
	ceiling float64
	now     func() time.Time

	mu    sync.Mutex
	day   string
	total float64
}

// NewSpend opens the ceiling. A ceiling of zero refuses every call.
func NewSpend(store ledger.Store, ceilingUSD float64, now func() time.Time) *Spend {
	if now == nil {
		now = time.Now
	}
	return &Spend{store: store, ceiling: ceilingUSD, now: now}
}

// reservation is one object under spend/<day>/.
type reservation struct {
	USD float64 `json:"usd"`
	Key string  `json:"key"`
	At  string  `json:"at"`
}

// Reserve records usd against today's total, or refuses when it would pass the ceiling. It returns the
// total reserved today, after this reservation when it is granted. An error means the ledger could not
// be read or written, and no call may be made.
func (s *Spend) Reserve(ctx context.Context, key string, usd float64) (bool, float64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now().UTC()
	day := now.Format("2006-01-02")
	if day != s.day {
		total, err := s.load(ctx, day)
		if err != nil {
			return false, 0, err
		}
		s.day, s.total = day, total
	}

	if s.total+usd > s.ceiling {
		return false, s.total, nil
	}

	body, err := json.Marshal(reservation{USD: usd, Key: key, At: now.Format(time.RFC3339Nano)})
	if err != nil {
		return false, s.total, fmt.Errorf("encode the spend reservation: %w", err)
	}
	// The random part keeps two reservations for one finding in one instant from colliding, which a
	// redelivery racing a restart can produce, and create-only would otherwise refuse.
	sum := sha256.Sum256([]byte(key))
	nonce := make([]byte, 6)
	if _, err := rand.Read(nonce); err != nil {
		return false, s.total, fmt.Errorf("name the spend reservation: %w", err)
	}
	name := fmt.Sprintf("spend/%s/%s-%d-%s.json", day, hex.EncodeToString(sum[:8]), now.UnixNano(), hex.EncodeToString(nonce))
	if err := s.store.Create(ctx, name, body); err != nil {
		return false, s.total, fmt.Errorf("reserve model spend: %w", err)
	}
	s.total += usd
	return true, s.total, nil
}

// Ceiling is the configured limit, for the refusal message.
func (s *Spend) Ceiling() float64 { return s.ceiling }

// load sums what is already reserved today, so a restart does not reset the ceiling.
func (s *Spend) load(ctx context.Context, day string) (float64, error) {
	names, err := s.store.List(ctx, "spend/"+day+"/")
	if err != nil {
		return 0, fmt.Errorf("read today's model spend: %w", err)
	}
	var total float64
	for _, name := range names {
		body, err := s.store.Read(ctx, name)
		if err != nil {
			return 0, fmt.Errorf("read today's model spend: %w", err)
		}
		var r reservation
		if err := json.Unmarshal(body, &r); err != nil {
			return 0, fmt.Errorf("parse spend reservation %s: %w", name, err)
		}
		total += r.USD
	}
	return total, nil
}
