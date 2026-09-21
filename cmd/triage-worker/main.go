// Command triage-worker pulls Security Command Center findings and settles them against the corpus.
//
// Increment 1 calls no model, so the whole path is proven before a single token is spent. It runs as
// one replica in the agents namespace, pulling continuously, and holds four grants: consume on one
// subscription, object create and read on the ledger bucket, invoke on Vertex AI, and write on its
// own log. It holds no Security Command Center permission and no cluster credential.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloud.google.com/go/pubsub/v2"

	"github.com/sindredg/ai-k8s/internal/corpus"
	"github.com/sindredg/ai-k8s/internal/gcp"
	"github.com/sindredg/ai-k8s/internal/health"
	"github.com/sindredg/ai-k8s/internal/ledger"
	"github.com/sindredg/ai-k8s/internal/model"
	"github.com/sindredg/ai-k8s/internal/notify"
	"github.com/sindredg/ai-k8s/internal/verdict"
	"github.com/sindredg/ai-k8s/internal/worker"
)

func main() {
	corpusPath := flag.String("corpus", "/corpus/corpus.json", "the index corpusc compiled into the image")
	subscription := flag.String("subscription", "scc-triage", "the one subscription this identity may pull")
	bucket := flag.String("ledger-bucket", "", "the verdict ledger bucket")
	reportEvery := flag.Duration("report-every", 5*time.Minute, "how often to log the counters")
	probeAddr := flag.String("probe-addr", ":8080", "where the kubelet reads /healthz and /readyz")
	idleLimit := flag.Duration("idle-limit", 24*time.Hour, "report not live after this long with no message; 0 disables it")
	crashAt := flag.String("crash-at", "", "stop at a drill boundary: received, notification_attempted or acknowledged; empty disables it")

	// Increment 2. Empty -model runs the rules alone.
	modelID := flag.String("model", "", "the Vertex AI publisher model for unmatched findings; empty disables the model")
	modelLocation := flag.String("model-location", "europe-north1", "the Vertex AI region the model is called in")
	modelTimeout := flag.Duration("model-timeout", 30*time.Second, "how long one model call may take before the message goes back unacknowledged")
	maxInputTokens := flag.Int("max-input-tokens", 16384, "input over this is refused as insufficient_evidence rather than truncated")
	maxOutputTokens := flag.Int("max-output-tokens", 1024, "the most the model may write; output cut off at this is rejected")
	ceilingUSD := flag.Float64("daily-spend-ceiling-usd", 1.00, "model spend reserved per UTC day before the model stops being called")
	priceIn := flag.Float64("price-input-usd-per-mtok", 0.30, "estimated USD per million input tokens")
	priceOut := flag.Float64("price-output-usd-per-mtok", 2.50, "estimated USD per million output tokens")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := run(settings{
		corpusPath:   *corpusPath,
		subscription: *subscription,
		bucketName:   *bucket,
		reportEvery:  *reportEvery,
		probeAddr:    *probeAddr,
		idleLimit:    *idleLimit,
		crashAt:      *crashAt,
		model: modelSettings{
			id:              *modelID,
			location:        *modelLocation,
			timeout:         *modelTimeout,
			maxInputTokens:  *maxInputTokens,
			maxOutputTokens: *maxOutputTokens,
			ceilingUSD:      *ceilingUSD,
			prices:          model.Prices{InputPerMillion: *priceIn, OutputPerMillion: *priceOut},
		},
	}, log); err != nil {
		log.Error("the worker stopped", "error", err)
		os.Exit(1)
	}
}

// settings are the flags, gathered so run takes one argument rather than six.
type settings struct {
	corpusPath   string
	subscription string
	bucketName   string
	reportEvery  time.Duration
	probeAddr    string
	idleLimit    time.Duration
	crashAt      string
	model        modelSettings
}

// modelSettings configure Increment 2. An empty id leaves the model off.
type modelSettings struct {
	id              string
	location        string
	timeout         time.Duration
	maxInputTokens  int
	maxOutputTokens int
	ceilingUSD      float64
	prices          model.Prices
}

func run(s settings, log *slog.Logger) error {
	// Refuse at startup rather than emitting entries the alert policy silently does not match.
	pod, err := notify.PodIdentityFrom(os.Getenv)
	if err != nil {
		return err
	}
	if s.bucketName == "" {
		return errors.New("-ledger-bucket is required")
	}

	// Refuse a boundary that does not exist rather than running a drill that never crashes.
	crashAt, err := worker.ParseCrashAt(s.crashAt)
	if err != nil {
		return err
	}
	if crashAt != "" {
		// A worker left holding the flag stops on the next finding it settles, so say so loudly.
		log.Warn("the crash drill boundary is set, this worker will stop on purpose", "boundary", crashAt)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Serving before the clients open means a slow startup reads as not ready rather than as a
	// crash, and liveness answers throughout.
	probes := health.New(s.idleLimit)
	go serveProbes(ctx, s.probeAddr, probes, log)

	index, err := loadCorpus(s.corpusPath)
	if err != nil {
		return err
	}
	log.Info("corpus loaded", "entries", len(index.Entries), "categories", len(index.Mapping), "path", s.corpusPath)

	bucket, closeBucket, err := gcp.NewBucket(ctx, s.bucketName)
	if err != nil {
		return err
	}
	defer closeBucket()

	verdictLog, closeLog, err := gcp.NewVerdictLog(ctx, pod.ProjectID, pod)
	if err != nil {
		return err
	}
	defer closeLog()

	w := &worker.Worker{
		Index:      index,
		Ledger:     ledger.New(bucket),
		Notifier:   verdictLog,
		Provenance: provenance(),
		Log:        log,
		CrashAt:    crashAt,
	}

	if s.model.id != "" {
		caller, err := gcp.NewVertex(ctx, pod.ProjectID, s.model.location, s.model.id, s.model.timeout)
		if err != nil {
			return err
		}
		w.Model = &model.Settler{
			Caller:         caller,
			Params:         model.Params{Model: s.model.id, Temperature: 0, MaxOutputTokens: s.model.maxOutputTokens, ThinkingBudget: 0},
			Index:          index,
			MaxInputTokens: s.model.maxInputTokens,
			Prices:         s.model.prices,
			Spend:          model.NewSpend(bucket, s.model.ceilingUSD, nil),
		}
		log.Info("the model settles unmatched findings", "model", s.model.id, "location", s.model.location,
			"max_input_tokens", s.model.maxInputTokens, "daily_spend_ceiling_usd", s.model.ceilingUSD)
	} else {
		log.Info("no model configured, the rules settle every finding")
	}

	client, err := pubsub.NewClient(ctx, pod.ProjectID)
	if err != nil {
		return fmt.Errorf("open pub/sub: %w", err)
	}
	defer client.Close()

	// One replica, one message at a time. Throughput is not the constraint here; a model call will be.
	sub := client.Subscriber(s.subscription)
	sub.ReceiveSettings.NumGoroutines = 1
	sub.ReceiveSettings.MaxOutstandingMessages = 1

	go report(ctx, w, s.reportEvery, log)

	log.Info("pulling", "subscription", s.subscription, "bucket", s.bucketName, "namespace", pod.Namespace, "pod", pod.PodName)
	probes.Started()
	if err := sub.Receive(ctx, func(ctx context.Context, m *pubsub.Message) {
		probes.Seen()
		w.Handle(ctx, message{m})
	}); err != nil && ctx.Err() == nil {
		return fmt.Errorf("receive: %w", err)
	}

	counts, _ := json.Marshal(w.Counters.Snapshot())
	log.Info("stopped", "counts", json.RawMessage(counts))
	return nil
}

// loadCorpus reads the index the build compiled. Nothing here reads a corpus source at runtime.
func loadCorpus(path string) (*corpus.Index, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the compiled corpus: %w", err)
	}
	return corpus.Unmarshal(body)
}

// provenance is stamped into the image at build time, so a verdict names the tree it came from.
func provenance() verdict.Provenance {
	return verdict.Provenance{
		CorpusCommit: os.Getenv("CORPUS_COMMIT"),
		AgentCommit:  os.Getenv("AGENT_COMMIT"),
		ImageDigest:  os.Getenv("IMAGE_DIGEST"),
	}
}

// report publishes the counters periodically. The rules-settled number is the one Phase 15 publishes.
func report(ctx context.Context, w *worker.Worker, every time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			counts, err := json.Marshal(w.Counters.Snapshot())
			if err != nil {
				continue
			}
			log.Info("counters", "counts", json.RawMessage(counts))
		}
	}
}

// serveProbes answers the kubelet. A failure here is logged rather than fatal: the worker triaging
// findings matters more than the probe server, and a dead probe server fails the liveness check anyway.
func serveProbes(ctx context.Context, addr string, probes *health.State, log *slog.Logger) {
	server := &http.Server{
		Addr:              addr,
		Handler:           probes.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("the probe server stopped", "error", err)
	}
}

// message adapts a Pub/Sub message to the worker's two outcomes.
type message struct{ m *pubsub.Message }

func (m message) Body() []byte { return m.m.Data }
func (m message) Ack()         { m.m.Ack() }
func (m message) Nack()        { m.m.Nack() }
