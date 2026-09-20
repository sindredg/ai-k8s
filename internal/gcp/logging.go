package gcp

import (
	"context"
	"fmt"

	"cloud.google.com/go/logging"
	mrpb "google.golang.org/genproto/googleapis/api/monitoredres"

	"github.com/sindredg/ai-k8s/internal/notify"
	"github.com/sindredg/ai-k8s/internal/verdict"
)

// VerdictLog emits the log entry the logs-based metric counts and the alert policy reads.
type VerdictLog struct {
	client *logging.Client
	logger *logging.Logger
}

// NewVerdictLog opens the log triage.tf filters on, with the monitored resource set explicitly.
// The library would otherwise report "global", the metric would still count the entry, and the
// alert would never fire, which is a failure nobody sees.
func NewVerdictLog(ctx context.Context, projectID string, pod notify.PodIdentity) (*VerdictLog, func() error, error) {
	client, err := logging.NewClient(ctx, "projects/"+projectID)
	if err != nil {
		return nil, nil, fmt.Errorf("open cloud logging: %w", err)
	}

	resource := notify.MonitoredResource(pod)
	logger := client.Logger(notify.LogID, logging.CommonResource(&mrpb.MonitoredResource{
		Type:   resource.Type,
		Labels: resource.Labels,
	}))

	v := &VerdictLog{client: client, logger: logger}
	return v, client.Close, nil
}

// Emit writes one verdict and flushes it. A buffered entry that never leaves the process is a
// notification that never happened, and the ledger has already recorded that one was attempted.
func (v *VerdictLog) Emit(_ context.Context, r verdict.Record) error {
	v.logger.Log(logging.Entry{
		Severity: severityFor(r.Verdict),
		Payload:  notify.Payload(r),
	})
	if err := v.logger.Flush(); err != nil {
		return fmt.Errorf("flush the verdict entry: %w", err)
	}
	return nil
}

// severityFor rates the entry itself. The alert fires off the metric rather than off this, so it is
// for whoever reads the log directly.
func severityFor(value verdict.Value) logging.Severity {
	switch value {
	case verdict.ContradictsDecision:
		return logging.Warning
	case verdict.InsufficientEvidence:
		return logging.Warning
	case verdict.New:
		return logging.Notice
	default:
		return logging.Info
	}
}
