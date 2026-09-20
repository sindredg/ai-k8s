// Package notify turns a verdict into the log entry the alert policy reads.
//
// A notification channel has no send API, so a verdict becomes a log entry, a logs-based metric
// counts it, and the policy carries its labels into the mail. Two things here are contracts with
// terraform/modules/observability/triage.tf rather than choices: the log id, and the monitored
// resource type. Either one wrong and the alert fails silently.
package notify

import (
	"fmt"
	"strings"

	"github.com/sindredg/ai-k8s/internal/verdict"
)

// LogID is the log triage.tf filters on: logName = "projects/<project>/logs/triage-verdict".
const LogID = "triage-verdict"

// resourceType is what the alert policy's condition filter requires. A client library reports
// "global" instead, the metric still counts the entry, and the alert never fires.
const resourceType = "k8s_container"

// PodIdentity is what k8s_container needs to identify the writer. Every field is required.
type PodIdentity struct {
	ProjectID     string
	ClusterName   string
	Location      string
	Namespace     string
	PodName       string
	ContainerName string
}

// Resource is a monitored resource, in the shape the logging client takes.
type Resource struct {
	Type   string
	Labels map[string]string
}

// MonitoredResource builds the k8s_container resource explicitly, rather than letting the library detect one.
func MonitoredResource(p PodIdentity) Resource {
	return Resource{
		Type: resourceType,
		Labels: map[string]string{
			"project_id":     p.ProjectID,
			"location":       p.Location,
			"cluster_name":   p.ClusterName,
			"namespace_name": p.Namespace,
			"pod_name":       p.PodName,
			"container_name": p.ContainerName,
		},
	}
}

// Payload is the jsonPayload the metric extracts its labels from.
func Payload(r verdict.Record) verdict.Record { return r }

// Notifies reports whether a verdict reaches the owner. Accepted is recorded and stays quiet,
// which is what the metric filter jsonPayload.verdict != "accepted" already enforces.
func Notifies(v verdict.Value) bool { return v != verdict.Accepted }

// PodIdentityFrom reads the identity from the environment, refusing rather than defaulting.
// A missing label produces a resource the alert policy does not match, and that failure is silent.
func PodIdentityFrom(lookup func(string) string) (PodIdentity, error) {
	var p PodIdentity
	fields := []struct {
		env string
		out *string
	}{
		{"PROJECT_ID", &p.ProjectID},
		{"CLUSTER_NAME", &p.ClusterName},
		{"CLUSTER_LOCATION", &p.Location},
		{"POD_NAMESPACE", &p.Namespace},
		{"POD_NAME", &p.PodName},
		{"CONTAINER_NAME", &p.ContainerName},
	}

	var missing []string
	for _, f := range fields {
		v := strings.TrimSpace(lookup(f.env))
		if v == "" {
			missing = append(missing, f.env)
			continue
		}
		*f.out = v
	}
	if len(missing) > 0 {
		return PodIdentity{}, fmt.Errorf("the log entry needs %s, which the Pod does not set", strings.Join(missing, ", "))
	}
	return p, nil
}
