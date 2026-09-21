package notify

import (
	"encoding/json"
	"testing"

	"github.com/sindredg/ai-k8s/internal/verdict"
)

func testRecord(v verdict.Value) verdict.Record {
	return verdict.Record{
		SchemaVersion: verdict.SchemaVersion,
		Verdict:       v,
		CorpusMatch:   verdict.MatchNone,
		SettledBy:     verdict.SettledByRules,
		Finding: verdict.FindingRef{
			Category: "BINARY_AUTHORIZATION_DISABLED",
			Severity: "MEDIUM",
			Digest:   "sha256:abc",
		},
	}
}

func testPod() PodIdentity {
	return PodIdentity{
		ProjectID:     "project-69726555",
		ClusterName:   "k8-lab",
		Location:      "europe-north1-a",
		Namespace:     "agents",
		PodName:       "triage-worker-7d9f-abcde",
		ContainerName: "worker",
	}
}

func TestResourceTypeIsK8sContainerRatherThanWhatTheLibraryDetects(t *testing.T) {
	// The alert policy filters on resource.type = "k8s_container". A client library reports
	// "global", the metric still counts the entry, and the alert never fires.
	if got := MonitoredResource(testPod()).Type; got != "k8s_container" {
		t.Errorf("resource type = %q, want k8s_container", got)
	}
}

func TestMonitoredResourceCarriesEveryLabelK8sContainerRequires(t *testing.T) {
	labels := MonitoredResource(testPod()).Labels
	want := map[string]string{
		"project_id":     "project-69726555",
		"location":       "europe-north1-a",
		"cluster_name":   "k8-lab",
		"namespace_name": "agents",
		"pod_name":       "triage-worker-7d9f-abcde",
		"container_name": "worker",
	}
	for k, v := range want {
		if labels[k] != v {
			t.Errorf("label %s = %q, want %q", k, labels[k], v)
		}
	}
}

func TestLogNameIsTheOneTheMetricFiltersOn(t *testing.T) {
	// triage.tf filters logName = "projects/<project>/logs/triage-verdict".
	if LogID != "triage-verdict" {
		t.Errorf("LogID = %q, want triage-verdict", LogID)
	}
}

func TestPayloadCarriesTheVerdictSpellingTheFilterCompares(t *testing.T) {
	body, err := json.Marshal(Payload(testRecord(verdict.Accepted)))
	if err != nil {
		t.Fatalf("Marshal returned %v", err)
	}
	// jsonPayload.verdict != "accepted" is an exact string comparison, and any other
	// spelling of accepted matches it and pages the platform owner.
	if !jsonHas(t, body, "verdict", "accepted") {
		t.Errorf("payload does not carry verdict as the exact lowercase string: %s", body)
	}
}

func TestPayloadCarriesTheFieldsTheLabelExtractorsRead(t *testing.T) {
	body, err := json.Marshal(Payload(testRecord(verdict.New)))
	if err != nil {
		t.Fatalf("Marshal returned %v", err)
	}
	var payload struct {
		Verdict string `json:"verdict"`
		Finding struct {
			Category string `json:"category"`
			Severity string `json:"severity"`
		} `json:"finding"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("Unmarshal returned %v", err)
	}
	if payload.Verdict != "new" {
		t.Errorf("jsonPayload.verdict = %q", payload.Verdict)
	}
	if payload.Finding.Category != "BINARY_AUTHORIZATION_DISABLED" {
		t.Errorf("jsonPayload.finding.category = %q", payload.Finding.Category)
	}
	if payload.Finding.Severity != "MEDIUM" {
		t.Errorf("jsonPayload.finding.severity = %q", payload.Finding.Severity)
	}
}

func TestNotifiesReportsWhichVerdictsReachTheOwner(t *testing.T) {
	// The metric counts jsonPayload.verdict != "accepted". Accepted is recorded and stays quiet.
	cases := map[verdict.Value]bool{
		verdict.Accepted:             false,
		verdict.ContradictsDecision:  true,
		verdict.New:                  true,
		verdict.InsufficientEvidence: true,
	}
	for v, want := range cases {
		if got := Notifies(v); got != want {
			t.Errorf("Notifies(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestPodIdentityFromEnvReadsTheDownwardAPINames(t *testing.T) {
	env := map[string]string{
		"PROJECT_ID":       "project-69726555",
		"CLUSTER_NAME":     "k8-lab",
		"CLUSTER_LOCATION": "europe-north1-a",
		"POD_NAMESPACE":    "agents",
		"POD_NAME":         "triage-worker-7d9f-abcde",
		"CONTAINER_NAME":   "worker",
	}
	got, err := PodIdentityFrom(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("PodIdentityFrom returned %v", err)
	}
	if got != testPod() {
		t.Errorf("PodIdentityFrom = %+v, want %+v", got, testPod())
	}
}

func TestPodIdentityFromRefusesAMissingLabel(t *testing.T) {
	// A missing label produces a resource the alert policy does not match, and the failure is silent.
	// Refusing at startup turns that into a crash loop the owner can see.
	for _, missing := range []string{"PROJECT_ID", "CLUSTER_NAME", "CLUSTER_LOCATION", "POD_NAMESPACE", "POD_NAME", "CONTAINER_NAME"} {
		env := map[string]string{
			"PROJECT_ID": "p", "CLUSTER_NAME": "c", "CLUSTER_LOCATION": "l",
			"POD_NAMESPACE": "n", "POD_NAME": "pod", "CONTAINER_NAME": "worker",
		}
		delete(env, missing)
		if _, err := PodIdentityFrom(func(k string) string { return env[k] }); err == nil {
			t.Errorf("PodIdentityFrom accepted an identity with no %s", missing)
		}
	}
}

func jsonHas(t *testing.T, body []byte, key, want string) bool {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("Unmarshal returned %v", err)
	}
	got, _ := m[key].(string)
	return got == want
}

func TestAModelVerdictCarriesItsTokensAndCostAsLabels(t *testing.T) {
	r := verdict.Record{SettledBy: verdict.SettledByModel, Provenance: verdict.Provenance{
		Model: "gemini-2.5-flash@001", InputTokens: 9000, OutputTokens: 120, CostEstimate: "0.003000 USD",
	}}
	got := Labels(r)
	if got["input_tokens"] != "9000" || got["output_tokens"] != "120" || got["cost_estimate"] != "0.003000 USD" || got["model"] == "" {
		t.Fatalf("labels: %v", got)
	}
	if rules := Labels(verdict.Record{SettledBy: verdict.SettledByRules}); len(rules) != 1 {
		t.Fatalf("a rules verdict carries model labels: %v", rules)
	}
}
