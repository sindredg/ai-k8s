package scc

import (
	"strings"
	"testing"
)

// The envelope shape recorded in worklog/phase-15-scc-triage.md, slice 4.
const realEnvelope = `{
  "notificationConfigName": "projects/p/locations/global/notificationConfigs/k8-lab-triage",
  "finding": {
    "name": "organizations/550178366891/sources/1405720631579532947/locations/global/findings/e5d7b4",
    "canonicalName": "projects/421458901689/sources/1405720631579532947/locations/global/findings/e5d7b4",
    "parent": "organizations/550178366891/sources/1405720631579532947/locations/global",
    "parentDisplayName": "Security Health Analytics",
    "category": "MASTER_AUTHORIZED_NETWORKS_DISABLED",
    "resourceName": "//container.googleapis.com/projects/project-69726555/locations/europe-north1-a/clusters/k8-lab",
    "state": "ACTIVE",
    "severity": "MEDIUM",
    "findingClass": "MISCONFIGURATION",
    "eventTime": "2026-09-19T22:05:22.735Z",
    "createTime": "2026-09-19T22:05:24.695Z",
    "description": "Master authorized networks is disabled on this cluster.",
    "externalUri": "https://console.cloud.google.com/kubernetes/clusters",
    "mute": "UNDEFINED",
    "sourceProperties": {"Recommendation": "Enable master authorized networks."}
  },
  "resource": {"name": "//container.googleapis.com/projects/project-69726555/locations/europe-north1-a/clusters/k8-lab"}
}`

func TestParseReadsTheFieldsTheWorkerActsOn(t *testing.T) {
	env, err := Parse([]byte(realEnvelope))
	if err != nil {
		t.Fatalf("Parse returned %v", err)
	}
	f := env.Finding

	if f.Category != "MASTER_AUTHORIZED_NETWORKS_DISABLED" {
		t.Errorf("Category = %q", f.Category)
	}
	if !strings.HasSuffix(f.ResourceName, "/clusters/k8-lab") {
		t.Errorf("ResourceName = %q", f.ResourceName)
	}
	if f.State != "ACTIVE" || f.Severity != "MEDIUM" || f.FindingClass != "MISCONFIGURATION" {
		t.Errorf("state/severity/class = %q/%q/%q", f.State, f.Severity, f.FindingClass)
	}
	if f.EventTime != "2026-09-19T22:05:22.735Z" {
		t.Errorf("EventTime = %q", f.EventTime)
	}
}

func TestParseKeepsTheCanonicalNameSeparateFromTheName(t *testing.T) {
	env, err := Parse([]byte(realEnvelope))
	if err != nil {
		t.Fatalf("Parse returned %v", err)
	}
	// A finding is read at organization scope and written at project scope, so the two are not interchangeable.
	if !strings.HasPrefix(env.Finding.CanonicalName, "projects/") {
		t.Errorf("CanonicalName = %q, want the project-scoped form", env.Finding.CanonicalName)
	}
	if !strings.HasPrefix(env.Finding.Name, "organizations/") {
		t.Errorf("Name = %q, want the organization-scoped form", env.Finding.Name)
	}
}

func TestKeyCombinesCanonicalNameEventTimeAndState(t *testing.T) {
	env, _ := Parse([]byte(realEnvelope))
	key := env.Finding.Key()

	for _, want := range []string{"e5d7b4", "2026-09-19T22:05:22.735Z", "ACTIVE"} {
		if !strings.Contains(key, want) {
			t.Errorf("Key() = %q, want it to carry %q", key, want)
		}
	}
}

func TestKeyIsSafeAsAnObjectPrefix(t *testing.T) {
	env, _ := Parse([]byte(realEnvelope))
	key := env.Finding.Key()

	// Colons and slashes are legal in an object name and keep the ledger browsable. An empty
	// path segment, a leading or trailing slash, or a newline are the shapes that break it.
	for _, bad := range []string{"//", "\n", "\r", "#", "[", "]", "*", "?"} {
		if strings.Contains(key, bad) {
			t.Errorf("Key() = %q, want no %q in an object prefix", key, bad)
		}
	}
	if strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") {
		t.Errorf("Key() = %q, want no leading or trailing slash", key)
	}
}

func TestKeyRejectsAHostileCanonicalName(t *testing.T) {
	// The canonical name is a Google-assigned string, but nothing in the worker may assume that.
	f := Finding{CanonicalName: "projects/p/findings/../../escape\n", EventTime: "t", State: "ACTIVE"}
	key := f.Key()
	if strings.Contains(key, "..") || strings.Contains(key, "\n") {
		t.Errorf("Key() = %q, want traversal and newlines removed", key)
	}
}

func TestParseRejectsAFindingMissingARequiredField(t *testing.T) {
	required := []string{"canonicalName", "category", "resourceName", "state", "eventTime", "findingClass"}
	for _, field := range required {
		body := strings.Replace(realEnvelope, `"`+field+`"`, `"removed_`+field+`"`, 1)
		_, err := Parse([]byte(body))
		if err == nil {
			t.Errorf("Parse accepted a finding with no %s", field)
			continue
		}
		if !strings.Contains(err.Error(), field) {
			t.Errorf("error for missing %s is %q, and does not name the field", field, err)
		}
	}
}

func TestParseDefaultsAnAbsentSeverityRatherThanRefusing(t *testing.T) {
	body := strings.Replace(realEnvelope, `"severity"`, `"removed_severity"`, 1)
	env, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("Parse refused a finding with no severity: %v", err)
	}
	if env.Finding.Severity != "SEVERITY_UNSPECIFIED" {
		t.Errorf("Severity = %q, want SEVERITY_UNSPECIFIED", env.Finding.Severity)
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	if _, err := Parse([]byte("{not json")); err == nil {
		t.Fatal("Parse accepted malformed JSON")
	}
}

func TestDigestIgnoresKeyOrder(t *testing.T) {
	a, _ := Parse([]byte(realEnvelope))
	reordered := `{"finding":{"state":"ACTIVE","category":"MASTER_AUTHORIZED_NETWORKS_DISABLED",` +
		`"canonicalName":"projects/421458901689/sources/1405720631579532947/locations/global/findings/e5d7b4",` +
		`"name":"organizations/550178366891/sources/1405720631579532947/locations/global/findings/e5d7b4",` +
		`"parent":"organizations/550178366891/sources/1405720631579532947/locations/global",` +
		`"parentDisplayName":"Security Health Analytics",` +
		`"resourceName":"//container.googleapis.com/projects/project-69726555/locations/europe-north1-a/clusters/k8-lab",` +
		`"severity":"MEDIUM","findingClass":"MISCONFIGURATION","eventTime":"2026-09-19T22:05:22.735Z",` +
		`"createTime":"2026-09-19T22:05:24.695Z","description":"Master authorized networks is disabled on this cluster.",` +
		`"externalUri":"https://console.cloud.google.com/kubernetes/clusters","mute":"UNDEFINED",` +
		`"sourceProperties":{"Recommendation":"Enable master authorized networks."}},` +
		`"resource":{"name":"//container.googleapis.com/projects/project-69726555/locations/europe-north1-a/clusters/k8-lab"},` +
		`"notificationConfigName":"projects/p/locations/global/notificationConfigs/k8-lab-triage"}`
	b, err := Parse([]byte(reordered))
	if err != nil {
		t.Fatalf("Parse returned %v", err)
	}
	if a.Digest != b.Digest {
		t.Errorf("digest changed with key order: %q then %q", a.Digest, b.Digest)
	}
}

func TestDigestChangesWhenTheBodyChanges(t *testing.T) {
	a, _ := Parse([]byte(realEnvelope))
	changed := strings.Replace(realEnvelope, "MEDIUM", "HIGH", 1)
	b, _ := Parse([]byte(changed))
	if a.Digest == b.Digest {
		t.Error("digest did not change when the finding severity did")
	}
}

func TestIsVulnerabilityNamesTheClassPhase15DoesNotTriage(t *testing.T) {
	cases := map[string]bool{
		"VULNERABILITY":     true,
		"MISCONFIGURATION":  false,
		"THREAT":            false,
		"OBSERVATION":       false,
		"POSTURE_VIOLATION": false,
	}
	for class, want := range cases {
		if got := IsVulnerability(class); got != want {
			t.Errorf("IsVulnerability(%q) = %v, want %v", class, got, want)
		}
	}
}

func TestInScopeIsEverythingExceptVulnerability(t *testing.T) {
	// Phase 15 triages misconfiguration, external exposure and threat. Google's class for an
	// exposure finding is not recorded anywhere this worker can read, so scope is defined by
	// the one class that is out rather than by a list that could silently drop a third class.
	inScope := []string{"MISCONFIGURATION", "THREAT", "OBSERVATION", "POSTURE_VIOLATION", "SOMETHING_GOOGLE_ADDS_LATER"}
	for _, class := range inScope {
		if !InScope(class) {
			t.Errorf("InScope(%q) = false, want true", class)
		}
	}
	if InScope("VULNERABILITY") {
		t.Error("InScope(VULNERABILITY) = true; Phase 15 records the volume and does not triage it")
	}
}
