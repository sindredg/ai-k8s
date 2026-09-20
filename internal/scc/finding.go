// Package scc parses the finding notifications Security Command Center publishes to Pub/Sub.
//
// Every string in a finding is hostile input. Resource names are chosen by whoever created the
// resource, so nothing here is treated as an instruction and nothing is interpolated unescaped.
package scc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Finding is the subset of the envelope the worker acts on. The rest of the body reaches the digest and nothing else.
type Finding struct {
	Name              string          `json:"name"`
	CanonicalName     string          `json:"canonicalName"`
	Parent            string          `json:"parent"`
	ParentDisplayName string          `json:"parentDisplayName"`
	Category          string          `json:"category"`
	ResourceName      string          `json:"resourceName"`
	State             string          `json:"state"`
	Severity          string          `json:"severity"`
	FindingClass      string          `json:"findingClass"`
	EventTime         string          `json:"eventTime"`
	CreateTime        string          `json:"createTime"`
	Description       string          `json:"description"`
	ExternalURI       string          `json:"externalUri"`
	Mute              string          `json:"mute"`
	SourceProperties  map[string]any  `json:"sourceProperties"`
	Raw               json.RawMessage `json:"-"`
}

// Envelope is one Pub/Sub message body.
type Envelope struct {
	NotificationConfigName string         `json:"notificationConfigName"`
	Finding                Finding        `json:"finding"`
	Resource               map[string]any `json:"resource"`

	// Digest fixes the finding body, so an attribute-only change is recorded as drift without a verdict.
	Digest string `json:"-"`
}

// severityUnspecified is what Security Command Center itself calls an unrated finding.
const severityUnspecified = "SEVERITY_UNSPECIFIED"

// Parse reads one message body. A missing required field is an error, which the worker records as insufficient evidence rather than guessing.
func Parse(body []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("parse finding notification: %w", err)
	}

	required := []struct{ field, value string }{
		{"canonicalName", env.Finding.CanonicalName},
		{"category", env.Finding.Category},
		{"resourceName", env.Finding.ResourceName},
		{"state", env.Finding.State},
		{"eventTime", env.Finding.EventTime},
		{"findingClass", env.Finding.FindingClass},
	}
	var missing []string
	for _, r := range required {
		if strings.TrimSpace(r.value) == "" {
			missing = append(missing, r.field)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("finding is missing required fields: %s", strings.Join(missing, ", "))
	}

	if strings.TrimSpace(env.Finding.Severity) == "" {
		env.Finding.Severity = severityUnspecified
	}

	digest, err := digestOf(body)
	if err != nil {
		return nil, err
	}
	env.Digest = digest
	return &env, nil
}

// digestOf hashes the body through a canonical re-encoding, so key order does not move the digest.
func digestOf(body []byte) (string, error) {
	var canonical any
	if err := json.Unmarshal(body, &canonical); err != nil {
		return "", fmt.Errorf("canonicalize finding: %w", err)
	}
	encoded, err := json.Marshal(canonical) // Go sorts map keys, which is the canonical form.
	if err != nil {
		return "", fmt.Errorf("canonicalize finding: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Key identifies one event on one finding: the canonical name, its event time and its state.
// A mute carries the same three, which collapses it into a redelivery rather than a second verdict.
func (f Finding) Key() string {
	return strings.Join([]string{
		pathSafe(f.CanonicalName),
		pathSafe(f.EventTime),
		pathSafe(f.State),
	}, "/")
}

// pathSafe reduces a finding string to characters an object name carries safely, keeping colons
// and single slashes so the ledger stays browsable. Traversal and empty segments are collapsed.
func pathSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.', r == ':', r == '/':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}

	out := b.String()
	for strings.Contains(out, "..") {
		out = strings.ReplaceAll(out, "..", ".")
	}
	for strings.Contains(out, "//") {
		out = strings.ReplaceAll(out, "//", "/")
	}
	return strings.Trim(out, "/_")
}

// IsVulnerability reports the one finding class Phase 15 counts and does not triage.
func IsVulnerability(class string) bool {
	return strings.EqualFold(class, "VULNERABILITY")
}

// InScope reports whether the worker triages this class. Everything except vulnerabilities is in scope,
// so a class Google adds later is triaged rather than silently dropped.
func InScope(class string) bool {
	return !IsVulnerability(class)
}
