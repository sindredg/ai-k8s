package corpus

import "testing"

func TestCheckovIDJoinsCheckAndAddress(t *testing.T) {
	got := CheckovID("CKV_GCP_20", "module.gke.google_container_cluster.main")
	want := ID("checkov:CKV_GCP_20:module.gke.google_container_cluster.main")
	if got != want {
		t.Errorf("CheckovID = %q, want %q", got, want)
	}
}

func TestThreatIDUsesTheFindingNumber(t *testing.T) {
	if got := ThreatID(10); got != ID("threat:10") {
		t.Errorf("ThreatID = %q, want %q", got, "threat:10")
	}
}

func TestDecisionIDUsesTheAnchor(t *testing.T) {
	if got := DecisionID("agent-permission-boundary"); got != ID("decision:agent-permission-boundary") {
		t.Errorf("DecisionID = %q, want %q", got, "decision:agent-permission-boundary")
	}
}

func TestControlIDUsesTheSlug(t *testing.T) {
	if got := ControlID("pod-security-restricted"); got != ID("control:pod-security-restricted") {
		t.Errorf("ControlID = %q, want %q", got, "control:pod-security-restricted")
	}
}

func TestParseIDAcceptsEachKind(t *testing.T) {
	cases := map[ID]Kind{
		"checkov:CKV_GCP_20:module.gke.google_container_cluster.main": KindCheckov,
		"threat:10":                          KindThreat,
		"decision:agent-permission-boundary": KindDecision,
		"control:pod-security-restricted":    KindControl,
	}
	for id, want := range cases {
		got, err := ParseID(id)
		if err != nil {
			t.Errorf("ParseID(%q) returned error %v", id, err)
			continue
		}
		if got != want {
			t.Errorf("ParseID(%q) kind = %q, want %q", id, got, want)
		}
	}
}

func TestParseIDRejectsMalformedIDs(t *testing.T) {
	bad := []ID{
		"",
		"checkov",
		"checkov:CKV_GCP_20",
		"checkov::module.gke.main",
		"checkov:CKV_GCP_20:",
		"threat:",
		"threat:ten",
		"threat:0",
		"threat:10:extra",
		"decision:",
		"control:",
		"cve:CVE-2026-1234",
		"CHECKOV:CKV_GCP_20:module.gke.main",
	}
	for _, id := range bad {
		if _, err := ParseID(id); err == nil {
			t.Errorf("ParseID(%q) accepted a malformed id", id)
		}
	}
}
