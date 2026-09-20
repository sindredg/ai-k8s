package corpus

import (
	"strings"
	"testing"
)

func TestLoadCheckovIDsOneEntryPerCheckAndResource(t *testing.T) {
	idx := NewIndex()
	if err := LoadCheckov(idx, "testdata/checkov.baseline"); err != nil {
		t.Fatalf("LoadCheckov returned %v", err)
	}

	want := []ID{
		"checkov:CKV_K8S_40:Deployment.demo.nginx",
		"checkov:CKV_GCP_20:module.gke.google_container_cluster.main",
		"checkov:CKV_GCP_66:module.gke.google_container_cluster.main",
	}
	if len(idx.Entries) != len(want) {
		t.Errorf("loaded %d entries, want %d", len(idx.Entries), len(want))
	}
	for _, id := range want {
		if _, ok := idx.Lookup(id); !ok {
			t.Errorf("entry %q is missing", id)
		}
	}
}

func TestLoadCheckovRecordsTheFileAsTheSource(t *testing.T) {
	idx := NewIndex()
	if err := LoadCheckov(idx, "testdata/checkov.baseline"); err != nil {
		t.Fatalf("LoadCheckov returned %v", err)
	}
	e, ok := idx.Lookup("checkov:CKV_K8S_40:Deployment.demo.nginx")
	if !ok {
		t.Fatal("entry is missing")
	}
	if !strings.Contains(e.Source, "/kubernetes/nginx/deployment.yml") {
		t.Errorf("Source = %q, want the file the check failed against", e.Source)
	}
	if !strings.Contains(e.Summary, "CKV_K8S_40") {
		t.Errorf("Summary = %q, want the check named", e.Summary)
	}
}

func TestLoadCheckovRejectsAFindingWithNoCheckIDs(t *testing.T) {
	if err := LoadCheckov(NewIndex(), "testdata/checkov-no-check-ids.baseline"); err == nil {
		t.Fatal("LoadCheckov accepted a finding carrying no check ids")
	}
}

func TestLoadCheckovRejectsAFindingWithNoResource(t *testing.T) {
	if err := LoadCheckov(NewIndex(), "testdata/checkov-no-resource.baseline"); err == nil {
		t.Fatal("LoadCheckov accepted a finding naming no resource")
	}
}

func TestLoadCheckovReportsAMissingFile(t *testing.T) {
	if err := LoadCheckov(NewIndex(), "testdata/there-is-no-such-baseline"); err == nil {
		t.Fatal("LoadCheckov accepted a path that does not exist")
	}
}
