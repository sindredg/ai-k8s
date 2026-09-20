package corpus

import "testing"

const (
	theCluster = "//container.googleapis.com/projects/p/locations/europe-north1-a/clusters/k8-lab"
	theBucket  = "//storage.googleapis.com/k8-lab-verdicts-p"
)

func resolvableIndex(t *testing.T) *Index {
	t.Helper()
	idx := NewIndex()
	for _, id := range []ID{ThreatID(10), CheckovID("CKV_GCP_66", "module.gke.google_container_cluster.main"), CheckovID("CKV_GCP_62", "module.findings.google_storage_bucket.ledger")} {
		if err := idx.Add(entry(id)); err != nil {
			t.Fatalf("Add returned %v", err)
		}
	}
	idx.Mapping = map[string][]Pairing{
		"BINARY_AUTHORIZATION_DISABLED": {{
			Resource: theCluster,
			Cite:     []ID{ThreatID(10), CheckovID("CKV_GCP_66", "module.gke.google_container_cluster.main")},
			Why:      "Binary Authorization is off on this cluster and accepted.",
		}},
		"BUCKET_LOGGING_DISABLED": {{
			Resource: theBucket,
			Cite:     []ID{CheckovID("CKV_GCP_62", "module.findings.google_storage_bucket.ledger")},
			Why:      "The ledger bucket has no access logging, already in the baseline.",
		}},
		"PRIMITIVE_ROLES_USED": {},
	}
	if err := idx.Validate(); err != nil {
		t.Fatalf("Validate returned %v", err)
	}
	return idx
}

func TestResolveMatchesOnCategoryAndResourceTogether(t *testing.T) {
	idx := resolvableIndex(t)
	got := idx.Resolve("BINARY_AUTHORIZATION_DISABLED", theCluster)
	if len(got) != 2 {
		t.Fatalf("resolved %d citations, want 2", len(got))
	}
}

func TestResolveReturnsTheEntriesNotJustTheIDs(t *testing.T) {
	idx := resolvableIndex(t)
	got := idx.Resolve("BUCKET_LOGGING_DISABLED", theBucket)
	if len(got) != 1 {
		t.Fatalf("resolved %d citations, want 1", len(got))
	}
	if got[0].Summary == "" || got[0].Source == "" {
		t.Errorf("resolved entry %+v carries no summary or source", got[0])
	}
}

func TestResolveRefusesADecisionAboutAnotherResource(t *testing.T) {
	idx := resolvableIndex(t)
	// Same category, a different cluster. An accepted decision about one resource does not cover another.
	other := "//container.googleapis.com/projects/p/locations/europe-north1-a/clusters/someone-elses"
	if got := idx.Resolve("BINARY_AUTHORIZATION_DISABLED", other); len(got) != 0 {
		t.Errorf("resolved %d citations for another resource, want 0", len(got))
	}
}

func TestResolveRefusesAResourceUnderTheWrongCategory(t *testing.T) {
	idx := resolvableIndex(t)
	if got := idx.Resolve("BUCKET_LOGGING_DISABLED", theCluster); len(got) != 0 {
		t.Errorf("resolved %d citations across categories, want 0", len(got))
	}
}

func TestResolveReturnsNothingForACategoryMappedToNothing(t *testing.T) {
	idx := resolvableIndex(t)
	if got := idx.Resolve("PRIMITIVE_ROLES_USED", theCluster); len(got) != 0 {
		t.Errorf("resolved %d citations, want 0", len(got))
	}
}

func TestResolveReturnsNothingForAnUnmappedCategory(t *testing.T) {
	idx := resolvableIndex(t)
	if got := idx.Resolve("SOMETHING_NOBODY_MAPPED", theCluster); len(got) != 0 {
		t.Errorf("resolved %d citations, want 0", len(got))
	}
}

func TestResolveIsCaseSensitiveOnTheResource(t *testing.T) {
	idx := resolvableIndex(t)
	if got := idx.Resolve("BINARY_AUTHORIZATION_DISABLED", "//CONTAINER.googleapis.com/PROJECTS/p/locations/europe-north1-a/clusters/k8-lab"); len(got) != 0 {
		t.Errorf("resolved %d citations on a case-folded resource, want 0; resolution is exact", len(got))
	}
}
