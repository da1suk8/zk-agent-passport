package passport

import (
	"errors"
	"testing"
)

func TestRebuildPolicyDetectsTampering(t *testing.T) {
	vp := ManifestVersionPolicy{Allowed: map[int][]string{0: {"a", "b"}}}
	bundle, err := NewPolicy(PolicyRequest{
		RequiredThreshold: 12, MinimumReceiptCount: 3, RequestedTaskDomain: "1001",
		RequestedManifestCommitment: "7", RequestedAggregationEpoch: "202608", ManifestVersionPolicy: vp,
	})
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := RebuildPolicy(bundle.Policy, bundle.PolicyHash, vp)
	if err != nil {
		t.Fatalf("consistent policy rejected: %v", err)
	}
	if rebuilt.Allowlist.Root != bundle.Allowlist.Root {
		t.Fatal("allowlist root differs after rebuild")
	}

	tampered := bundle.Policy
	tampered.RequiredThreshold = "1"
	if _, err := RebuildPolicy(tampered, bundle.PolicyHash, vp); !errors.Is(err, ErrPolicyInconsistent) {
		t.Fatalf("expected inconsistency for a changed threshold, got %v", err)
	}
	wider := ManifestVersionPolicy{Allowed: map[int][]string{0: {"a", "b", "c"}}}
	if _, err := RebuildPolicy(bundle.Policy, bundle.PolicyHash, wider); !errors.Is(err, ErrPolicyInconsistent) {
		t.Fatalf("expected inconsistency for a changed allowlist, got %v", err)
	}
}
