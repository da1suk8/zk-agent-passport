package passport

import (
	"errors"
	"testing"
)

func TestGatewayReportStopsAtFirstFailure(t *testing.T) {
	issuer, err := NewIdentity("provider-a")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := NewAgent(Manifest{ModelID: "m", SystemPromptHash: "p", ToolPolicyHash: "t", PermissionScope: "s"})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := IssueReceipt(issuer, agent, ReceiptRequest{ReceiptID: "r1", TaskDomain: "1001", Rating: 5, IssuedAt: 100, ExpiresAt: 200})
	if err != nil {
		t.Fatal(err)
	}
	gateway := NewInputGateway(NewIssuerRegistry(issuer))

	forged := receipt
	forged.Rating = 1
	_, checks, err := gateway.ValidateReceiptReport(forged, "202608", 150)
	if !errors.Is(err, ErrReceiptSignature) {
		t.Fatalf("expected signature failure, got %v", err)
	}
	want := []CheckStatus{CheckOK, CheckFailed, CheckSkipped, CheckSkipped, CheckSkipped, CheckSkipped}
	if len(checks) != len(GatewayChecks) {
		t.Fatalf("expected %d checks, got %d", len(GatewayChecks), len(checks))
	}
	for i, c := range checks {
		if c.Key != GatewayChecks[i] || c.Status != want[i] {
			t.Fatalf("check %d = %s %s, want %s %s", i, c.Key, c.Status, GatewayChecks[i], want[i])
		}
	}

	// A failed receipt leaves no state: the genuine one is still accepted.
	if _, checks, err := gateway.ValidateReceiptReport(receipt, "202608", 150); err != nil {
		t.Fatalf("genuine receipt rejected: %v", err)
	} else {
		for _, c := range checks {
			if c.Status != CheckOK {
				t.Fatalf("expected all ok, got %s %s", c.Key, c.Status)
			}
		}
	}
}
