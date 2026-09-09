package passport

import (
	"errors"
	"testing"
)

func TestCommitteeRejectsReceiptValidatedForAnotherEpoch(t *testing.T) {
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
	validated, err := gateway.ValidateReceipt(receipt, "202608", 150)
	if err != nil {
		t.Fatal(err)
	}
	var committee []*CommitteeNode
	for _, name := range []string{"c1", "c2", "c3"} {
		node, err := NewCommitteeNode(name)
		if err != nil {
			t.Fatal(err)
		}
		committee = append(committee, node)
	}
	_, err = IssueScoreCertificate(committee, AggregationRequest{
		Receipts: []ValidatedReceipt{validated}, AggregationEpoch: "202609", IssuedAt: 150, ExpiresAt: 300,
	})
	if !errors.Is(err, ErrBatchMismatch) {
		t.Fatalf("expected batch mismatch for a different epoch, got %v", err)
	}
	if _, err := IssueScoreCertificate(committee, AggregationRequest{
		Receipts: []ValidatedReceipt{validated}, AggregationEpoch: "202608", IssuedAt: 150, ExpiresAt: 300,
	}); err != nil {
		t.Fatalf("expected issuance for the validated epoch: %v", err)
	}
}
