package passport

import (
	"errors"
	"fmt"
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

func TestCommitteeRefusesToAggregateTheSameBatchTwice(t *testing.T) {
	issuers := make([]*Identity, 2)
	for i := range issuers {
		id, err := NewIdentity(fmt.Sprintf("provider-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		issuers[i] = id
	}
	agent, err := NewAgent(Manifest{ModelID: "m", SystemPromptHash: "p", ToolPolicyHash: "t", PermissionScope: "s"})
	if err != nil {
		t.Fatal(err)
	}
	gateway := NewInputGateway(NewIssuerRegistry(issuers...))
	validated := make([]ValidatedReceipt, len(issuers))
	for i, issuer := range issuers {
		r, err := IssueReceipt(issuer, agent, ReceiptRequest{
			ReceiptID: fmt.Sprintf("r%d", i), TaskDomain: "1001", Rating: 5, IssuedAt: 100, ExpiresAt: 200,
		})
		if err != nil {
			t.Fatal(err)
		}
		if validated[i], err = gateway.ValidateReceipt(r, "202608", 150); err != nil {
			t.Fatal(err)
		}
	}
	var committee []*CommitteeNode
	for _, name := range []string{"c1", "c2", "c3"} {
		node, err := NewCommitteeNode(name)
		if err != nil {
			t.Fatal(err)
		}
		committee = append(committee, node)
	}
	first, err := IssueScoreCertificate(committee, AggregationRequest{
		Receipts: validated[:1], AggregationEpoch: "202608", IssuedAt: 150, ExpiresAt: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Score != "5" {
		t.Fatalf("expected the first certificate to total 5, got %s", first.Score)
	}
	// The second receipt belongs to the same batch. Aggregating it on top of
	// the committee's running totals would report score=10 next to
	// receiptCount=1, so the committee refuses instead.
	if _, err := IssueScoreCertificate(committee, AggregationRequest{
		Receipts: validated[1:], AggregationEpoch: "202608", IssuedAt: 150, ExpiresAt: 300,
	}); !errors.Is(err, ErrBatchAlreadyIssued) {
		t.Fatalf("expected a second aggregation of the same batch to be refused, got %v", err)
	}
}
