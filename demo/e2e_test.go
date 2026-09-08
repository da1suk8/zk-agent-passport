package demo

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/da1suk8/zk-agent-passport/passport"
	"github.com/da1suk8/zk-agent-passport/verifier"
	"github.com/da1suk8/zk-agent-passport/zkp"
)

var sys *zkp.System

func TestMain(m *testing.M) {
	var err error
	if sys, err = zkp.Setup(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func newWorld(t *testing.T) *World {
	t.Helper()
	w, err := NewWorld(sys)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func proven(t *testing.T) (*World, passport.Challenge, *passport.ProofPackage) {
	t.Helper()
	w := newWorld(t)
	ch, err := w.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := w.Prove(ch)
	if err != nil {
		t.Fatal(err)
	}
	return w, ch, pkg
}

func TestAuthorizesValidPassportWithoutDisclosingScore(t *testing.T) {
	w, ch, pkg := proven(t)
	decision, err := w.Access(ch, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Authorized {
		t.Fatal("expected authorization")
	}
	raw, err := pkg.Proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), w.Issued.Score) {
		t.Fatal("proof bytes leak the score")
	}
	for _, v := range []string{
		pkg.Statement.CertificateHash, pkg.Statement.PolicyHash, pkg.Statement.ScoreCommitment,
	} {
		if v == w.Issued.Score {
			t.Fatal("statement leaks the score")
		}
	}
}

func TestCannotProveScoreBelowThreshold(t *testing.T) {
	w := newWorld(t)
	strict, err := w.StricterPolicy(15)
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := w.NewChallenge()
	if _, err := w.ProveWith(ch, strict, w.Issued); !errors.Is(err, passport.ErrThresholdNotMet) {
		t.Fatalf("expected threshold error, got %v", err)
	}
}

func TestGatewayRejectsForgedReceipt(t *testing.T) {
	w := newWorld(t)
	forged := w.Receipts[0]
	forged.Rating = 1
	forged.ReceiptID = "forged"
	err := w.Gateway.ValidateReceipt(forged, AggregationEpoch, Now)
	if !errors.Is(err, passport.ErrReceiptSignature) {
		t.Fatalf("expected signature error, got %v", err)
	}
}

func TestGatewayRejectsUnregisteredIssuer(t *testing.T) {
	w := newWorld(t)
	stranger, err := passport.NewIdentity("unregistered-provider")
	if err != nil {
		t.Fatal(err)
	}
	r, err := passport.IssueReceipt(stranger, w.Agent, passport.ReceiptRequest{
		ReceiptID: "unregistered-receipt", TaskDomain: TaskDomain, Rating: 5, IssuedAt: Now, ExpiresAt: Now + 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Gateway.ValidateReceipt(r, AggregationEpoch, Now); !errors.Is(err, passport.ErrIssuerNotRegistered) {
		t.Fatalf("expected registry error, got %v", err)
	}
}

func TestGatewayRejectsDuplicateReceiptAndSecondReceiptFromSameIssuer(t *testing.T) {
	w := newWorld(t)
	if err := w.Gateway.ValidateReceipt(w.Receipts[0], AggregationEpoch, Now); !errors.Is(err, passport.ErrReceiptReused) {
		t.Fatalf("expected reuse error, got %v", err)
	}
	second, err := passport.IssueReceipt(w.Issuers[0], w.Agent, passport.ReceiptRequest{
		ReceiptID: "receipt-1b", TaskDomain: TaskDomain, Rating: 5, IssuedAt: Now, ExpiresAt: Now + 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Gateway.ValidateReceipt(second, AggregationEpoch, Now); !errors.Is(err, passport.ErrIssuerAlreadyContributed) {
		t.Fatalf("expected issuer-epoch error, got %v", err)
	}
}

func TestCannotProveAgainstDifferentManifestPolicy(t *testing.T) {
	w := newWorld(t)
	mismatch, err := w.ManifestMismatchPolicy()
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := w.NewChallenge()
	if _, err := w.ProveWith(ch, mismatch, w.Issued); !errors.Is(err, passport.ErrPolicyMismatch) {
		t.Fatalf("expected policy mismatch, got %v", err)
	}
}

func TestVerifierRejectsExpiredCertificate(t *testing.T) {
	w, ch, pkg := proven(t)
	if _, err := w.AccessAt(ch, pkg, Now+901); !errors.Is(err, verifier.ErrCertificateExpired) {
		t.Fatalf("expected expiry error, got %v", err)
	}
}

func TestVerifierRejectsProofMixedWithAnotherCertificate(t *testing.T) {
	w, ch, pkg := proven(t)
	mixed := w.Issued.Certificate
	mixed.CertificateID = "777"
	// Re-sign so that only the proof binding, not the signature check, rejects it.
	hash, err := passport.CertificateHash(mixed.CertificatePayload)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := fieldBytes(hash)
	mixed.Signatures = nil
	for _, node := range w.Committee[:passport.Quorum] {
		mixed.Signatures = append(mixed.Signatures, passport.CommitteeSignature{NodeID: node.NodeID, Signature: node.Sign(msg)})
	}
	_, err = w.Verifier.VerifyAccess(verifier.AccessRequest{
		Certificate: mixed, Policy: w.Policy, Challenge: ch, Proof: pkg, Now: Now,
	})
	if !errors.Is(err, verifier.ErrInvalidProof) {
		t.Fatalf("expected invalid proof, got %v", err)
	}
}

func TestVerifierRejectsProofForAnotherChallenge(t *testing.T) {
	w, _, pkg := proven(t)
	other, err := w.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Access(other, pkg); !errors.Is(err, verifier.ErrInvalidProof) {
		t.Fatalf("expected invalid proof for a different nonce, got %v", err)
	}
}

func TestVerifierRejectsReplayedNonce(t *testing.T) {
	w, ch, pkg := proven(t)
	if _, err := w.Access(ch, pkg); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Access(ch, pkg); !errors.Is(err, verifier.ErrNonceConsumed) {
		t.Fatalf("expected consumed nonce, got %v", err)
	}
}

func TestVerifierRejectsSingleCommitteeSignature(t *testing.T) {
	w, ch, pkg := proven(t)
	single := w.Issued.Certificate
	single.Signatures = single.Signatures[:1]
	_, err := w.Verifier.VerifyAccess(verifier.AccessRequest{
		Certificate: single, Policy: w.Policy, Challenge: ch, Proof: pkg, Now: Now,
	})
	if !errors.Is(err, verifier.ErrQuorum) {
		t.Fatalf("expected quorum error, got %v", err)
	}
}
