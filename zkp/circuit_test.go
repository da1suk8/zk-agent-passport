package zkp

import (
	"errors"
	"testing"

	"github.com/da1suk8/zk-agent-passport/field"
)

// buildWitness produces a satisfying witness for arbitrary secrets.
func buildWitness(t *testing.T, score, threshold int64) Witness {
	t.Helper()
	rnd := func() field.Element {
		v, err := field.Random()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	must := func(v field.Element, err error) field.Element {
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	w := Witness{
		Score:        field.FromInt(score),
		ScoreSalt:    rnd(),
		AgentSecret:  rnd(),
		PassportSalt: rnd(),
	}
	p := &w.PublicInputs
	p.CertificateID = rnd()
	p.PassportCommitment = must(field.Commit(w.AgentSecret, w.PassportSalt))
	p.AgentManifestCommitment = rnd()
	p.TaskDomain = "1001"
	p.AggregationEpoch = "202608"
	p.ScoreCommitment = must(field.Commit(w.Score, w.ScoreSalt))
	p.ReceiptCount = "3"
	p.CertificateIssuedAt = "1800000000"
	p.CertificateExpiresAt = "1800000900"
	p.CommitteeKeysetID = "1"
	p.CertificateHash = must(field.Hash(
		p.CertificateID, p.PassportCommitment, p.AgentManifestCommitment, p.TaskDomain, p.AggregationEpoch,
		p.ScoreCommitment, p.ReceiptCount, p.CertificateIssuedAt, p.CertificateExpiresAt, p.CommitteeKeysetID,
	))
	p.PolicyVersion = "1"
	p.RequiredThreshold = field.FromInt(threshold)
	p.MinimumReceiptCount = "3"
	p.RequestedTaskDomain = p.TaskDomain
	p.RequestedManifestCommitment = p.AgentManifestCommitment
	p.RequestedAggregationEpoch = p.AggregationEpoch
	p.PolicyHash = must(field.Hash(
		p.PolicyVersion, p.RequiredThreshold, p.MinimumReceiptCount, p.RequestedTaskDomain,
		p.RequestedManifestCommitment, p.RequestedAggregationEpoch,
	))
	p.VerifierID = field.FromText("service")
	p.Nonce = rnd()
	p.ProofExpiresAt = "1800000300"
	return w
}

func TestProofBindsEveryPublicInput(t *testing.T) {
	sys, err := Setup()
	if err != nil {
		t.Fatal(err)
	}
	w := buildWitness(t, 14, 12)
	proof, err := sys.Prove(w)
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.Verify(proof, w.PublicInputs); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}

	tamper := map[string]func(*PublicInputs){
		"nonce":          func(p *PublicInputs) { p.Nonce = "12345" },
		"verifierId":     func(p *PublicInputs) { p.VerifierID = "999" },
		"proofExpiresAt": func(p *PublicInputs) { p.ProofExpiresAt = "1900000000" },
		"receiptCount":   func(p *PublicInputs) { p.ReceiptCount = "99" },
		"threshold":      func(p *PublicInputs) { p.RequiredThreshold = "1" },
		"manifest":       func(p *PublicInputs) { p.RequestedManifestCommitment = "7" },
	}
	for name, mutate := range tamper {
		statement := w.PublicInputs
		mutate(&statement)
		if err := sys.Verify(proof, statement); !errors.Is(err, ErrInvalidProof) {
			t.Errorf("tampering %s did not invalidate the proof: %v", name, err)
		}
	}
}

func TestCannotProveBelowThreshold(t *testing.T) {
	sys, err := Setup()
	if err != nil {
		t.Fatal(err)
	}
	w := buildWitness(t, 11, 12)
	if _, err := sys.Prove(w); err == nil {
		t.Fatal("proof for score below threshold unexpectedly succeeded")
	}
}
