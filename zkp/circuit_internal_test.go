package zkp

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"

	"github.com/da1suk8/zk-agent-passport/field"
)

// signedWitness builds a witness with a real committee keyset and quorum of
// EdDSA signatures over the certificate hash. The manifest is unchanged, so
// the allowlist paths are empty.
func signedWitness(t *testing.T, signers [Quorum]int) Witness {
	t.Helper()
	must := func(v field.Element, err error) field.Element {
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	rnd := func() field.Element { return must(field.Random()) }

	var keys [CommitteeSize]*eddsa.PrivateKey
	var w Witness
	for i := range keys {
		k, err := eddsa.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = k
		w.CommitteeKeys[i] = k.PublicKey.Bytes()
	}
	w.CommitteeKeysetID = "1"

	w.Score, w.ScoreSalt, w.AgentSecret, w.PassportSalt = "14", rnd(), rnd(), rnd()
	w.CertificateID = rnd()
	w.PassportCommitment = must(field.Commit(w.AgentSecret, w.PassportSalt))
	manifest := [ManifestFieldCount]field.Element{field.FromText("m"), field.FromText("p"), field.FromText("t"), field.FromText("s")}
	w.CertifiedManifest, w.CurrentManifest = manifest, manifest
	w.AgentManifestCommitment = must(field.Hash(manifest[:]...))
	w.TaskDomain, w.AggregationEpoch = "1001", "202608"
	w.ScoreCommitment = must(field.Commit(w.Score, w.ScoreSalt))
	w.ReceiptCount = "3"
	w.CertificateIssuedAt, w.CertificateExpiresAt = "1800000000", "1800000900"
	for i := range w.AllowlistPaths {
		w.AllowlistPaths[i].Index = "0"
		for k := range w.AllowlistPaths[i].Siblings {
			w.AllowlistPaths[i].Siblings[k] = "0"
		}
	}

	certificateHash := must(field.Hash(
		w.CertificateID, w.PassportCommitment, w.AgentManifestCommitment, w.TaskDomain, w.AggregationEpoch,
		w.ScoreCommitment, w.ReceiptCount, w.CertificateIssuedAt, w.CertificateExpiresAt, w.CommitteeKeysetID,
	))
	msg, err := field.Bytes(certificateHash)
	if err != nil {
		t.Fatal(err)
	}
	for i, idx := range signers {
		sig, err := keys[idx].Sign(msg, mimc.NewMiMC())
		if err != nil {
			t.Fatal(err)
		}
		w.Signatures[i] = sig
		w.SignerIndex[i] = idx
	}

	p := &w.PublicInputs
	p.PolicyVersion, p.RequiredThreshold, p.MinimumReceiptCount = "2", "12", "3"
	p.RequestedTaskDomain, p.RequestedManifestCommitment, p.RequestedAggregationEpoch = w.TaskDomain, w.AgentManifestCommitment, w.AggregationEpoch
	p.ManifestMutableMask, p.ManifestAllowlistRoot = "0", "5"
	p.PolicyHash = must(field.Hash(p.PolicyVersion, p.RequiredThreshold, p.MinimumReceiptCount, p.RequestedTaskDomain,
		p.RequestedManifestCommitment, p.RequestedAggregationEpoch, p.ManifestMutableMask, p.ManifestAllowlistRoot))
	p.VerifierID = field.FromText("service")
	p.Nonce = rnd()
	p.ProofExpiresAt = "1800000300"
	p.Nullifier = must(field.Hash(w.AgentSecret, p.VerifierID))
	return w
}

func TestCircuitProvesWithCommitteeQuorum(t *testing.T) {
	start := time.Now()
	sys, err := Setup()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("constraints=%d public=%d setup=%s", sys.NbConstraints(), sys.NbPublicInputs(), time.Since(start))

	w := signedWitness(t, [Quorum]int{0, 2})
	start = time.Now()
	proof, err := sys.Prove(w)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("prove=%s", time.Since(start))
	if err := sys.Verify(proof, w.PublicInputs); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}

	tamper := map[string]func(*PublicInputs){
		"nullifier":  func(p *PublicInputs) { p.Nullifier = "1" },
		"nonce":      func(p *PublicInputs) { p.Nonce = "12345" },
		"verifierId": func(p *PublicInputs) { p.VerifierID = "999" },
		"expiry":     func(p *PublicInputs) { p.ProofExpiresAt = "1800000901" },
		"keyset":     func(p *PublicInputs) { p.CommitteeKeys[0], p.CommitteeKeys[1] = p.CommitteeKeys[1], p.CommitteeKeys[0] },
		"threshold":  func(p *PublicInputs) { p.RequiredThreshold = "1" },
	}
	for name, mutate := range tamper {
		statement := w.PublicInputs
		mutate(&statement)
		if err := sys.Verify(proof, statement); !errors.Is(err, ErrInvalidProof) {
			t.Errorf("tampering %s did not invalidate the proof: %v", name, err)
		}
	}

	// Same node twice is not a quorum.
	dup := signedWitness(t, [Quorum]int{1, 1})
	if _, err := sys.Prove(dup); err == nil {
		t.Fatal("duplicate signer unexpectedly proved")
	}
	// A proof that outlives its certificate is rejected.
	late := signedWitness(t, [Quorum]int{0, 1})
	late.ProofExpiresAt = "1800001000"
	if _, err := sys.Prove(late); err == nil {
		t.Fatal("proof outliving the certificate unexpectedly proved")
	}
}
