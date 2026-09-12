package demo

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/da1suk8/zk-agent-passport/field"
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
	for _, v := range []string{pkg.Statement.PolicyHash, pkg.Statement.Nullifier} {
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
	_, err := w.Gateway.ValidateReceipt(forged, AggregationEpoch, Now)
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
	if _, err := w.Gateway.ValidateReceipt(r, AggregationEpoch, Now); !errors.Is(err, passport.ErrIssuerNotRegistered) {
		t.Fatalf("expected registry error, got %v", err)
	}
}

func TestGatewayRejectsDuplicateReceiptAndSecondReceiptFromSameIssuer(t *testing.T) {
	w := newWorld(t)
	if _, err := w.Gateway.ValidateReceipt(w.Receipts[0], AggregationEpoch, Now); !errors.Is(err, passport.ErrReceiptReused) {
		t.Fatalf("expected reuse error, got %v", err)
	}
	second, err := passport.IssueReceipt(w.Issuers[0], w.Agent, passport.ReceiptRequest{
		ReceiptID: "receipt-1b", TaskDomain: TaskDomain, Rating: 5, IssuedAt: Now, ExpiresAt: Now + 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Gateway.ValidateReceipt(second, AggregationEpoch, Now); !errors.Is(err, passport.ErrIssuerAlreadyContributed) {
		t.Fatalf("expected issuer-epoch error, got %v", err)
	}
}

func withManifest(t *testing.T, mutate func(*passport.Manifest), policy *passport.ManifestVersionPolicy) *World {
	t.Helper()
	opts := DefaultOptions()
	current := opts.Manifest
	mutate(&current)
	opts.CurrentManifest = &current
	opts.VersionPolicy = policy
	w, err := NewWorldWith(sys, opts)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestProvesAfterPermittedManifestUpdate(t *testing.T) {
	w := withManifest(t, func(m *passport.Manifest) { m.ModelID = "gpt-demo-v2" }, nil)
	ch, _ := w.NewChallenge()
	pkg, err := w.Prove(ch)
	if err != nil {
		t.Fatalf("permitted update should prove: %v", err)
	}
	decision, err := w.Access(ch, pkg)
	if err != nil || !decision.Authorized {
		t.Fatalf("permitted update should authorize: %v", err)
	}
	if w.Issued.Certificate.AgentManifestCommitment == w.Policy.Policy.RequestedManifestCommitment {
		t.Fatal("test setup: manifests should differ")
	}
}

func TestCannotProveWhenImmutableFieldChanges(t *testing.T) {
	w := withManifest(t, func(m *passport.Manifest) { m.PermissionScope = "travel-booking-admin" }, nil)
	ch, _ := w.NewChallenge()
	if _, err := w.Prove(ch); !errors.Is(err, passport.ErrManifestFieldImmutable) {
		t.Fatalf("expected immutable-field error, got %v", err)
	}
}

func TestCannotProveWhenNewValueNotAllowlisted(t *testing.T) {
	w := withManifest(t, func(m *passport.Manifest) { m.ModelID = "gpt-demo-v3" }, nil)
	ch, _ := w.NewChallenge()
	if _, err := w.Prove(ch); !errors.Is(err, passport.ErrManifestValueNotAllowed) {
		t.Fatalf("expected allowlist error, got %v", err)
	}
}

func TestStrictPolicyRejectsAnyManifestChange(t *testing.T) {
	strict := passport.StrictManifestPolicy()
	w := withManifest(t, func(m *passport.Manifest) { m.ModelID = "gpt-demo-v2" }, &strict)
	ch, _ := w.NewChallenge()
	if _, err := w.Prove(ch); !errors.Is(err, passport.ErrManifestFieldImmutable) {
		t.Fatalf("expected immutable-field error, got %v", err)
	}
}

func TestCannotProveAgainstForeignManifestPolicy(t *testing.T) {
	w := newWorld(t)
	foreign, err := w.ForeignManifestPolicy()
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := w.NewChallenge()
	if _, err := w.ProveWith(ch, foreign, w.Issued); !errors.Is(err, passport.ErrPolicyMismatch) {
		t.Fatalf("expected policy mismatch, got %v", err)
	}
}

func TestVerifierRejectsExpiredProof(t *testing.T) {
	w, ch, pkg := proven(t)
	if _, err := w.AccessAt(ch, pkg, Now+301); !errors.Is(err, verifier.ErrProofExpired) {
		t.Fatalf("expected proof expiry error, got %v", err)
	}
}

func TestVerifierRejectsTamperedNullifier(t *testing.T) {
	w, ch, pkg := proven(t)
	tampered := *pkg
	tampered.Statement.Nullifier = "7"
	if _, err := w.Access(ch, &tampered); !errors.Is(err, verifier.ErrInvalidProof) {
		t.Fatalf("expected invalid proof for a tampered nullifier, got %v", err)
	}
}

func TestCannotProveWithSingleCommitteeSignature(t *testing.T) {
	w := newWorld(t)
	single := w.Issued
	single.Certificate.Signatures = single.Certificate.Signatures[:1]
	ch, _ := w.NewChallenge()
	if _, err := w.ProveWith(ch, w.Policy, single); !errors.Is(err, passport.ErrInsufficientQuorum) {
		t.Fatalf("expected quorum error, got %v", err)
	}
}

func TestCannotProveWithSignatureFromOutsideTheKeyset(t *testing.T) {
	w := newWorld(t)
	outsider, err := passport.NewCommitteeNode("committee-x")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := passport.CertificateHash(w.Issued.Certificate.CertificatePayload)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := outsider.Sign(hash)
	if err != nil {
		t.Fatal(err)
	}
	forged := w.Issued
	forged.Certificate.Signatures = []passport.CommitteeSignature{
		forged.Certificate.Signatures[0],
		{NodeID: "committee-x", Signature: sig},
	}
	ch, _ := w.NewChallenge()
	if _, err := w.ProveWith(ch, w.Policy, forged); !errors.Is(err, passport.ErrInsufficientQuorum) {
		t.Fatalf("expected quorum error for an outsider signature, got %v", err)
	}
}

func TestCannotProveBeyondCertificateExpiry(t *testing.T) {
	w := newWorld(t)
	late := passport.Challenge{VerifierID: field.FromText(VerifierName), Nonce: "5", ProofExpiresAt: field.FromInt(Now + 901)}
	if _, err := w.Prove(late); !errors.Is(err, passport.ErrCertificateExpired) {
		t.Fatalf("expected certificate expiry error, got %v", err)
	}
}

func TestTwoServicesCannotLinkTheSameAgent(t *testing.T) {
	w, chA, pkgA := proven(t)
	if _, err := w.Access(chA, pkgA); err != nil {
		t.Fatal(err)
	}
	other := verifier.New(sys, w.Keyset, "travel-insurance-service")
	chB, err := other.IssueChallenge(Now, w.Policy.PolicyHash)
	if err != nil {
		t.Fatal(err)
	}
	pkgB, err := w.Prove(chB)
	if err != nil {
		t.Fatal(err)
	}
	decisionB, err := other.VerifyAccess(verifier.AccessRequest{Policy: w.Policy, Challenge: chB, Proof: pkgB, Now: Now})
	if err != nil || !decisionB.Authorized {
		t.Fatalf("second service should authorize: %v", err)
	}
	if pkgA.Statement.Nullifier == pkgB.Statement.Nullifier {
		t.Fatal("nullifiers should differ across services")
	}
	// Nothing agent-specific other than the nullifier is public. (The score
	// itself is too short to search for; its commitment stands in for it.)
	rawA, _ := json.Marshal(pkgA.Statement)
	for _, secret := range []string{
		w.Issued.Certificate.PassportCommitment, w.Issued.Certificate.CertificateID,
		w.Issued.Certificate.ScoreCommitment, w.Agent.AgentSecret, w.Issued.ScoreSalt,
	} {
		if strings.Contains(string(rawA), secret) {
			t.Fatalf("statement exposes %s…", secret[:8])
		}
	}
	// The same service sees the same nullifier again.
	chA2, _ := w.NewChallenge()
	pkgA2, err := w.Prove(chA2)
	if err != nil {
		t.Fatal(err)
	}
	if pkgA2.Statement.Nullifier != pkgA.Statement.Nullifier {
		t.Fatal("nullifier should be stable for one service")
	}
}

func TestTwoPermittedManifestUpdates(t *testing.T) {
	w := withManifest(t, func(m *passport.Manifest) { m.ModelID = "gpt-demo-v2"; m.SystemPromptHash = "travel-booking-v2" }, nil)
	ch, _ := w.NewChallenge()
	pkg, err := w.Prove(ch)
	if err != nil {
		t.Fatalf("two permitted updates should prove: %v", err)
	}
	if _, err := w.Access(ch, pkg); err != nil {
		t.Fatalf("two permitted updates should authorize: %v", err)
	}
}

func TestCannotProveWithTooFewReceipts(t *testing.T) {
	opts := DefaultOptions()
	opts.MinimumReceiptCount = 4
	w, err := NewWorldWith(sys, opts)
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := w.NewChallenge()
	if _, err := w.Prove(ch); !errors.Is(err, passport.ErrReceiptCountNotMet) {
		t.Fatalf("expected receipt count error, got %v", err)
	}
}

func TestCannotProveWithSomeoneElsesSecret(t *testing.T) {
	w := newWorld(t)
	impostor, err := passport.NewAgent(w.Agent.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := w.NewChallenge()
	_, err = passport.Prove(sys, passport.ProofRequest{
		Agent: impostor, CertifiedManifest: w.CertifiedManifest, Issued: w.Issued, Policy: w.Policy, Challenge: ch,
	})
	if !errors.Is(err, passport.ErrNotPassportHolder) {
		t.Fatalf("expected not-holder error, got %v", err)
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

func TestVerifierRejectsChallengeItDidNotIssue(t *testing.T) {
	w := newWorld(t)
	forged, err := passport.NewChallenge(VerifierName, Now, passport.DefaultChallengeTTL)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := w.Prove(forged)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := w.Access(forged, pkg)
	if !errors.Is(err, verifier.ErrUnknownNonce) {
		t.Fatalf("expected unknown nonce, got %v", err)
	}
	if len(decision.Checks) != len(verifier.Checks) {
		t.Fatalf("expected %d reported checks, got %d", len(verifier.Checks), len(decision.Checks))
	}
}

func TestVerifierReportsEveryCheck(t *testing.T) {
	w, ch, pkg := proven(t)
	decision, err := w.Access(ch, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.Checks) != len(verifier.Checks) {
		t.Fatalf("expected %d checks, got %d", len(verifier.Checks), len(decision.Checks))
	}
	for i, c := range decision.Checks {
		if c.Key != verifier.Checks[i] || c.Status != verifier.CheckOK {
			t.Fatalf("check %d = %+v, want %s ok", i, c, verifier.Checks[i])
		}
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

func TestVerifierRejectsProofBuiltForAnotherPolicy(t *testing.T) {
	w := newWorld(t)
	// A policy the agent can satisfy, but not the one the service challenged
	// for: the threshold is lower than the world's.
	looser, err := w.StricterPolicy(RequiredThreshold - 2)
	if err != nil {
		t.Fatal(err)
	}
	if looser.PolicyHash == w.Policy.PolicyHash {
		t.Fatal("test setup: the two policies should differ")
	}
	ch, err := w.NewChallenge() // issued for w.Policy
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := w.ProveWith(ch, looser, w.Issued)
	if err != nil {
		t.Fatalf("the agent should be able to prove the looser policy: %v", err)
	}
	if _, err := w.Verifier.VerifyAccess(verifier.AccessRequest{
		Policy: looser, Challenge: ch, Proof: pkg, Now: Now,
	}); !errors.Is(err, verifier.ErrPolicyNotChallenged) {
		t.Fatalf("expected the nonce to be bound to the challenged policy, got %v", err)
	}
}
