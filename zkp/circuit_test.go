package zkp_test

import (
	"errors"
	"testing"

	"github.com/da1suk8/zk-agent-passport/field"
	"github.com/da1suk8/zk-agent-passport/passport"
	"github.com/da1suk8/zk-agent-passport/zkp"
)

var (
	certifiedManifest = passport.Manifest{ModelID: "gpt-demo", SystemPromptHash: "prompt-v1", ToolPolicyHash: "tools-v1", PermissionScope: "travel"}
	permissivePolicy  = passport.ManifestVersionPolicy{Allowed: map[int][]string{0: {"gpt-demo-v2"}, 1: {"prompt-v2"}}}
)

type scenario struct {
	score, threshold  int64
	receipts, minimum int64
	certified         passport.Manifest
	current           passport.Manifest
	policy            passport.ManifestVersionPolicy
}

// buildWitness produces a witness for a scenario, computing the allowlist
// paths the way the prover does.
func buildWitness(t *testing.T, sc scenario) zkp.Witness {
	t.Helper()
	must := func(v field.Element, err error) field.Element {
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	rnd := func() field.Element { return must(field.Random()) }

	if sc.receipts == 0 {
		sc.receipts = 3
	}
	if sc.minimum == 0 {
		sc.minimum = 3
	}
	w := zkp.Witness{
		Score:             field.FromInt(sc.score),
		ScoreSalt:         rnd(),
		AgentSecret:       rnd(),
		PassportSalt:      rnd(),
		ReceiptCount:      field.FromInt(sc.receipts),
		CertifiedManifest: passport.ManifestFields(sc.certified),
		CurrentManifest:   passport.ManifestFields(sc.current),
	}
	allowlist, err := passport.BuildManifestAllowlist(sc.policy)
	if err != nil {
		t.Fatal(err)
	}
	certifiedValues := []string{sc.certified.ModelID, sc.certified.SystemPromptHash, sc.certified.ToolPolicyHash, sc.certified.PermissionScope}
	currentValues := []string{sc.current.ModelID, sc.current.SystemPromptHash, sc.current.ToolPolicyHash, sc.current.PermissionScope}
	for i := 0; i < zkp.ManifestFieldCount; i++ {
		path := passport.EmptyPath()
		if certifiedValues[i] != currentValues[i] {
			if p, ok := allowlist.Path(i, currentValues[i]); ok {
				path = p
			}
		}
		w.AllowlistPaths[i] = zkp.MerkleWitness{Index: field.FromInt(path.Index), Siblings: path.Siblings}
	}

	p := &w.PublicInputs
	p.CertificateID = rnd()
	p.PassportCommitment = must(field.Commit(w.AgentSecret, w.PassportSalt))
	p.AgentManifestCommitment = must(passport.ManifestCommitment(sc.certified))
	p.TaskDomain = "1001"
	p.AggregationEpoch = "202608"
	p.ScoreCommitment = must(field.Commit(w.Score, w.ScoreSalt))
	p.CertificateIssuedAt = "1800000000"
	p.CertificateExpiresAt = "1800000900"
	p.CommitteeKeysetID = "1"
	p.CertificateHash = must(field.Hash(
		p.CertificateID, p.PassportCommitment, p.AgentManifestCommitment, p.TaskDomain, p.AggregationEpoch,
		p.ScoreCommitment, w.ReceiptCount, p.CertificateIssuedAt, p.CertificateExpiresAt, p.CommitteeKeysetID,
	))
	policy := passport.Policy{
		PolicyVersion:               "2",
		RequiredThreshold:           field.FromInt(sc.threshold),
		MinimumReceiptCount:         field.FromInt(sc.minimum),
		RequestedTaskDomain:         p.TaskDomain,
		RequestedManifestCommitment: must(passport.ManifestCommitment(sc.current)),
		RequestedAggregationEpoch:   p.AggregationEpoch,
		ManifestMutableMask:         field.FromInt(sc.policy.Mask()),
		ManifestAllowlistRoot:       allowlist.Root,
	}
	p.PolicyVersion = policy.PolicyVersion
	p.RequiredThreshold = policy.RequiredThreshold
	p.MinimumReceiptCount = policy.MinimumReceiptCount
	p.RequestedTaskDomain = policy.RequestedTaskDomain
	p.RequestedManifestCommitment = policy.RequestedManifestCommitment
	p.RequestedAggregationEpoch = policy.RequestedAggregationEpoch
	p.ManifestMutableMask = policy.ManifestMutableMask
	p.ManifestAllowlistRoot = policy.ManifestAllowlistRoot
	p.PolicyHash = must(passport.PolicyHash(policy))
	p.VerifierID = field.FromText("service")
	p.Nonce = rnd()
	p.ProofExpiresAt = "1800000300"
	return w
}

var sys *zkp.System

func system(t *testing.T) *zkp.System {
	t.Helper()
	if sys == nil {
		var err error
		if sys, err = zkp.Setup(); err != nil {
			t.Fatal(err)
		}
	}
	return sys
}

func TestProofBindsEveryPublicInput(t *testing.T) {
	s := system(t)
	w := buildWitness(t, scenario{score: 14, threshold: 12, certified: certifiedManifest, current: certifiedManifest, policy: permissivePolicy})
	proof, err := s.Prove(w)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(proof, w.PublicInputs); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}

	tamper := map[string]func(*zkp.PublicInputs){
		"nonce":           func(p *zkp.PublicInputs) { p.Nonce = "12345" },
		"verifierId":      func(p *zkp.PublicInputs) { p.VerifierID = "999" },
		"proofExpiresAt":  func(p *zkp.PublicInputs) { p.ProofExpiresAt = "1900000000" },
		"minimumReceipts": func(p *zkp.PublicInputs) { p.MinimumReceiptCount = "1" },
		"threshold":       func(p *zkp.PublicInputs) { p.RequiredThreshold = "1" },
		"manifest":        func(p *zkp.PublicInputs) { p.RequestedManifestCommitment = "7" },
		"mutableMask":     func(p *zkp.PublicInputs) { p.ManifestMutableMask = "15" },
		"allowlistRoot":   func(p *zkp.PublicInputs) { p.ManifestAllowlistRoot = "8" },
	}
	for name, mutate := range tamper {
		statement := w.PublicInputs
		mutate(&statement)
		if err := s.Verify(proof, statement); !errors.Is(err, zkp.ErrInvalidProof) {
			t.Errorf("tampering %s did not invalidate the proof: %v", name, err)
		}
	}
}

func TestCannotProveBelowThreshold(t *testing.T) {
	s := system(t)
	w := buildWitness(t, scenario{score: 11, threshold: 12, certified: certifiedManifest, current: certifiedManifest, policy: permissivePolicy})
	if _, err := s.Prove(w); err == nil {
		t.Fatal("proof for score below threshold unexpectedly succeeded")
	}
}

func TestCannotProveWithTooFewReceipts(t *testing.T) {
	s := system(t)
	w := buildWitness(t, scenario{score: 14, threshold: 12, receipts: 2, minimum: 3, certified: certifiedManifest, current: certifiedManifest, policy: permissivePolicy})
	if _, err := s.Prove(w); err == nil {
		t.Fatal("proof with too few receipts unexpectedly succeeded")
	}
}

func TestManifestVersionPolicy(t *testing.T) {
	s := system(t)
	updatedModel := certifiedManifest
	updatedModel.ModelID = "gpt-demo-v2"
	unlistedModel := certifiedManifest
	unlistedModel.ModelID = "gpt-demo-v3"
	widerScope := certifiedManifest
	widerScope.PermissionScope = "travel-admin"
	twoChanges := updatedModel
	twoChanges.SystemPromptHash = "prompt-v2"

	cases := []struct {
		name    string
		current passport.Manifest
		policy  passport.ManifestVersionPolicy
		proves  bool
	}{
		{"unchanged under strict policy", certifiedManifest, passport.StrictManifestPolicy(), true},
		{"permitted model update", updatedModel, permissivePolicy, true},
		{"two permitted updates", twoChanges, permissivePolicy, true},
		{"model update under strict policy", updatedModel, passport.StrictManifestPolicy(), false},
		{"model value outside allowlist", unlistedModel, permissivePolicy, false},
		{"immutable permission scope changed", widerScope, permissivePolicy, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := buildWitness(t, scenario{score: 14, threshold: 12, certified: certifiedManifest, current: tc.current, policy: tc.policy})
			proof, err := s.Prove(w)
			if tc.proves {
				if err != nil {
					t.Fatalf("expected a proof: %v", err)
				}
				if err := s.Verify(proof, w.PublicInputs); err != nil {
					t.Fatalf("valid proof rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected proving to fail")
			}
		})
	}
}
