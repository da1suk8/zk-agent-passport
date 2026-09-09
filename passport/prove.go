package passport

import (
	"errors"
	"fmt"

	"github.com/da1suk8/zk-agent-passport/field"
	"github.com/da1suk8/zk-agent-passport/zkp"
)

// Prover-side errors. They mirror what the circuit would reject, so that an
// agent gets a clear reason instead of a failed proof.
var (
	ErrThresholdNotMet = errors.New("score does not satisfy the policy threshold")
	ErrPolicyMismatch  = errors.New("certificate does not satisfy the requested policy")
)

// BuildStatement assembles the public inputs for one certificate, policy,
// and challenge. Both the prover and the verifier compute it independently.
func BuildStatement(cert ScoreCertificate, bundle PolicyBundle, ch Challenge) (zkp.PublicInputs, error) {
	hash, err := CertificateHash(cert.CertificatePayload)
	if err != nil {
		return zkp.PublicInputs{}, err
	}
	p := cert.CertificatePayload
	pol := bundle.Policy
	return zkp.PublicInputs{
		CertificateHash:         hash,
		CertificateID:           p.CertificateID,
		PassportCommitment:      p.PassportCommitment,
		AgentManifestCommitment: p.AgentManifestCommitment,
		TaskDomain:              p.TaskDomain,
		AggregationEpoch:        p.AggregationEpoch,
		ScoreCommitment:         p.ScoreCommitment,
		ReceiptCount:            p.ReceiptCount,
		CertificateIssuedAt:     p.IssuedAt,
		CertificateExpiresAt:    p.ExpiresAt,
		CommitteeKeysetID:       p.CommitteeKeysetID,

		PolicyHash:                  bundle.PolicyHash,
		PolicyVersion:               pol.PolicyVersion,
		RequiredThreshold:           pol.RequiredThreshold,
		MinimumReceiptCount:         pol.MinimumReceiptCount,
		RequestedTaskDomain:         pol.RequestedTaskDomain,
		RequestedManifestCommitment: pol.RequestedManifestCommitment,
		RequestedAggregationEpoch:   pol.RequestedAggregationEpoch,
		ManifestMutableMask:         pol.ManifestMutableMask,
		ManifestAllowlistRoot:       pol.ManifestAllowlistRoot,

		VerifierID:     ch.VerifierID,
		Nonce:          ch.Nonce,
		ProofExpiresAt: ch.ProofExpiresAt,
	}, nil
}

// ProofRequest is everything the agent needs to prove access. The agent's
// current manifest is Agent.Manifest; CertifiedManifest is the manifest the
// certificate was issued for. A zero CertifiedManifest means the
// certificate was issued for the agent's current manifest.
type ProofRequest struct {
	Agent             *Agent
	CertifiedManifest Manifest
	Issued            IssuedCertificate
	Policy            PolicyBundle
	Challenge         Challenge
}

// ProofPackage is what the agent sends to the verifier alongside the
// certificate. The statement is included for transparency; the verifier
// rebuilds it from its own inputs and never trusts this copy.
type ProofPackage struct {
	Proof     *zkp.Proof
	Statement zkp.PublicInputs
}

// Prove generates a proof that the agent's certificate satisfies the policy.
func Prove(sys *zkp.System, req ProofRequest) (*ProofPackage, error) {
	cert := req.Issued.Certificate
	pol := req.Policy.Policy
	below, err := field.Less(req.Issued.Score, pol.RequiredThreshold)
	if err != nil {
		return nil, err
	}
	if below {
		return nil, ErrThresholdNotMet
	}
	if cert.TaskDomain != pol.RequestedTaskDomain || cert.AggregationEpoch != pol.RequestedAggregationEpoch {
		return nil, fmt.Errorf("%w: domain or epoch", ErrPolicyMismatch)
	}

	// Both manifest commitments must open to manifests the agent knows.
	if req.CertifiedManifest == (Manifest{}) {
		req.CertifiedManifest = req.Agent.Manifest
	}
	certifiedCommitment, err := ManifestCommitment(req.CertifiedManifest)
	if err != nil {
		return nil, err
	}
	if certifiedCommitment != cert.AgentManifestCommitment {
		return nil, fmt.Errorf("%w: certificate was not issued for the given certified manifest", ErrPolicyMismatch)
	}
	current := req.Agent.Manifest
	if req.Agent.AgentManifestCommitment != pol.RequestedManifestCommitment {
		return nil, fmt.Errorf("%w: policy requests a manifest other than the agent's current one", ErrPolicyMismatch)
	}
	if err := req.Policy.VersionPolicy.Permits(req.CertifiedManifest, current); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPolicyMismatch, err)
	}

	statement, err := BuildStatement(cert, req.Policy, req.Challenge)
	if err != nil {
		return nil, err
	}
	w := zkp.Witness{
		PublicInputs:      statement,
		Score:             req.Issued.Score,
		ScoreSalt:         req.Issued.ScoreSalt,
		AgentSecret:       req.Agent.AgentSecret,
		PassportSalt:      req.Agent.PassportSalt,
		CertifiedManifest: ManifestFields(req.CertifiedManifest),
		CurrentManifest:   ManifestFields(current),
	}
	certifiedValues, currentValues := manifestValues(req.CertifiedManifest), manifestValues(current)
	for i := 0; i < ManifestFieldCount; i++ {
		path := EmptyPath()
		if certifiedValues[i] != currentValues[i] {
			p, ok := req.Policy.Allowlist.Path(i, currentValues[i])
			if !ok {
				return nil, fmt.Errorf("%w: %s", ErrManifestValueNotAllowed, ManifestFieldNames[i])
			}
			path = p
		}
		w.AllowlistPaths[i] = zkp.MerkleWitness{Index: field.FromInt(path.Index), Siblings: path.Siblings}
	}
	proof, err := sys.Prove(w)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return &ProofPackage{Proof: proof, Statement: statement}, nil
}
