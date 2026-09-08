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

		VerifierID:     ch.VerifierID,
		Nonce:          ch.Nonce,
		ProofExpiresAt: ch.ProofExpiresAt,
	}, nil
}

// ProofRequest is everything the agent needs to prove access.
type ProofRequest struct {
	Agent     *Agent
	Issued    IssuedCertificate
	Policy    PolicyBundle
	Challenge Challenge
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
	if cert.AgentManifestCommitment != pol.RequestedManifestCommitment ||
		cert.TaskDomain != pol.RequestedTaskDomain ||
		cert.AggregationEpoch != pol.RequestedAggregationEpoch {
		return nil, ErrPolicyMismatch
	}
	statement, err := BuildStatement(cert, req.Policy, req.Challenge)
	if err != nil {
		return nil, err
	}
	proof, err := sys.Prove(zkp.Witness{
		PublicInputs: statement,
		Score:        req.Issued.Score,
		ScoreSalt:    req.Issued.ScoreSalt,
		AgentSecret:  req.Agent.AgentSecret,
		PassportSalt: req.Agent.PassportSalt,
	})
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return &ProofPackage{Proof: proof, Statement: statement}, nil
}
