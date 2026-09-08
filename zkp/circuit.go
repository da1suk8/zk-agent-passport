// Package zkp defines the passport circuit and the Groth16 prove/verify flow.
package zkp

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/poseidon2"
)

// ScoreBits bounds scores and thresholds to unsigned 32-bit values.
const ScoreBits = 32

// PassportCircuit proves that the holder of a passport secret owns a score
// certificate whose committed score satisfies a public policy, without
// revealing the score or the secret.
type PassportCircuit struct {
	// Certificate statement, all public.
	CertificateHash         frontend.Variable `gnark:",public"`
	CertificateID           frontend.Variable `gnark:",public"`
	PassportCommitment      frontend.Variable `gnark:",public"`
	AgentManifestCommitment frontend.Variable `gnark:",public"`
	TaskDomain              frontend.Variable `gnark:",public"`
	AggregationEpoch        frontend.Variable `gnark:",public"`
	ScoreCommitment         frontend.Variable `gnark:",public"`
	ReceiptCount            frontend.Variable `gnark:",public"`
	CertificateIssuedAt     frontend.Variable `gnark:",public"`
	CertificateExpiresAt    frontend.Variable `gnark:",public"`
	CommitteeKeysetID       frontend.Variable `gnark:",public"`

	// Policy statement, all public.
	PolicyHash                  frontend.Variable `gnark:",public"`
	PolicyVersion               frontend.Variable `gnark:",public"`
	RequiredThreshold           frontend.Variable `gnark:",public"`
	MinimumReceiptCount         frontend.Variable `gnark:",public"`
	RequestedTaskDomain         frontend.Variable `gnark:",public"`
	RequestedManifestCommitment frontend.Variable `gnark:",public"`
	RequestedAggregationEpoch   frontend.Variable `gnark:",public"`

	// Verifier challenge statement, all public.
	VerifierID     frontend.Variable `gnark:",public"`
	Nonce          frontend.Variable `gnark:",public"`
	ProofExpiresAt frontend.Variable `gnark:",public"`

	// Witnesses, never exposed to the verifier.
	Score        frontend.Variable
	ScoreSalt    frontend.Variable
	AgentSecret  frontend.Variable
	PassportSalt frontend.Variable
}

// Define declares the constraints.
func (c *PassportCircuit) Define(api frontend.API) error {
	h, err := poseidon2.New(api)
	if err != nil {
		return err
	}

	// The certificate hash commits to every certificate field.
	h.Write(
		c.CertificateID,
		c.PassportCommitment,
		c.AgentManifestCommitment,
		c.TaskDomain,
		c.AggregationEpoch,
		c.ScoreCommitment,
		c.ReceiptCount,
		c.CertificateIssuedAt,
		c.CertificateExpiresAt,
		c.CommitteeKeysetID,
	)
	api.AssertIsEqual(h.Sum(), c.CertificateHash)
	h.Reset()

	// The policy hash commits to every policy field.
	h.Write(
		c.PolicyVersion,
		c.RequiredThreshold,
		c.MinimumReceiptCount,
		c.RequestedTaskDomain,
		c.RequestedManifestCommitment,
		c.RequestedAggregationEpoch,
	)
	api.AssertIsEqual(h.Sum(), c.PolicyHash)
	h.Reset()

	// Opening of the score commitment.
	h.Write(c.Score, c.ScoreSalt)
	api.AssertIsEqual(h.Sum(), c.ScoreCommitment)
	h.Reset()

	// Knowledge of the passport secret behind the passport commitment.
	h.Write(c.AgentSecret, c.PassportSalt)
	api.AssertIsEqual(h.Sum(), c.PassportCommitment)

	// The certificate must satisfy the public policy.
	api.AssertIsEqual(c.AgentManifestCommitment, c.RequestedManifestCommitment)
	api.AssertIsEqual(c.TaskDomain, c.RequestedTaskDomain)
	api.AssertIsEqual(c.AggregationEpoch, c.RequestedAggregationEpoch)

	// score >= requiredThreshold over unsigned 32-bit values. Both operands
	// are range-checked so that the difference cannot wrap around the field.
	api.ToBinary(c.Score, ScoreBits)
	api.ToBinary(c.RequiredThreshold, ScoreBits)
	api.ToBinary(api.Sub(c.Score, c.RequiredThreshold), ScoreBits)

	// Groth16 does not bind public inputs that appear in no constraint. The
	// challenge fields must therefore be constrained explicitly; requiring
	// them to be non-zero is the cheapest meaningful constraint.
	api.AssertIsDifferent(c.VerifierID, 0)
	api.AssertIsDifferent(c.Nonce, 0)
	api.AssertIsDifferent(c.ProofExpiresAt, 0)
	return nil
}
