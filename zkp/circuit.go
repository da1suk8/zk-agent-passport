// Package zkp defines the passport circuit and the Groth16 prove/verify flow.
package zkp

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/poseidon2"
)

// ScoreBits bounds scores and thresholds to unsigned 32-bit values.
const ScoreBits = 32

// ManifestFieldCount is the number of manifest fields bound by a passport:
// modelId, systemPromptHash, toolPolicyHash, permissionScope.
const ManifestFieldCount = 4

// AllowlistDepth is the Merkle depth of a manifest allowlist.
const AllowlistDepth = 4

// PassportCircuit proves that the holder of a passport secret owns a score
// certificate whose committed score satisfies a public policy, and that the
// agent's current manifest differs from the certified one only in the ways
// the policy permits, without revealing the score, the secret, or the
// manifests.
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
	ManifestMutableMask         frontend.Variable `gnark:",public"`
	ManifestAllowlistRoot       frontend.Variable `gnark:",public"`

	// Verifier challenge statement, all public.
	VerifierID     frontend.Variable `gnark:",public"`
	Nonce          frontend.Variable `gnark:",public"`
	ProofExpiresAt frontend.Variable `gnark:",public"`

	// Witnesses, never exposed to the verifier.
	Score        frontend.Variable
	ScoreSalt    frontend.Variable
	AgentSecret  frontend.Variable
	PassportSalt frontend.Variable

	// CertifiedManifest opens AgentManifestCommitment; CurrentManifest opens
	// RequestedManifestCommitment. For every field that differs, the
	// allowlist path proves the new value is permitted.
	CertifiedManifest [ManifestFieldCount]frontend.Variable
	CurrentManifest   [ManifestFieldCount]frontend.Variable
	AllowlistIndex    [ManifestFieldCount]frontend.Variable
	AllowlistSiblings [ManifestFieldCount][AllowlistDepth]frontend.Variable
}

// Define declares the constraints.
func (c *PassportCircuit) Define(api frontend.API) error {
	h, err := poseidon2.New(api)
	if err != nil {
		return err
	}
	hash := func(inputs ...frontend.Variable) frontend.Variable {
		h.Reset()
		h.Write(inputs...)
		return h.Sum()
	}

	// The certificate hash commits to every certificate field.
	api.AssertIsEqual(hash(
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
	), c.CertificateHash)

	// The policy hash commits to every policy field.
	api.AssertIsEqual(hash(
		c.PolicyVersion,
		c.RequiredThreshold,
		c.MinimumReceiptCount,
		c.RequestedTaskDomain,
		c.RequestedManifestCommitment,
		c.RequestedAggregationEpoch,
		c.ManifestMutableMask,
		c.ManifestAllowlistRoot,
	), c.PolicyHash)

	// Opening of the score commitment.
	api.AssertIsEqual(hash(c.Score, c.ScoreSalt), c.ScoreCommitment)

	// Knowledge of the passport secret behind the passport commitment.
	api.AssertIsEqual(hash(c.AgentSecret, c.PassportSalt), c.PassportCommitment)

	// Openings of both manifest commitments.
	api.AssertIsEqual(hash(c.CertifiedManifest[:]...), c.AgentManifestCommitment)
	api.AssertIsEqual(hash(c.CurrentManifest[:]...), c.RequestedManifestCommitment)

	// Manifest version policy: each field is either unchanged, or mutable
	// under the policy with its new value present in the allowlist.
	mutable := api.ToBinary(c.ManifestMutableMask, ManifestFieldCount)
	for i := 0; i < ManifestFieldCount; i++ {
		same := api.IsZero(api.Sub(c.CertifiedManifest[i], c.CurrentManifest[i]))

		node := hash(i+1, c.CurrentManifest[i])
		bits := api.ToBinary(c.AllowlistIndex[i], AllowlistDepth)
		for k := 0; k < AllowlistDepth; k++ {
			sibling := c.AllowlistSiblings[i][k]
			left := api.Select(bits[k], sibling, node)
			right := api.Select(bits[k], node, sibling)
			node = hash(left, right)
		}
		inAllowlist := api.IsZero(api.Sub(node, c.ManifestAllowlistRoot))

		permitted := api.Mul(mutable[i], inAllowlist)
		ok := api.Add(same, api.Mul(api.Sub(1, same), permitted))
		api.AssertIsEqual(ok, 1)
	}

	// The certificate must match the policy's domain and epoch exactly.
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
