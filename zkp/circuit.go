// Package zkp defines the passport circuit and the Groth16 prove/verify flow.
package zkp

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// ScoreBits bounds scores, counts, and timestamps to unsigned 32-bit values.
const ScoreBits = 32

// ManifestFieldCount is the number of manifest fields bound by a passport:
// modelId, systemPromptHash, toolPolicyHash, permissionScope.
const ManifestFieldCount = 4

// AllowlistDepth is the Merkle depth of a manifest allowlist.
const AllowlistDepth = 4

// CommitteeSize is the number of committee nodes in a keyset; Quorum is how
// many of their signatures a certificate needs.
const (
	CommitteeSize = 3
	Quorum        = 2
)

// PassportCircuit proves, without revealing the certificate, that the
// holder of a passport secret owns a committee-signed score certificate
// whose hidden score and receipt count satisfy a public policy, whose
// domain and epoch match the policy, that is still valid when the proof
// expires, and whose certified manifest differs from the current one only
// as the policy permits. The only agent-specific public value is a
// per-verifier nullifier, so two verifiers cannot link the same passport.
type PassportCircuit struct {
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

	// Nullifier = Hash(agentSecret, verifierId): stable for one verifier,
	// unrelated across verifiers.
	Nullifier frontend.Variable `gnark:",public"`

	// Committee keyset the verifier trusts, public.
	CommitteeKeysetID frontend.Variable              `gnark:",public"`
	CommitteeKeys     [CommitteeSize]eddsa.PublicKey `gnark:",public"`

	// Certificate, private. Its hash is recomputed in-circuit and is what
	// the committee signed.
	CertificateID           frontend.Variable
	PassportCommitment      frontend.Variable
	AgentManifestCommitment frontend.Variable
	TaskDomain              frontend.Variable
	AggregationEpoch        frontend.Variable
	ScoreCommitment         frontend.Variable
	ReceiptCount            frontend.Variable
	CertificateIssuedAt     frontend.Variable
	CertificateExpiresAt    frontend.Variable

	// Quorum of committee signatures over the certificate hash, private.
	// SignerIndex says which keyset entry each signature belongs to.
	Signatures  [Quorum]eddsa.Signature
	SignerIndex [Quorum]frontend.Variable

	// Secrets.
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

// hasher is the in-circuit Poseidon2 sponge, reset before every absorption.
type hasher func(inputs ...frontend.Variable) frontend.Variable

// Define declares the constraints. Each step below is one condition the
// passport has to satisfy, in the same order the prover checks them natively.
func (c *PassportCircuit) Define(api frontend.API) error {
	h, err := poseidon2.New(api)
	if err != nil {
		return err
	}
	hash := hasher(func(inputs ...frontend.Variable) frontend.Variable {
		h.Reset()
		h.Write(inputs...)
		return h.Sum()
	})

	if err := c.assertCommitteeQuorum(api, hash); err != nil {
		return err
	}
	c.assertPolicyHash(api, hash)
	c.assertOpenings(api, hash)
	c.assertManifestVersionPolicy(api, hash)
	c.assertCertificateMatchesPolicy(api)
	c.assertBounds(api)

	// Groth16 does not bind public inputs that appear in no constraint. The
	// nonce is otherwise unused, so it is constrained to be non-zero.
	api.AssertIsDifferent(c.Nonce, 0)
	return nil
}

// assertCommitteeQuorum recomputes the certificate hash and requires that
// Quorum distinct members of the public keyset signed it.
func (c *PassportCircuit) assertCommitteeQuorum(api frontend.API, hash hasher) error {
	// The certificate hash commits to every certificate field, including
	// the keyset it was issued under.
	certificateHash := hash(
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
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	for i := 0; i < Quorum; i++ {
		key := selectKey(api, c.CommitteeKeys, c.SignerIndex[i])
		m, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}
		if err := eddsa.Verify(curve, c.Signatures[i], certificateHash, key, &m); err != nil {
			return err
		}
	}
	api.AssertIsDifferent(c.SignerIndex[0], c.SignerIndex[1])
	return nil
}

// assertPolicyHash binds the published policy hash to the policy fields, so a
// proof for one policy cannot be presented under another.
func (c *PassportCircuit) assertPolicyHash(api frontend.API, hash hasher) {
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
}

// assertOpenings proves the prover holds what the commitments hide: the
// score, the passport secret, and both manifests. The nullifier is derived
// from the same secret, which is what makes it stable per verifier.
func (c *PassportCircuit) assertOpenings(api frontend.API, hash hasher) {
	api.AssertIsEqual(hash(c.Score, c.ScoreSalt), c.ScoreCommitment)
	api.AssertIsEqual(hash(c.AgentSecret, c.PassportSalt), c.PassportCommitment)
	api.AssertIsEqual(hash(c.AgentSecret, c.VerifierID), c.Nullifier)
	api.AssertIsEqual(hash(c.CertifiedManifest[:]...), c.AgentManifestCommitment)
	api.AssertIsEqual(hash(c.CurrentManifest[:]...), c.RequestedManifestCommitment)
}

// assertManifestVersionPolicy requires every manifest field to be either
// unchanged since certification, or mutable under the policy with its new
// value present in the allowlist.
func (c *PassportCircuit) assertManifestVersionPolicy(api frontend.API, hash hasher) {
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
}

// assertCertificateMatchesPolicy requires the certificate to be the one the
// policy asked about: same task domain, same aggregation epoch.
func (c *PassportCircuit) assertCertificateMatchesPolicy(api frontend.API) {
	api.AssertIsEqual(c.TaskDomain, c.RequestedTaskDomain)
	api.AssertIsEqual(c.AggregationEpoch, c.RequestedAggregationEpoch)
}

// assertBounds checks score >= threshold, receiptCount >= minimum, and that
// the certificate outlives the proof.
func (c *PassportCircuit) assertBounds(api frontend.API) {
	assertGreaterEqual32(api, c.Score, c.RequiredThreshold)
	assertGreaterEqual32(api, c.ReceiptCount, c.MinimumReceiptCount)
	assertGreaterEqual32(api, c.CertificateExpiresAt, c.ProofExpiresAt)
}

// assertGreaterEqual32 enforces a >= b with both operands range-checked to
// 32 bits so that the difference cannot wrap around the field.
func assertGreaterEqual32(api frontend.API, a, b frontend.Variable) {
	api.ToBinary(a, ScoreBits)
	api.ToBinary(b, ScoreBits)
	api.ToBinary(api.Sub(a, b), ScoreBits)
}

// selectKey picks keyset entry index (0..CommitteeSize-1) with a binary
// decomposition of the index, and rejects indices out of range. The two index
// bits and the "index != 3" check are written for CommitteeSize == 3; both
// have to be widened if the keyset ever grows.
func selectKey(api frontend.API, keys [CommitteeSize]eddsa.PublicKey, index frontend.Variable) eddsa.PublicKey {
	bits := api.ToBinary(index, 2)
	api.AssertIsEqual(api.Mul(bits[0], bits[1]), 0) // index != 3
	var key eddsa.PublicKey
	key.A.X = api.Select(bits[1], keys[2].A.X, api.Select(bits[0], keys[1].A.X, keys[0].A.X))
	key.A.Y = api.Select(bits[1], keys[2].A.Y, api.Select(bits[0], keys[1].A.Y, keys[0].A.Y))
	return key
}
