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
	ErrThresholdNotMet    = errors.New("score does not satisfy the policy threshold")
	ErrReceiptCountNotMet = errors.New("receipt count does not satisfy the policy minimum")
	ErrPolicyMismatch     = errors.New("certificate does not satisfy the requested policy")
	ErrNotPassportHolder  = errors.New("agent secret does not open the certificate's passport commitment")
	ErrScoreOpening       = errors.New("score and salt do not open the certificate's score commitment")
	ErrCertificateExpired = errors.New("certificate expires before the proof would")
	ErrKeysetMismatch     = errors.New("certificate was issued under a different committee keyset")
	ErrInsufficientQuorum = errors.New("certificate lacks a quorum of signatures from the keyset")
)

// Nullifier is the only agent-specific public value of a proof. It is
// stable for one verifier and unrelated across verifiers.
func Nullifier(agentSecret, verifierID field.Element) (field.Element, error) {
	return field.Hash(agentSecret, verifierID)
}

// BuildStatement assembles the public inputs for one policy, challenge,
// keyset, and nullifier. Both the prover and the verifier compute it: the
// verifier from its own policy, challenge, and keyset, plus the nullifier
// the prover declares.
func BuildStatement(bundle PolicyBundle, ch Challenge, keyset CommitteeKeyset, nullifier field.Element) zkp.PublicInputs {
	pol := bundle.Policy
	return zkp.PublicInputs{
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

		Nullifier: nullifier,

		CommitteeKeysetID: keyset.ID,
		CommitteeKeys:     keyset.PublicKeys(),
	}
}

// ProofRequest is everything the agent needs to prove access. The agent's
// current manifest is Agent.Manifest; CertifiedManifest is the manifest the
// certificate was issued for (zero means the current one). Keyset is the
// committee keyset the verifier trusts.
type ProofRequest struct {
	Agent             *Agent
	CertifiedManifest Manifest
	Issued            IssuedCertificate
	Policy            PolicyBundle
	Challenge         Challenge
	Keyset            CommitteeKeyset
}

// ProofPackage is what the agent sends to the verifier: the proof and the
// statement it claims. The verifier rebuilds every part of the statement it
// owns and takes only the nullifier from this copy.
type ProofPackage struct {
	Proof     *zkp.Proof
	Statement zkp.PublicInputs
}

// Prove generates a proof that the agent's certificate satisfies the policy.
func Prove(sys *zkp.System, req ProofRequest) (*ProofPackage, error) {
	cert := req.Issued.Certificate
	pol := req.Policy.Policy

	// The agent must actually hold this certificate.
	passportCommitment, err := field.Commit(req.Agent.AgentSecret, req.Agent.PassportSalt)
	if err != nil {
		return nil, err
	}
	if passportCommitment != cert.PassportCommitment {
		return nil, ErrNotPassportHolder
	}
	scoreCommitment, err := field.Commit(req.Issued.Score, req.Issued.ScoreSalt)
	if err != nil {
		return nil, err
	}
	if scoreCommitment != cert.ScoreCommitment {
		return nil, ErrScoreOpening
	}

	// Policy conditions the circuit will enforce.
	if below, err := field.Less(req.Issued.Score, pol.RequiredThreshold); err != nil || below {
		if err != nil {
			return nil, err
		}
		return nil, ErrThresholdNotMet
	}
	if tooFew, err := field.Less(cert.ReceiptCount, pol.MinimumReceiptCount); err != nil || tooFew {
		if err != nil {
			return nil, err
		}
		return nil, ErrReceiptCountNotMet
	}
	if cert.TaskDomain != pol.RequestedTaskDomain || cert.AggregationEpoch != pol.RequestedAggregationEpoch {
		return nil, fmt.Errorf("%w: domain or epoch", ErrPolicyMismatch)
	}
	if outlived, err := field.Less(cert.ExpiresAt, req.Challenge.ProofExpiresAt); err != nil || outlived {
		if err != nil {
			return nil, err
		}
		return nil, ErrCertificateExpired
	}

	// Manifests: the certified one opens the certificate, the current one
	// opens the policy's request, and the change between them is permitted.
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

	// Committee quorum from the verifier's keyset.
	if cert.CommitteeKeysetID != req.Keyset.ID {
		return nil, ErrKeysetMismatch
	}
	var signatures [zkp.Quorum][]byte
	var signers [zkp.Quorum]int
	seen := map[int]bool{}
	found := 0
	for _, sig := range cert.Signatures {
		idx, ok := req.Keyset.Index(sig.NodeID)
		if !ok || seen[idx] {
			continue
		}
		seen[idx] = true
		signatures[found], signers[found] = sig.Signature, idx
		found++
		if found == zkp.Quorum {
			break
		}
	}
	if found < zkp.Quorum {
		return nil, ErrInsufficientQuorum
	}

	nullifier, err := Nullifier(req.Agent.AgentSecret, req.Challenge.VerifierID)
	if err != nil {
		return nil, err
	}
	statement := BuildStatement(req.Policy, req.Challenge, req.Keyset, nullifier)
	w := zkp.Witness{
		PublicInputs:            statement,
		CertificateID:           cert.CertificateID,
		PassportCommitment:      cert.PassportCommitment,
		AgentManifestCommitment: cert.AgentManifestCommitment,
		TaskDomain:              cert.TaskDomain,
		AggregationEpoch:        cert.AggregationEpoch,
		ScoreCommitment:         cert.ScoreCommitment,
		ReceiptCount:            cert.ReceiptCount,
		CertificateIssuedAt:     cert.IssuedAt,
		CertificateExpiresAt:    cert.ExpiresAt,
		Signatures:              signatures,
		SignerIndex:             signers,
		Score:                   req.Issued.Score,
		ScoreSalt:               req.Issued.ScoreSalt,
		AgentSecret:             req.Agent.AgentSecret,
		PassportSalt:            req.Agent.PassportSalt,
		CertifiedManifest:       ManifestFields(req.CertifiedManifest),
		CurrentManifest:         ManifestFields(current),
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
