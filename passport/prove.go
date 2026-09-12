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
// Every condition the circuit enforces is checked here first, so an agent
// that cannot satisfy the policy learns why instead of watching a proof fail.
func Prove(sys *zkp.System, req ProofRequest) (*ProofPackage, error) {
	cert := req.Issued.Certificate

	if err := checkHolder(req); err != nil {
		return nil, err
	}
	if err := checkPolicyConditions(req); err != nil {
		return nil, err
	}
	certified, err := checkManifests(req)
	if err != nil {
		return nil, err
	}
	signatures, signers, err := selectQuorum(cert, req.Keyset)
	if err != nil {
		return nil, err
	}
	paths, err := allowlistPaths(req.Policy, certified, req.Agent.Manifest)
	if err != nil {
		return nil, err
	}

	nullifier, err := Nullifier(req.Agent.AgentSecret, req.Challenge.VerifierID)
	if err != nil {
		return nil, err
	}
	statement := BuildStatement(req.Policy, req.Challenge, req.Keyset, nullifier)
	proof, err := sys.Prove(zkp.Witness{
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
		CertifiedManifest:       ManifestFields(certified),
		CurrentManifest:         ManifestFields(req.Agent.Manifest),
		AllowlistPaths:          paths,
	})
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return &ProofPackage{Proof: proof, Statement: statement}, nil
}

// checkHolder verifies that the agent actually holds this certificate: its
// secret opens the passport commitment, and its score opens the score
// commitment the committee signed.
func checkHolder(req ProofRequest) error {
	cert := req.Issued.Certificate
	passportCommitment, err := field.Commit(req.Agent.AgentSecret, req.Agent.PassportSalt)
	if err != nil {
		return err
	}
	if passportCommitment != cert.PassportCommitment {
		return ErrNotPassportHolder
	}
	scoreCommitment, err := field.Commit(req.Issued.Score, req.Issued.ScoreSalt)
	if err != nil {
		return err
	}
	if scoreCommitment != cert.ScoreCommitment {
		return ErrScoreOpening
	}
	return nil
}

// checkPolicyConditions mirrors the numeric and equality conditions the
// circuit enforces over the certificate and the policy.
func checkPolicyConditions(req ProofRequest) error {
	cert, pol := req.Issued.Certificate, req.Policy.Policy
	if below, err := field.Less(req.Issued.Score, pol.RequiredThreshold); err != nil {
		return err
	} else if below {
		return ErrThresholdNotMet
	}
	if tooFew, err := field.Less(cert.ReceiptCount, pol.MinimumReceiptCount); err != nil {
		return err
	} else if tooFew {
		return ErrReceiptCountNotMet
	}
	if cert.TaskDomain != pol.RequestedTaskDomain || cert.AggregationEpoch != pol.RequestedAggregationEpoch {
		return fmt.Errorf("%w: domain or epoch", ErrPolicyMismatch)
	}
	if outlived, err := field.Less(cert.ExpiresAt, req.Challenge.ProofExpiresAt); err != nil {
		return err
	} else if outlived {
		return ErrCertificateExpired
	}
	return nil
}

// checkManifests resolves the certified manifest (defaulting to the agent's
// current one) and checks the three manifest conditions: the certified one
// opens the certificate, the current one opens the policy's request, and the
// change between them is permitted. It returns the resolved certified
// manifest.
func checkManifests(req ProofRequest) (Manifest, error) {
	certified := req.CertifiedManifest
	if certified == (Manifest{}) {
		certified = req.Agent.Manifest
	}
	certifiedCommitment, err := ManifestCommitment(certified)
	if err != nil {
		return Manifest{}, err
	}
	if certifiedCommitment != req.Issued.Certificate.AgentManifestCommitment {
		return Manifest{}, fmt.Errorf("%w: certificate was not issued for the given certified manifest", ErrPolicyMismatch)
	}
	if req.Agent.AgentManifestCommitment != req.Policy.Policy.RequestedManifestCommitment {
		return Manifest{}, fmt.Errorf("%w: policy requests a manifest other than the agent's current one", ErrPolicyMismatch)
	}
	if err := req.Policy.VersionPolicy.Permits(certified, req.Agent.Manifest); err != nil {
		return Manifest{}, fmt.Errorf("%w: %w", ErrPolicyMismatch, err)
	}
	return certified, nil
}

// selectQuorum picks Quorum signatures from distinct keyset entries. A
// signature from a node outside the keyset, or a second signature from a node
// already counted, does not contribute.
func selectQuorum(cert ScoreCertificate, keyset CommitteeKeyset) (signatures [zkp.Quorum][]byte, signers [zkp.Quorum]int, err error) {
	if cert.CommitteeKeysetID != keyset.ID {
		return signatures, signers, ErrKeysetMismatch
	}
	seen := map[int]bool{}
	found := 0
	for _, sig := range cert.Signatures {
		idx, ok := keyset.Index(sig.NodeID)
		if !ok || seen[idx] {
			continue
		}
		seen[idx] = true
		signatures[found], signers[found] = sig.Signature, idx
		found++
		if found == zkp.Quorum {
			return signatures, signers, nil
		}
	}
	return signatures, signers, ErrInsufficientQuorum
}

// allowlistPaths builds one Merkle path per manifest field: a real inclusion
// path for a field that changed, and the placeholder path for one that did
// not. The circuit ignores the path of an unchanged field.
func allowlistPaths(policy PolicyBundle, certified, current Manifest) ([ManifestFieldCount]zkp.MerkleWitness, error) {
	var paths [ManifestFieldCount]zkp.MerkleWitness
	certifiedValues, currentValues := manifestValues(certified), manifestValues(current)
	for i := 0; i < ManifestFieldCount; i++ {
		path := EmptyPath()
		if certifiedValues[i] != currentValues[i] {
			p, ok := policy.Allowlist.Path(i, currentValues[i])
			if !ok {
				return paths, fmt.Errorf("%w: %s", ErrManifestValueNotAllowed, ManifestFieldNames[i])
			}
			path = p
		}
		paths[i] = zkp.MerkleWitness{Index: field.FromInt(path.Index), Siblings: path.Siblings}
	}
	return paths, nil
}
