// Package verifier implements the service-side checks: committee signatures,
// expiry, policy match, nonce consumption, and the ZK proof.
package verifier

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/da1suk8/zk-agent-passport/field"
	"github.com/da1suk8/zk-agent-passport/passport"
	"github.com/da1suk8/zk-agent-passport/zkp"
)

// Verification failures.
var (
	ErrUnknownKeyset      = errors.New("certificate uses an unknown committee keyset")
	ErrCertificateExpired = errors.New("certificate is expired")
	ErrProofExpired       = errors.New("proof is expired")
	ErrReceiptCount       = errors.New("certificate does not satisfy minimum receipt count")
	ErrQuorum             = errors.New("certificate requires signatures from two committee nodes")
	ErrNonceConsumed      = errors.New("nonce has already been consumed")
	ErrPolicyMismatch     = passport.ErrPolicyMismatch
	ErrInvalidProof       = zkp.ErrInvalidProof
)

// Verifier is a service that gates access on a passport proof.
type Verifier struct {
	sys           *zkp.System
	committeeKeys map[string]ed25519.PublicKey
	usedNonces    map[string]struct{}
}

// New creates a verifier trusting the given committee public keys.
func New(sys *zkp.System, committee []passport.PublicIdentity) *Verifier {
	keys := make(map[string]ed25519.PublicKey, len(committee))
	for _, node := range committee {
		keys[node.NodeID] = node.PublicKey
	}
	return &Verifier{sys: sys, committeeKeys: keys, usedNonces: map[string]struct{}{}}
}

// AccessRequest is what an agent submits.
type AccessRequest struct {
	Certificate passport.ScoreCertificate
	Policy      passport.PolicyBundle
	Challenge   passport.Challenge
	Proof       *passport.ProofPackage
	Now         int64
}

// Decision is the result of a successful verification.
type Decision struct {
	Authorized      bool
	CertificateHash field.Element
}

// VerifyAccess runs every check and consumes the nonce only on success.
func (v *Verifier) VerifyAccess(req AccessRequest) (Decision, error) {
	cert := req.Certificate
	pol := req.Policy.Policy
	if cert.CommitteeKeysetID != passport.CommitteeKeysetID {
		return Decision{}, ErrUnknownKeyset
	}
	now := field.FromInt(req.Now)
	if expired, err := field.Less(cert.ExpiresAt, now); err != nil || expired {
		if err != nil {
			return Decision{}, err
		}
		return Decision{}, ErrCertificateExpired
	}
	if expired, err := field.Less(req.Challenge.ProofExpiresAt, now); err != nil || expired {
		if err != nil {
			return Decision{}, err
		}
		return Decision{}, ErrProofExpired
	}
	if short, err := field.Less(cert.ReceiptCount, pol.MinimumReceiptCount); err != nil || short {
		if err != nil {
			return Decision{}, err
		}
		return Decision{}, ErrReceiptCount
	}
	// Domain and epoch are checked here as well as in the circuit. The
	// manifest relation is checked only in the circuit: the verifier knows
	// the two commitments but not the manifests behind them, and the policy
	// may permit them to differ.
	if cert.TaskDomain != pol.RequestedTaskDomain || cert.AggregationEpoch != pol.RequestedAggregationEpoch {
		return Decision{}, ErrPolicyMismatch
	}

	hash, err := passport.CertificateHash(cert.CertificatePayload)
	if err != nil {
		return Decision{}, err
	}
	msg, err := field.Bytes(hash)
	if err != nil {
		return Decision{}, err
	}
	signers := map[string]struct{}{}
	for _, sig := range cert.Signatures {
		pub, ok := v.committeeKeys[sig.NodeID]
		if ok && passport.VerifySignature(pub, msg, sig.Signature) {
			signers[sig.NodeID] = struct{}{}
		}
	}
	if len(signers) < passport.Quorum {
		return Decision{}, ErrQuorum
	}

	nonceKey := req.Challenge.VerifierID + ":" + req.Challenge.Nonce
	if _, used := v.usedNonces[nonceKey]; used {
		return Decision{}, ErrNonceConsumed
	}

	statement, err := passport.BuildStatement(cert, req.Policy, req.Challenge)
	if err != nil {
		return Decision{}, err
	}
	if req.Proof == nil || req.Proof.Proof == nil {
		return Decision{}, fmt.Errorf("%w: missing proof", ErrInvalidProof)
	}
	if err := v.sys.Verify(req.Proof.Proof, statement); err != nil {
		return Decision{}, err
	}

	v.usedNonces[nonceKey] = struct{}{}
	return Decision{Authorized: true, CertificateHash: hash}, nil
}
