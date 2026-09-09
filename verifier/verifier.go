// Package verifier implements the service-side checks: committee signatures,
// expiry, policy match, nonce issuance and consumption, and the ZK proof.
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
	ErrPolicyHash         = errors.New("policy hash does not match the policy")
	ErrQuorum             = errors.New("certificate requires signatures from two committee nodes")
	ErrUnknownNonce       = errors.New("nonce was not issued by this verifier")
	ErrNonceConsumed      = errors.New("nonce has already been consumed")
	ErrPolicyMismatch     = passport.ErrPolicyMismatch
	ErrInvalidProof       = zkp.ErrInvalidProof
)

// Checks names the verifier's checks, in the order they run. The verifier
// stops at the first failure and reports the rest as skipped.
var Checks = []string{
	"keyset-known",
	"certificate-unexpired",
	"proof-unexpired",
	"policy-hash",
	"policy-match",
	"committee-quorum",
	"nonce-issued",
	"nonce-unused",
	"proof-valid",
}

// CheckStatus and Check are shared with the gateway so that both report
// their checks in one shape.
type (
	CheckStatus = passport.CheckStatus
	Check       = passport.Check
)

// Check outcomes.
const (
	CheckOK      = passport.CheckOK
	CheckFailed  = passport.CheckFailed
	CheckSkipped = passport.CheckSkipped
)

// Verifier is a service that gates access on a passport proof. It issues the
// challenges it later accepts, so a proof can only be bound to a nonce this
// verifier handed out.
type Verifier struct {
	sys           *zkp.System
	name          string
	verifierID    field.Element
	ttl           int64
	committeeKeys map[string]ed25519.PublicKey
	pending       map[string]field.Element // nonce key -> proofExpiresAt
	used          map[string]struct{}
}

// New creates a verifier named verifierName that trusts the given committee
// public keys.
func New(sys *zkp.System, committee []passport.PublicIdentity, verifierName string) *Verifier {
	keys := make(map[string]ed25519.PublicKey, len(committee))
	for _, node := range committee {
		keys[node.NodeID] = node.PublicKey
	}
	return &Verifier{
		sys:           sys,
		name:          verifierName,
		verifierID:    field.FromText(verifierName),
		ttl:           passport.DefaultChallengeTTL,
		committeeKeys: keys,
		pending:       map[string]field.Element{},
		used:          map[string]struct{}{},
	}
}

// State is the verifier's nonce bookkeeping, so that a service can persist
// it between processes.
type State struct {
	Pending map[string]field.Element `json:"pending"`
	Used    []string                 `json:"used"`
}

// ExportState snapshots the nonce bookkeeping.
func (v *Verifier) ExportState() State {
	st := State{Pending: map[string]field.Element{}}
	for k, exp := range v.pending {
		st.Pending[k] = exp
	}
	for k := range v.used {
		st.Used = append(st.Used, k)
	}
	return st
}

// ImportState restores nonce bookkeeping from a snapshot.
func (v *Verifier) ImportState(st State) {
	v.pending = map[string]field.Element{}
	for k, exp := range st.Pending {
		v.pending[k] = exp
	}
	v.used = map[string]struct{}{}
	for _, k := range st.Used {
		v.used[k] = struct{}{}
	}
}

// IssueChallenge hands out a fresh nonce bound to this verifier and records
// it as pending.
func (v *Verifier) IssueChallenge(now int64) (passport.Challenge, error) {
	ch, err := passport.NewChallenge(v.name, now, v.ttl)
	if err != nil {
		return passport.Challenge{}, err
	}
	v.pending[nonceKey(ch)] = ch.ProofExpiresAt
	return ch, nil
}

func nonceKey(ch passport.Challenge) string {
	return ch.VerifierID + ":" + ch.Nonce
}

// AccessRequest is what an agent submits. The certificate arrives redacted:
// the verifier never sees the receipt count, only the hash the committee
// signed and the fields the proof binds to that hash.
type AccessRequest struct {
	Presentation passport.CertificatePresentation
	Policy       passport.PolicyBundle
	Challenge    passport.Challenge
	Proof        *passport.ProofPackage
	Now          int64
}

// Decision is the result of a verification. Checks is filled in whether or
// not the request was authorized, so callers can show what was examined.
type Decision struct {
	Authorized      bool
	CertificateHash field.Element
	Checks          []Check
}

// checkRun executes the checks in order and records their outcomes.
type checkRun struct {
	checks []Check
	err    error
}

func (r *checkRun) do(key string, fn func() error) {
	if r.err != nil {
		r.checks = append(r.checks, Check{Key: key, Status: CheckSkipped})
		return
	}
	if err := fn(); err != nil {
		r.err = err
		r.checks = append(r.checks, Check{Key: key, Status: CheckFailed, Err: err})
		return
	}
	r.checks = append(r.checks, Check{Key: key, Status: CheckOK})
}

// VerifyAccess runs every check in the order of Checks and consumes the
// nonce only on success.
func (v *Verifier) VerifyAccess(req AccessRequest) (Decision, error) {
	cert := req.Presentation
	pol := req.Policy.Policy
	now := field.FromInt(req.Now)
	var run checkRun

	run.do("keyset-known", func() error {
		if cert.CommitteeKeysetID != passport.CommitteeKeysetID {
			return ErrUnknownKeyset
		}
		return nil
	})
	run.do("certificate-unexpired", func() error {
		return lessIs(cert.ExpiresAt, now, ErrCertificateExpired)
	})
	run.do("proof-unexpired", func() error {
		return lessIs(req.Challenge.ProofExpiresAt, now, ErrProofExpired)
	})
	run.do("policy-hash", func() error {
		expected, err := passport.PolicyHash(pol)
		if err != nil {
			return err
		}
		if expected != req.Policy.PolicyHash {
			return ErrPolicyHash
		}
		return nil
	})
	run.do("policy-match", func() error {
		// Domain and epoch are checked here as well as in the circuit. The
		// manifest relation is checked only in the circuit: the verifier
		// knows the two commitments but not the manifests behind them, and
		// the policy may permit them to differ.
		if cert.TaskDomain != pol.RequestedTaskDomain || cert.AggregationEpoch != pol.RequestedAggregationEpoch {
			return ErrPolicyMismatch
		}
		return nil
	})
	run.do("committee-quorum", func() error {
		// The hash is taken from the presentation; the proof establishes
		// that the presented fields (and the hidden receipt count) are its
		// preimage.
		msg, err := field.Bytes(cert.CertificateHash)
		if err != nil {
			return err
		}
		signers := map[string]struct{}{}
		for _, sig := range cert.Signatures {
			pub, ok := v.committeeKeys[sig.NodeID]
			if ok && passport.VerifySignature(pub, msg, sig.Signature) {
				signers[sig.NodeID] = struct{}{}
			}
		}
		if len(signers) < passport.Quorum {
			return ErrQuorum
		}
		return nil
	})
	key := nonceKey(req.Challenge)
	run.do("nonce-issued", func() error {
		expiry, ok := v.pending[key]
		if !ok || expiry != req.Challenge.ProofExpiresAt || req.Challenge.VerifierID != v.verifierID {
			if _, wasUsed := v.used[key]; wasUsed {
				return nil // reported by the next check
			}
			return ErrUnknownNonce
		}
		return nil
	})
	run.do("nonce-unused", func() error {
		if _, used := v.used[key]; used {
			return ErrNonceConsumed
		}
		return nil
	})
	run.do("proof-valid", func() error {
		if req.Proof == nil || req.Proof.Proof == nil {
			return fmt.Errorf("%w: missing proof", ErrInvalidProof)
		}
		statement, err := passport.BuildStatement(cert, req.Policy, req.Challenge)
		if err != nil {
			return err
		}
		return v.sys.Verify(req.Proof.Proof, statement)
	})

	if run.err != nil {
		return Decision{Checks: run.checks}, run.err
	}
	delete(v.pending, key)
	v.used[key] = struct{}{}
	return Decision{Authorized: true, CertificateHash: cert.CertificateHash, Checks: run.checks}, nil
}

// lessIs returns failure if a < b as integers.
func lessIs(a, b field.Element, failure error) error {
	less, err := field.Less(a, b)
	if err != nil {
		return err
	}
	if less {
		return failure
	}
	return nil
}
