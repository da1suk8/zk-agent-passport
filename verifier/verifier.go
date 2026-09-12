// Package verifier implements the service-side checks. With the certificate
// hidden inside the proof, the verifier's own work shrinks to: the proof is
// still valid in time, the policy is the one it published, the nonce is one
// it issued for that policy and has not consumed, and the proof verifies
// against a statement it rebuilds itself.
package verifier

import (
	"errors"
	"fmt"

	"github.com/da1suk8/zk-agent-passport/field"
	"github.com/da1suk8/zk-agent-passport/passport"
	"github.com/da1suk8/zk-agent-passport/zkp"
)

// Verification failures.
var (
	ErrProofExpired        = errors.New("proof is expired")
	ErrPolicyHash          = errors.New("policy hash does not match the policy")
	ErrUnknownNonce        = errors.New("nonce was not issued by this verifier")
	ErrPolicyNotChallenged = errors.New("nonce was issued for a different policy")
	ErrNonceConsumed       = errors.New("nonce has already been consumed")
	ErrInvalidProof        = zkp.ErrInvalidProof
)

// Checks names the verifier's checks, in the order they run. Certificate
// expiry, committee quorum, and policy match are enforced inside the proof.
var Checks = []string{
	"proof-unexpired",
	"policy-hash",
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
// verifier handed out, for the policy it handed out with it.
type Verifier struct {
	sys        *zkp.System
	name       string
	verifierID field.Element
	ttl        int64
	keyset     passport.CommitteeKeyset
	pending    map[string]Pending // nonce key -> what the nonce was issued for
	used       map[string]struct{}
}

// New creates a verifier named verifierName that trusts the given committee
// keyset.
func New(sys *zkp.System, keyset passport.CommitteeKeyset, verifierName string) *Verifier {
	return &Verifier{
		sys:        sys,
		name:       verifierName,
		verifierID: field.FromText(verifierName),
		ttl:        passport.DefaultChallengeTTL,
		keyset:     keyset,
		pending:    map[string]Pending{},
		used:       map[string]struct{}{},
	}
}

// Keyset returns the committee keyset this verifier trusts; agents need it
// to build the statement they prove.
func (v *Verifier) Keyset() passport.CommitteeKeyset {
	return v.keyset
}

// Pending is what an outstanding nonce was issued for. Recording the policy
// hash here is what stops a proof made for some other policy from being
// presented against this verifier's own challenge.
type Pending struct {
	ProofExpiresAt field.Element `json:"proofExpiresAt"`
	PolicyHash     field.Element `json:"policyHash"`
}

// State is the verifier's nonce bookkeeping, so that a service can persist
// it between processes.
type State struct {
	Pending map[string]Pending `json:"pending"`
	Used    []string           `json:"used"`
}

// ExportState snapshots the nonce bookkeeping.
func (v *Verifier) ExportState() State {
	st := State{Pending: map[string]Pending{}}
	for k, p := range v.pending {
		st.Pending[k] = p
	}
	for k := range v.used {
		st.Used = append(st.Used, k)
	}
	return st
}

// ImportState restores nonce bookkeeping from a snapshot.
func (v *Verifier) ImportState(st State) {
	v.pending = map[string]Pending{}
	for k, p := range st.Pending {
		v.pending[k] = p
	}
	v.used = map[string]struct{}{}
	for _, k := range st.Used {
		v.used[k] = struct{}{}
	}
}

// IssueChallenge hands out a fresh nonce bound to this verifier and to the
// policy the agent is being asked to satisfy, and records it as pending.
func (v *Verifier) IssueChallenge(now int64, policyHash field.Element) (passport.Challenge, error) {
	ch, err := passport.NewChallenge(v.name, now, v.ttl)
	if err != nil {
		return passport.Challenge{}, err
	}
	v.pending[nonceKey(ch)] = Pending{ProofExpiresAt: ch.ProofExpiresAt, PolicyHash: policyHash}
	return ch, nil
}

func nonceKey(ch passport.Challenge) string {
	return ch.VerifierID + ":" + ch.Nonce
}

// AccessRequest is what an agent submits: the proof and its statement. No
// certificate travels with it. Policy is the bundle the verifier published
// with the challenge; the verifier checks that it is the one it issued the
// nonce for rather than trusting the caller.
type AccessRequest struct {
	Policy    passport.PolicyBundle
	Challenge passport.Challenge
	Proof     *passport.ProofPackage
	Now       int64
}

// Decision is the result of a verification. Checks is filled in whether or
// not the request was authorized. Nullifier is the only agent-specific
// value the verifier learns; it is stable for this verifier and unrelated
// to what any other verifier sees.
type Decision struct {
	Authorized bool
	Nullifier  field.Element
	Checks     []Check
}

// VerifyAccess runs every check in the order of Checks and consumes the
// nonce only on success.
func (v *Verifier) VerifyAccess(req AccessRequest) (Decision, error) {
	now := field.FromInt(req.Now)
	key := nonceKey(req.Challenge)
	var run passport.CheckRun
	var nullifier field.Element

	run.Do("proof-unexpired", func() error {
		expired, err := field.Less(req.Challenge.ProofExpiresAt, now)
		if err != nil {
			return err
		}
		if expired {
			return ErrProofExpired
		}
		return nil
	})
	run.Do("policy-hash", func() error {
		expected, err := passport.PolicyHash(req.Policy.Policy)
		if err != nil {
			return err
		}
		if expected != req.Policy.PolicyHash {
			return ErrPolicyHash
		}
		return nil
	})
	run.Do("nonce-issued", func() error {
		if _, used := v.used[key]; used {
			return nil // reported by nonce-unused
		}
		p, ok := v.pending[key]
		if !ok || p.ProofExpiresAt != req.Challenge.ProofExpiresAt || req.Challenge.VerifierID != v.verifierID {
			return ErrUnknownNonce
		}
		if p.PolicyHash != req.Policy.PolicyHash {
			return ErrPolicyNotChallenged
		}
		return nil
	})
	run.Do("nonce-unused", func() error {
		if _, used := v.used[key]; used {
			return ErrNonceConsumed
		}
		return nil
	})
	run.Do("proof-valid", func() error {
		if req.Proof == nil || req.Proof.Proof == nil {
			return fmt.Errorf("%w: missing proof", ErrInvalidProof)
		}
		nullifier = req.Proof.Statement.Nullifier
		if _, err := field.ToBig(nullifier); err != nil {
			return fmt.Errorf("%w: bad nullifier", ErrInvalidProof)
		}
		statement := passport.BuildStatement(req.Policy, req.Challenge, v.keyset, nullifier)
		return v.sys.Verify(req.Proof.Proof, statement)
	})

	if run.Err() != nil {
		return Decision{Checks: run.Checks()}, run.Err()
	}
	delete(v.pending, key)
	v.used[key] = struct{}{}
	return Decision{Authorized: true, Nullifier: nullifier, Checks: run.Checks()}, nil
}
