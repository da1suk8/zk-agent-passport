// Package verifier implements the service-side checks. With the certificate
// hidden inside the proof, the verifier's own work shrinks to: the proof is
// still valid in time, the policy is the one it published, the nonce is one
// it issued and has not consumed, and the proof verifies against a
// statement it rebuilds itself.
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
	ErrProofExpired  = errors.New("proof is expired")
	ErrPolicyHash    = errors.New("policy hash does not match the policy")
	ErrUnknownNonce  = errors.New("nonce was not issued by this verifier")
	ErrNonceConsumed = errors.New("nonce has already been consumed")
	ErrInvalidProof  = zkp.ErrInvalidProof
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
// verifier handed out.
type Verifier struct {
	sys        *zkp.System
	name       string
	verifierID field.Element
	ttl        int64
	keyset     passport.CommitteeKeyset
	pending    map[string]field.Element // nonce key -> proofExpiresAt
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
		pending:    map[string]field.Element{},
		used:       map[string]struct{}{},
	}
}

// Keyset returns the committee keyset this verifier trusts; agents need it
// to build the statement they prove.
func (v *Verifier) Keyset() passport.CommitteeKeyset {
	return v.keyset
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

// AccessRequest is what an agent submits: the proof and its statement. No
// certificate travels with it.
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
	now := field.FromInt(req.Now)
	var run checkRun
	var nullifier field.Element

	run.do("proof-unexpired", func() error {
		expired, err := field.Less(req.Challenge.ProofExpiresAt, now)
		if err != nil {
			return err
		}
		if expired {
			return ErrProofExpired
		}
		return nil
	})
	run.do("policy-hash", func() error {
		expected, err := passport.PolicyHash(req.Policy.Policy)
		if err != nil {
			return err
		}
		if expected != req.Policy.PolicyHash {
			return ErrPolicyHash
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
		nullifier = req.Proof.Statement.Nullifier
		if _, err := field.ToBig(nullifier); err != nil {
			return fmt.Errorf("%w: bad nullifier", ErrInvalidProof)
		}
		statement := passport.BuildStatement(req.Policy, req.Challenge, v.keyset, nullifier)
		return v.sys.Verify(req.Proof.Proof, statement)
	})

	if run.err != nil {
		return Decision{Checks: run.checks}, run.err
	}
	delete(v.pending, key)
	v.used[key] = struct{}{}
	return Decision{Authorized: true, Nullifier: nullifier, Checks: run.checks}, nil
}
