package passport

import (
	"errors"
	"fmt"

	"github.com/da1suk8/zk-agent-passport/field"
)

// ErrPolicyInconsistent is returned when a published policy, its hash, and
// its version policy do not agree.
var ErrPolicyInconsistent = errors.New("policy, policy hash, and version policy are inconsistent")

// Policy is a service's access condition. Its hash is a public input of the
// proof, so a proof for one policy cannot be reused for another.
type Policy struct {
	PolicyVersion               field.Element `json:"policyVersion"`
	RequiredThreshold           field.Element `json:"requiredThreshold"`
	MinimumReceiptCount         field.Element `json:"minimumReceiptCount"`
	RequestedTaskDomain         field.Element `json:"requestedTaskDomain"`
	RequestedManifestCommitment field.Element `json:"requestedManifestCommitment"`
	RequestedAggregationEpoch   field.Element `json:"requestedAggregationEpoch"`
	// ManifestMutableMask and ManifestAllowlistRoot encode the manifest
	// version policy: which fields may differ from the certified manifest,
	// and the Merkle root of the values they may take.
	ManifestMutableMask   field.Element `json:"manifestMutableMask"`
	ManifestAllowlistRoot field.Element `json:"manifestAllowlistRoot"`
}

// PolicyBundle is a policy with its hash and the published allowlist the
// prover needs to build Merkle paths.
type PolicyBundle struct {
	Policy        Policy
	PolicyHash    field.Element
	VersionPolicy ManifestVersionPolicy
	Allowlist     *ManifestAllowlist
}

// PolicyRequest carries the service's requirements. A zero
// ManifestVersionPolicy permits no manifest change.
type PolicyRequest struct {
	RequiredThreshold           int64
	MinimumReceiptCount         int64
	RequestedTaskDomain         field.Element
	RequestedManifestCommitment field.Element
	RequestedAggregationEpoch   field.Element
	ManifestVersionPolicy       ManifestVersionPolicy
}

// NewPolicy builds a versioned policy, its allowlist, and its hash.
func NewPolicy(req PolicyRequest) (PolicyBundle, error) {
	allowlist, err := BuildManifestAllowlist(req.ManifestVersionPolicy)
	if err != nil {
		return PolicyBundle{}, err
	}
	p := Policy{
		PolicyVersion:               "2",
		RequiredThreshold:           field.FromInt(req.RequiredThreshold),
		MinimumReceiptCount:         field.FromInt(req.MinimumReceiptCount),
		RequestedTaskDomain:         req.RequestedTaskDomain,
		RequestedManifestCommitment: req.RequestedManifestCommitment,
		RequestedAggregationEpoch:   req.RequestedAggregationEpoch,
		ManifestMutableMask:         field.FromInt(req.ManifestVersionPolicy.Mask()),
		ManifestAllowlistRoot:       allowlist.Root,
	}
	hash, err := PolicyHash(p)
	if err != nil {
		return PolicyBundle{}, err
	}
	return PolicyBundle{Policy: p, PolicyHash: hash, VersionPolicy: req.ManifestVersionPolicy, Allowlist: allowlist}, nil
}

// PolicyHash hashes the policy fields in the order the circuit absorbs them.
func PolicyHash(p Policy) (field.Element, error) {
	return field.Hash(
		p.PolicyVersion,
		p.RequiredThreshold,
		p.MinimumReceiptCount,
		p.RequestedTaskDomain,
		p.RequestedManifestCommitment,
		p.RequestedAggregationEpoch,
		p.ManifestMutableMask,
		p.ManifestAllowlistRoot,
	)
}

// RebuildPolicy reconstructs a bundle from the parts a service publishes:
// the policy, its hash, and the version policy behind the allowlist root.
// It fails if the parts do not agree, so a prover never works from a
// tampered or mismatched policy.
func RebuildPolicy(p Policy, hash field.Element, vp ManifestVersionPolicy) (PolicyBundle, error) {
	allowlist, err := BuildManifestAllowlist(vp)
	if err != nil {
		return PolicyBundle{}, err
	}
	if p.ManifestAllowlistRoot != allowlist.Root || p.ManifestMutableMask != field.FromInt(vp.Mask()) {
		return PolicyBundle{}, fmt.Errorf("%w: version policy", ErrPolicyInconsistent)
	}
	computed, err := PolicyHash(p)
	if err != nil {
		return PolicyBundle{}, err
	}
	if computed != hash {
		return PolicyBundle{}, fmt.Errorf("%w: hash", ErrPolicyInconsistent)
	}
	return PolicyBundle{Policy: p, PolicyHash: hash, VersionPolicy: vp, Allowlist: allowlist}, nil
}
