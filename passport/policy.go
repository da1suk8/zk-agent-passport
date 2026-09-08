package passport

import "github.com/da1suk8/zk-agent-passport/field"

// Policy is a service's access condition. Its hash is a public input of the
// proof, so a proof for one policy cannot be reused for another.
type Policy struct {
	PolicyVersion               field.Element `json:"policyVersion"`
	RequiredThreshold           field.Element `json:"requiredThreshold"`
	MinimumReceiptCount         field.Element `json:"minimumReceiptCount"`
	RequestedTaskDomain         field.Element `json:"requestedTaskDomain"`
	RequestedManifestCommitment field.Element `json:"requestedManifestCommitment"`
	RequestedAggregationEpoch   field.Element `json:"requestedAggregationEpoch"`
}

// PolicyBundle is a policy with its hash.
type PolicyBundle struct {
	Policy     Policy
	PolicyHash field.Element
}

// PolicyRequest carries the service's requirements.
type PolicyRequest struct {
	RequiredThreshold           int64
	MinimumReceiptCount         int64
	RequestedTaskDomain         field.Element
	RequestedManifestCommitment field.Element
	RequestedAggregationEpoch   field.Element
}

// NewPolicy builds a versioned policy and its hash.
func NewPolicy(req PolicyRequest) (PolicyBundle, error) {
	p := Policy{
		PolicyVersion:               "1",
		RequiredThreshold:           field.FromInt(req.RequiredThreshold),
		MinimumReceiptCount:         field.FromInt(req.MinimumReceiptCount),
		RequestedTaskDomain:         req.RequestedTaskDomain,
		RequestedManifestCommitment: req.RequestedManifestCommitment,
		RequestedAggregationEpoch:   req.RequestedAggregationEpoch,
	}
	hash, err := PolicyHash(p)
	if err != nil {
		return PolicyBundle{}, err
	}
	return PolicyBundle{Policy: p, PolicyHash: hash}, nil
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
	)
}
