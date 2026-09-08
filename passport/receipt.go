package passport

import (
	"errors"
	"fmt"

	"github.com/da1suk8/zk-agent-passport/field"
)

// Rating bounds accepted by the protocol.
const (
	RatingMin = 1
	RatingMax = 5
)

// ErrRatingRange is returned for a rating outside [RatingMin, RatingMax].
var ErrRatingRange = errors.New("receipt rating is outside the permitted range")

// Receipt is a signed statement by a registered task provider that an agent
// completed a task in a domain with a given rating.
type Receipt struct {
	ReceiptID               string        `json:"receiptId"`
	PassportCommitment      field.Element `json:"passportCommitment"`
	AgentManifestCommitment field.Element `json:"agentManifestCommitment"`
	TaskDomain              field.Element `json:"taskDomain"`
	Rating                  int           `json:"rating"`
	IssuedAt                int64         `json:"issuedAt"`
	ExpiresAt               int64         `json:"expiresAt"`
	IssuerID                string        `json:"issuerId"`
	Signature               string        `json:"signature,omitempty"`
}

// ReceiptRequest carries the inputs a provider uses to issue a receipt.
type ReceiptRequest struct {
	ReceiptID  string
	TaskDomain field.Element
	Rating     int
	IssuedAt   int64
	ExpiresAt  int64
}

// IssueReceipt signs a receipt for the agent's passport and manifest.
func IssueReceipt(issuer *Identity, agent *Agent, req ReceiptRequest) (Receipt, error) {
	if req.Rating < RatingMin || req.Rating > RatingMax {
		return Receipt{}, fmt.Errorf("%w: %d", ErrRatingRange, req.Rating)
	}
	r := Receipt{
		ReceiptID:               req.ReceiptID,
		PassportCommitment:      agent.PassportCommitment,
		AgentManifestCommitment: agent.AgentManifestCommitment,
		TaskDomain:              req.TaskDomain,
		Rating:                  req.Rating,
		IssuedAt:                req.IssuedAt,
		ExpiresAt:               req.ExpiresAt,
		IssuerID:                issuer.NodeID,
	}
	msg, err := r.signable()
	if err != nil {
		return Receipt{}, err
	}
	r.Signature = issuer.Sign(msg)
	return r, nil
}

// signable is the canonical payload without the signature.
func (r Receipt) signable() ([]byte, error) {
	r.Signature = ""
	return Canonicalize(r)
}
