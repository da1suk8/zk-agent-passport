package passport

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/da1suk8/zk-agent-passport/field"
)

// Gateway validation failures.
var (
	ErrIssuerNotRegistered      = errors.New("receipt issuer is not registered")
	ErrReceiptSignature         = errors.New("receipt signature is invalid")
	ErrReceiptExpired           = errors.New("receipt is expired")
	ErrReceiptReused            = errors.New("receipt has already been aggregated")
	ErrIssuerAlreadyContributed = errors.New("issuer already contributed to this passport, domain, and epoch")
)

// GatewayChecks names the gateway's checks, in the order they run. User
// interfaces may map these keys to labels; the order is owned here.
var GatewayChecks = []string{
	"issuer-registered",
	"receipt-signature",
	"receipt-unexpired",
	"rating-range",
	"receipt-unused",
	"issuer-once-per-epoch",
}

// ValidatedReceipt is a receipt that passed every gateway check for a given
// aggregation epoch. Only the gateway can create one, so the committee can
// require it and never aggregate an unchecked receipt.
type ValidatedReceipt struct {
	receipt Receipt
	epoch   field.Element
}

// Receipt returns the underlying receipt.
func (v ValidatedReceipt) Receipt() Receipt { return v.receipt }

// AggregationEpoch returns the epoch the receipt was validated for.
func (v ValidatedReceipt) AggregationEpoch() field.Element { return v.epoch }

// IssuerRegistry is the fixed set of providers allowed to issue receipts.
type IssuerRegistry map[string]ed25519.PublicKey

// NewIssuerRegistry builds a registry from provider identities.
func NewIssuerRegistry(issuers ...*Identity) IssuerRegistry {
	reg := make(IssuerRegistry, len(issuers))
	for _, id := range issuers {
		reg[id.NodeID] = id.PublicKey
	}
	return reg
}

// InputGateway validates receipts before their ratings are secret-shared to
// the committee. It sees plaintext ratings; the MPC protects ratings from the
// committee nodes, not from the gateway.
type InputGateway struct {
	registry        IssuerRegistry
	usedReceiptIDs  map[string]struct{}
	issuerEpochKeys map[string]struct{}
}

// NewInputGateway creates a gateway bound to a registry.
func NewInputGateway(registry IssuerRegistry) *InputGateway {
	return &InputGateway{
		registry:        registry,
		usedReceiptIDs:  map[string]struct{}{},
		issuerEpochKeys: map[string]struct{}{},
	}
}

// ValidateReceipt applies every gateway check, records the receipt as
// consumed, and returns it as validated for the epoch. A receipt that fails
// any check leaves no state behind.
func (g *InputGateway) ValidateReceipt(r Receipt, aggregationEpoch field.Element, now int64) (ValidatedReceipt, error) {
	pub, ok := g.registry[r.IssuerID]
	if !ok {
		return ValidatedReceipt{}, fmt.Errorf("%w: %s", ErrIssuerNotRegistered, r.IssuerID)
	}
	msg, err := r.signable()
	if err != nil {
		return ValidatedReceipt{}, err
	}
	if !VerifySignature(pub, msg, r.Signature) {
		return ValidatedReceipt{}, ErrReceiptSignature
	}
	if r.ExpiresAt < now {
		return ValidatedReceipt{}, ErrReceiptExpired
	}
	if r.Rating < RatingMin || r.Rating > RatingMax {
		return ValidatedReceipt{}, fmt.Errorf("%w: %d", ErrRatingRange, r.Rating)
	}
	if _, used := g.usedReceiptIDs[r.ReceiptID]; used {
		return ValidatedReceipt{}, fmt.Errorf("%w: %s", ErrReceiptReused, r.ReceiptID)
	}
	key := strings.Join([]string{
		r.IssuerID, r.PassportCommitment, r.AgentManifestCommitment, r.TaskDomain, aggregationEpoch,
	}, ":")
	if _, seen := g.issuerEpochKeys[key]; seen {
		return ValidatedReceipt{}, ErrIssuerAlreadyContributed
	}
	g.usedReceiptIDs[r.ReceiptID] = struct{}{}
	g.issuerEpochKeys[key] = struct{}{}
	return ValidatedReceipt{receipt: r, epoch: aggregationEpoch}, nil
}

// ShareRating splits a rating into three additive shares over the field:
// rating = s1 + s2 + s3. Any two shares reveal nothing about the rating.
func ShareRating(rating int) ([3]field.Element, error) {
	var shares [3]field.Element
	var err error
	if shares[0], err = field.Random(); err != nil {
		return shares, err
	}
	if shares[1], err = field.Random(); err != nil {
		return shares, err
	}
	rest, err := field.Sub(field.FromInt(int64(rating)), shares[0])
	if err != nil {
		return shares, err
	}
	if shares[2], err = field.Sub(rest, shares[1]); err != nil {
		return shares, err
	}
	return shares, nil
}
