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
	v, _, err := g.ValidateReceiptReport(r, aggregationEpoch, now)
	return v, err
}

// ValidateReceiptReport is ValidateReceipt with the outcome of every check
// in the order of GatewayChecks. The gateway stops at the first failure and
// reports the rest as skipped.
func (g *InputGateway) ValidateReceiptReport(r Receipt, aggregationEpoch field.Element, now int64) (ValidatedReceipt, []Check, error) {
	var run CheckRun
	var pub ed25519.PublicKey
	key := issuerEpochKey(r, aggregationEpoch)

	run.Do("issuer-registered", func() error {
		var ok bool
		if pub, ok = g.registry[r.IssuerID]; !ok {
			return fmt.Errorf("%w: %s", ErrIssuerNotRegistered, r.IssuerID)
		}
		return nil
	})
	run.Do("receipt-signature", func() error {
		msg, err := r.signable()
		if err != nil {
			return err
		}
		if !VerifySignature(pub, msg, r.Signature) {
			return ErrReceiptSignature
		}
		return nil
	})
	run.Do("receipt-unexpired", func() error {
		if r.ExpiresAt < now {
			return ErrReceiptExpired
		}
		return nil
	})
	run.Do("rating-range", func() error {
		if r.Rating < RatingMin || r.Rating > RatingMax {
			return fmt.Errorf("%w: %d", ErrRatingRange, r.Rating)
		}
		return nil
	})
	run.Do("receipt-unused", func() error {
		if _, used := g.usedReceiptIDs[r.ReceiptID]; used {
			return fmt.Errorf("%w: %s", ErrReceiptReused, r.ReceiptID)
		}
		return nil
	})
	run.Do("issuer-once-per-epoch", func() error {
		if _, seen := g.issuerEpochKeys[key]; seen {
			return ErrIssuerAlreadyContributed
		}
		return nil
	})
	if run.Err() != nil {
		return ValidatedReceipt{}, run.Checks(), run.Err()
	}
	g.usedReceiptIDs[r.ReceiptID] = struct{}{}
	g.issuerEpochKeys[key] = struct{}{}
	return ValidatedReceipt{receipt: r, epoch: aggregationEpoch}, run.Checks(), nil
}

// issuerEpochKey names the slot an issuer may fill exactly once: one issuer,
// one passport, one manifest, one domain, one epoch.
func issuerEpochKey(r Receipt, aggregationEpoch field.Element) string {
	return strings.Join([]string{
		r.IssuerID, r.PassportCommitment, r.AgentManifestCommitment, r.TaskDomain, aggregationEpoch,
	}, ":")
}
