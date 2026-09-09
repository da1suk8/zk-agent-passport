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

// CheckStatus is the outcome of one check run by the gateway or a verifier.
type CheckStatus string

// Check outcomes.
const (
	CheckOK      CheckStatus = "ok"
	CheckFailed  CheckStatus = "fail"
	CheckSkipped CheckStatus = "skipped"
)

// Check is one check with its outcome.
type Check struct {
	Key    string
	Status CheckStatus
	Err    error
}

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
	var run checkRun
	var pub ed25519.PublicKey
	key := strings.Join([]string{
		r.IssuerID, r.PassportCommitment, r.AgentManifestCommitment, r.TaskDomain, aggregationEpoch,
	}, ":")

	run.do("issuer-registered", func() error {
		var ok bool
		if pub, ok = g.registry[r.IssuerID]; !ok {
			return fmt.Errorf("%w: %s", ErrIssuerNotRegistered, r.IssuerID)
		}
		return nil
	})
	run.do("receipt-signature", func() error {
		msg, err := r.signable()
		if err != nil {
			return err
		}
		if !VerifySignature(pub, msg, r.Signature) {
			return ErrReceiptSignature
		}
		return nil
	})
	run.do("receipt-unexpired", func() error {
		if r.ExpiresAt < now {
			return ErrReceiptExpired
		}
		return nil
	})
	run.do("rating-range", func() error {
		if r.Rating < RatingMin || r.Rating > RatingMax {
			return fmt.Errorf("%w: %d", ErrRatingRange, r.Rating)
		}
		return nil
	})
	run.do("receipt-unused", func() error {
		if _, used := g.usedReceiptIDs[r.ReceiptID]; used {
			return fmt.Errorf("%w: %s", ErrReceiptReused, r.ReceiptID)
		}
		return nil
	})
	run.do("issuer-once-per-epoch", func() error {
		if _, seen := g.issuerEpochKeys[key]; seen {
			return ErrIssuerAlreadyContributed
		}
		return nil
	})
	if run.err != nil {
		return ValidatedReceipt{}, run.checks, run.err
	}
	g.usedReceiptIDs[r.ReceiptID] = struct{}{}
	g.issuerEpochKeys[key] = struct{}{}
	return ValidatedReceipt{receipt: r, epoch: aggregationEpoch}, run.checks, nil
}

// checkRun executes checks in order and records their outcomes.
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
