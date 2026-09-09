// Package demo wires the fixed participants of the MVP together: three
// registered task providers, an input gateway, a three-node committee, one
// agent in the travel-booking domain, and one verifying service.
package demo

import (
	"fmt"

	"github.com/da1suk8/zk-agent-passport/field"
	"github.com/da1suk8/zk-agent-passport/passport"
	"github.com/da1suk8/zk-agent-passport/verifier"
	"github.com/da1suk8/zk-agent-passport/zkp"
)

// Fixed demo parameters, matching the project specification.
const (
	Now                 int64 = 1_800_000_000
	TaskDomain                = "1001"
	AggregationEpoch          = "202608"
	RequiredThreshold   int64 = 12
	MinimumReceiptCount int64 = 3
	VerifierName              = "travel-booking-service"
)

// Ratings issued by providers A, B, C. Their sum, 14, is never disclosed.
var Ratings = []int{5, 4, 5}

// Options customizes a demo world. Zero values fall back to the defaults
// from the specification.
type Options struct {
	// Ratings issued by providers A, B, C, in order. Each must be 1..5.
	Ratings []int
	// Manifest is the agent's configuration when the receipts were issued
	// and the certificate was bound.
	Manifest passport.Manifest
	// CurrentManifest is the configuration the agent declares to the service
	// at proof time. Nil means unchanged.
	CurrentManifest *passport.Manifest
	// VersionPolicy says which manifest changes the service tolerates. Nil
	// means DefaultVersionPolicy; use a pointer to an empty policy for strict.
	VersionPolicy *passport.ManifestVersionPolicy
	// RequiredThreshold and MinimumReceiptCount define the service policy.
	RequiredThreshold   int64
	MinimumReceiptCount int64
}

// DefaultManifest is the demo agent's configuration.
var DefaultManifest = passport.Manifest{
	ModelID:          "gpt-demo",
	SystemPromptHash: "travel-booking-v1",
	ToolPolicyHash:   "booking-tools-v1",
	PermissionScope:  "travel-booking",
}

// DefaultVersionPolicy lets the model and the system prompt move to listed
// newer versions, while the tool policy and permission scope must not
// change.
func DefaultVersionPolicy() passport.ManifestVersionPolicy {
	return passport.ManifestVersionPolicy{Allowed: map[int][]string{
		0: {"gpt-demo", "gpt-demo-v2"},
		1: {"travel-booking-v1", "travel-booking-v2"},
	}}
}

// DefaultOptions returns the specification's demo parameters.
func DefaultOptions() Options {
	return Options{
		Ratings:             append([]int(nil), Ratings...),
		Manifest:            DefaultManifest,
		RequiredThreshold:   RequiredThreshold,
		MinimumReceiptCount: MinimumReceiptCount,
	}
}

// World is a fully provisioned demo environment.
type World struct {
	Sys       *zkp.System
	Issuers   []*passport.Identity
	Committee []*passport.CommitteeNode
	Agent     *passport.Agent
	Receipts  []passport.Receipt
	Gateway   *passport.InputGateway
	Issued    passport.IssuedCertificate
	Policy    passport.PolicyBundle
	Verifier  *verifier.Verifier
	Options   Options
	// CertifiedManifest is the manifest the certificate was issued for.
	CertifiedManifest passport.Manifest
}

// NewWorld provisions the specification's demo world.
func NewWorld(sys *zkp.System) (*World, error) {
	return NewWorldWith(sys, DefaultOptions())
}

// NewWorldWith provisions participants, issues receipts, aggregates them,
// and prepares the service policy according to opts.
func NewWorldWith(sys *zkp.System, opts Options) (*World, error) {
	defaults := DefaultOptions()
	if len(opts.Ratings) == 0 {
		opts.Ratings = defaults.Ratings
	}
	if opts.Manifest == (passport.Manifest{}) {
		opts.Manifest = defaults.Manifest
	}
	if opts.RequiredThreshold == 0 {
		opts.RequiredThreshold = defaults.RequiredThreshold
	}
	if opts.MinimumReceiptCount == 0 {
		opts.MinimumReceiptCount = defaults.MinimumReceiptCount
	}
	if len(opts.Ratings) > 3 {
		return nil, fmt.Errorf("demo supports at most three providers, got %d ratings", len(opts.Ratings))
	}
	if opts.VersionPolicy == nil {
		vp := DefaultVersionPolicy()
		opts.VersionPolicy = &vp
	}
	w := &World{Sys: sys, Options: opts, CertifiedManifest: opts.Manifest}
	for _, name := range []string{"provider-a", "provider-b", "provider-c"} {
		id, err := passport.NewIdentity(name)
		if err != nil {
			return nil, err
		}
		w.Issuers = append(w.Issuers, id)
	}
	for _, name := range []string{"committee-1", "committee-2", "committee-3"} {
		node, err := passport.NewCommitteeNode(name)
		if err != nil {
			return nil, err
		}
		w.Committee = append(w.Committee, node)
	}
	agent, err := passport.NewAgent(opts.Manifest)
	if err != nil {
		return nil, err
	}
	w.Agent = agent

	for i, rating := range opts.Ratings {
		r, err := passport.IssueReceipt(w.Issuers[i], agent, passport.ReceiptRequest{
			ReceiptID:  fmt.Sprintf("receipt-%d", i+1),
			TaskDomain: TaskDomain,
			Rating:     rating,
			IssuedAt:   Now - 30,
			ExpiresAt:  Now + 3_600,
		})
		if err != nil {
			return nil, err
		}
		w.Receipts = append(w.Receipts, r)
	}

	w.Gateway = passport.NewInputGateway(passport.NewIssuerRegistry(w.Issuers...))
	for _, r := range w.Receipts {
		if err := w.Gateway.ValidateReceipt(r, AggregationEpoch, Now); err != nil {
			return nil, err
		}
	}
	issued, err := passport.IssueScoreCertificate(w.Committee, passport.AggregationRequest{
		Receipts:         w.Receipts,
		AggregationEpoch: AggregationEpoch,
		IssuedAt:         Now,
		ExpiresAt:        Now + 900,
	})
	if err != nil {
		return nil, err
	}
	w.Issued = issued

	// The agent may have changed its configuration since the certificate
	// was issued. The service asks about the current manifest.
	if opts.CurrentManifest != nil {
		if err := agent.UpdateManifest(*opts.CurrentManifest); err != nil {
			return nil, err
		}
	}
	w.Policy, err = passport.NewPolicy(passport.PolicyRequest{
		RequiredThreshold:           opts.RequiredThreshold,
		MinimumReceiptCount:         opts.MinimumReceiptCount,
		RequestedTaskDomain:         TaskDomain,
		RequestedManifestCommitment: agent.AgentManifestCommitment,
		RequestedAggregationEpoch:   AggregationEpoch,
		ManifestVersionPolicy:       *opts.VersionPolicy,
	})
	if err != nil {
		return nil, err
	}

	var committeePublic []passport.PublicIdentity
	for _, node := range w.Committee {
		committeePublic = append(committeePublic, node.Public())
	}
	w.Verifier = verifier.New(sys, committeePublic)
	return w, nil
}

// BatchKey identifies the aggregation batch of the world's certificate. It
// uses the certificate's own commitments, which stay fixed even after the
// agent updates its manifest.
func (w *World) BatchKey() string {
	c := w.Issued.Certificate
	return passport.BatchKey(c.PassportCommitment, c.AgentManifestCommitment, c.TaskDomain, c.AggregationEpoch)
}

// NewChallenge issues a challenge from the demo service.
func (w *World) NewChallenge() (passport.Challenge, error) {
	return passport.NewChallenge(VerifierName, Now, passport.DefaultChallengeTTL)
}

// Prove generates the agent's proof for the world's certificate and policy.
func (w *World) Prove(ch passport.Challenge) (*passport.ProofPackage, error) {
	return w.ProveWith(ch, w.Policy, w.Issued)
}

// ProveWith generates a proof for an alternative policy or certificate.
func (w *World) ProveWith(ch passport.Challenge, policy passport.PolicyBundle, issued passport.IssuedCertificate) (*passport.ProofPackage, error) {
	return passport.Prove(w.Sys, passport.ProofRequest{
		Agent:             w.Agent,
		CertifiedManifest: w.CertifiedManifest,
		Issued:            issued,
		Policy:            policy,
		Challenge:         ch,
	})
}

// Access submits a proof to the verifier at the demo time.
func (w *World) Access(ch passport.Challenge, pkg *passport.ProofPackage) (verifier.Decision, error) {
	return w.AccessAt(ch, pkg, Now)
}

// AccessAt submits a proof to the verifier at a chosen time.
func (w *World) AccessAt(ch passport.Challenge, pkg *passport.ProofPackage, now int64) (verifier.Decision, error) {
	return w.Verifier.VerifyAccess(verifier.AccessRequest{
		Certificate: w.Issued.Certificate,
		Policy:      w.Policy,
		Challenge:   ch,
		Proof:       pkg,
		Now:         now,
	})
}

// ForeignManifestPolicy is the world's policy bound to a manifest the agent
// cannot open.
func (w *World) ForeignManifestPolicy() (passport.PolicyBundle, error) {
	return passport.NewPolicy(passport.PolicyRequest{
		RequiredThreshold:           RequiredThreshold,
		MinimumReceiptCount:         MinimumReceiptCount,
		RequestedTaskDomain:         TaskDomain,
		RequestedManifestCommitment: field.FromText("some-other-manifest"),
		RequestedAggregationEpoch:   AggregationEpoch,
		ManifestVersionPolicy:       *w.Options.VersionPolicy,
	})
}

// StricterPolicy is the world's policy with a threshold the agent cannot meet.
func (w *World) StricterPolicy(threshold int64) (passport.PolicyBundle, error) {
	return passport.NewPolicy(passport.PolicyRequest{
		RequiredThreshold:           threshold,
		MinimumReceiptCount:         MinimumReceiptCount,
		RequestedTaskDomain:         TaskDomain,
		RequestedManifestCommitment: w.Agent.AgentManifestCommitment,
		RequestedAggregationEpoch:   AggregationEpoch,
		ManifestVersionPolicy:       *w.Options.VersionPolicy,
	})
}
