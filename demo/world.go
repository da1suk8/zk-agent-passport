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
}

// NewWorld provisions participants, issues receipts, aggregates them, and
// prepares the service policy.
func NewWorld(sys *zkp.System) (*World, error) {
	w := &World{Sys: sys}
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
	agent, err := passport.NewAgent(passport.Manifest{
		ModelID:          "gpt-demo",
		SystemPromptHash: "travel-booking-v1",
		ToolPolicyHash:   "booking-tools-v1",
		PermissionScope:  "travel-booking",
	})
	if err != nil {
		return nil, err
	}
	w.Agent = agent

	for i, rating := range Ratings {
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

	w.Policy, err = passport.NewPolicy(passport.PolicyRequest{
		RequiredThreshold:           RequiredThreshold,
		MinimumReceiptCount:         MinimumReceiptCount,
		RequestedTaskDomain:         TaskDomain,
		RequestedManifestCommitment: agent.AgentManifestCommitment,
		RequestedAggregationEpoch:   AggregationEpoch,
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
		Agent:     w.Agent,
		Issued:    issued,
		Policy:    policy,
		Challenge: ch,
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

// ManifestMismatchPolicy is the world's policy bound to a different manifest.
func (w *World) ManifestMismatchPolicy() (passport.PolicyBundle, error) {
	return passport.NewPolicy(passport.PolicyRequest{
		RequiredThreshold:           RequiredThreshold,
		MinimumReceiptCount:         MinimumReceiptCount,
		RequestedTaskDomain:         TaskDomain,
		RequestedManifestCommitment: field.FromText("some-other-manifest"),
		RequestedAggregationEpoch:   AggregationEpoch,
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
	})
}
