package passport

import (
	"errors"
	"fmt"
	"strings"

	"github.com/da1suk8/zk-agent-passport/field"
)

// CommitteeKeysetID identifies the committee key set used by this MVP.
const CommitteeKeysetID field.Element = "1"

// Quorum is the number of distinct committee signatures a certificate needs.
const Quorum = 2

// Committee errors.
var (
	ErrEmptyBatch     = errors.New("at least one receipt is required")
	ErrBatchMismatch  = errors.New("receipt does not match aggregation batch")
	ErrCommitteeSmall = errors.New("committee needs at least three nodes")
)

// CommitteeNode holds one additive share of every rating in a batch and only
// ever sees its own partial sum.
type CommitteeNode struct {
	*Identity
	partials map[string]field.Element
}

// NewCommitteeNode creates a committee node with a fresh signing key.
func NewCommitteeNode(nodeID string) (*CommitteeNode, error) {
	id, err := NewIdentity(nodeID)
	if err != nil {
		return nil, err
	}
	return &CommitteeNode{Identity: id, partials: map[string]field.Element{}}, nil
}

// Accumulate adds a share to the node's partial sum for a batch.
func (n *CommitteeNode) Accumulate(batchKey string, share field.Element) error {
	current, ok := n.partials[batchKey]
	if !ok {
		current = "0"
	}
	sum, err := field.Add(current, share)
	if err != nil {
		return err
	}
	n.partials[batchKey] = sum
	return nil
}

// PartialSum returns the node's share of the batch total.
func (n *CommitteeNode) PartialSum(batchKey string) field.Element {
	if v, ok := n.partials[batchKey]; ok {
		return v
	}
	return "0"
}

// BatchKey names one aggregation batch: one passport, one manifest, one
// domain, one epoch.
func BatchKey(passportCommitment, manifestCommitment, taskDomain, aggregationEpoch field.Element) string {
	return strings.Join([]string{passportCommitment, manifestCommitment, taskDomain, aggregationEpoch}, ":")
}

// CertificatePayload is the signed content of a score certificate. The score
// itself appears only as a hiding commitment.
type CertificatePayload struct {
	CertificateID           field.Element `json:"certificateId"`
	PassportCommitment      field.Element `json:"passportCommitment"`
	AgentManifestCommitment field.Element `json:"agentManifestCommitment"`
	TaskDomain              field.Element `json:"taskDomain"`
	AggregationEpoch        field.Element `json:"aggregationEpoch"`
	ScoreCommitment         field.Element `json:"scoreCommitment"`
	ReceiptCount            field.Element `json:"receiptCount"`
	IssuedAt                field.Element `json:"issuedAt"`
	ExpiresAt               field.Element `json:"expiresAt"`
	CommitteeKeysetID       field.Element `json:"committeeKeysetId"`
}

// CommitteeSignature is one node's signature over the certificate hash.
type CommitteeSignature struct {
	NodeID    string `json:"nodeId"`
	Signature string `json:"signature"`
}

// ScoreCertificate is a payload plus a quorum of committee signatures.
type ScoreCertificate struct {
	CertificatePayload
	Signatures []CommitteeSignature `json:"signatures"`
}

// CertificatePresentation is what the agent shows a verifier: the
// certificate hash, the committee signatures over it, and the certificate
// fields the verifier needs. The receipt count is withheld; the proof shows
// that the hash opens to a count meeting the policy's minimum, and that the
// presented fields are the ones behind the hash.
type CertificatePresentation struct {
	CertificateHash         field.Element        `json:"certificateHash"`
	CertificateID           field.Element        `json:"certificateId"`
	PassportCommitment      field.Element        `json:"passportCommitment"`
	AgentManifestCommitment field.Element        `json:"agentManifestCommitment"`
	TaskDomain              field.Element        `json:"taskDomain"`
	AggregationEpoch        field.Element        `json:"aggregationEpoch"`
	ScoreCommitment         field.Element        `json:"scoreCommitment"`
	IssuedAt                field.Element        `json:"issuedAt"`
	ExpiresAt               field.Element        `json:"expiresAt"`
	CommitteeKeysetID       field.Element        `json:"committeeKeysetId"`
	Signatures              []CommitteeSignature `json:"signatures"`
}

// Present redacts the certificate for a verifier.
func (c ScoreCertificate) Present() (CertificatePresentation, error) {
	hash, err := CertificateHash(c.CertificatePayload)
	if err != nil {
		return CertificatePresentation{}, err
	}
	return CertificatePresentation{
		CertificateHash:         hash,
		CertificateID:           c.CertificateID,
		PassportCommitment:      c.PassportCommitment,
		AgentManifestCommitment: c.AgentManifestCommitment,
		TaskDomain:              c.TaskDomain,
		AggregationEpoch:        c.AggregationEpoch,
		ScoreCommitment:         c.ScoreCommitment,
		IssuedAt:                c.IssuedAt,
		ExpiresAt:               c.ExpiresAt,
		CommitteeKeysetID:       c.CommitteeKeysetID,
		Signatures:              append([]CommitteeSignature(nil), c.Signatures...),
	}, nil
}

// IssuedCertificate is what the passport holder receives over an
// authenticated channel: the certificate and the opening of its score
// commitment.
type IssuedCertificate struct {
	Certificate ScoreCertificate
	Score       field.Element
	ScoreSalt   field.Element
}

// CertificateHash is the Poseidon2 hash of the payload fields, in the order
// the circuit absorbs them.
func CertificateHash(p CertificatePayload) (field.Element, error) {
	return field.Hash(
		p.CertificateID,
		p.PassportCommitment,
		p.AgentManifestCommitment,
		p.TaskDomain,
		p.AggregationEpoch,
		p.ScoreCommitment,
		p.ReceiptCount,
		p.IssuedAt,
		p.ExpiresAt,
		p.CommitteeKeysetID,
	)
}

// AggregationRequest describes one certificate issuance. Only receipts the
// gateway validated for the same epoch can be aggregated.
type AggregationRequest struct {
	Receipts         []ValidatedReceipt
	AggregationEpoch field.Element
	IssuedAt         int64
	ExpiresAt        int64
}

// IssueScoreCertificate runs the aggregation for one batch of validated
// receipts: each rating is secret-shared to the committee, every node sums its
// shares, the partial sums are combined into the score, and a quorum of nodes
// signs a certificate over the score commitment.
func IssueScoreCertificate(committee []*CommitteeNode, req AggregationRequest) (IssuedCertificate, error) {
	if len(committee) < 3 {
		return IssuedCertificate{}, ErrCommitteeSmall
	}
	if len(req.Receipts) == 0 {
		return IssuedCertificate{}, ErrEmptyBatch
	}
	first := req.Receipts[0].Receipt()
	for _, v := range req.Receipts {
		r := v.Receipt()
		if v.AggregationEpoch() != req.AggregationEpoch {
			return IssuedCertificate{}, fmt.Errorf("%w: %s validated for epoch %s", ErrBatchMismatch, r.ReceiptID, v.AggregationEpoch())
		}
		if r.PassportCommitment != first.PassportCommitment ||
			r.AgentManifestCommitment != first.AgentManifestCommitment ||
			r.TaskDomain != first.TaskDomain {
			return IssuedCertificate{}, fmt.Errorf("%w: %s", ErrBatchMismatch, r.ReceiptID)
		}
	}
	batchKey := BatchKey(first.PassportCommitment, first.AgentManifestCommitment, first.TaskDomain, req.AggregationEpoch)

	// Secret-share every rating; node i only ever receives share i.
	for _, v := range req.Receipts {
		shares, err := ShareRating(v.Receipt().Rating)
		if err != nil {
			return IssuedCertificate{}, err
		}
		for i := 0; i < 3; i++ {
			if err := committee[i].Accumulate(batchKey, shares[i]); err != nil {
				return IssuedCertificate{}, err
			}
		}
	}

	// Reconstruct the score from the partial sums. Individual ratings are
	// never reconstructed, only their total.
	score := field.Element("0")
	for i := 0; i < 3; i++ {
		var err error
		if score, err = field.Add(score, committee[i].PartialSum(batchKey)); err != nil {
			return IssuedCertificate{}, err
		}
	}

	scoreSalt, err := field.Random()
	if err != nil {
		return IssuedCertificate{}, err
	}
	scoreCommitment, err := field.Commit(score, scoreSalt)
	if err != nil {
		return IssuedCertificate{}, err
	}
	certificateID, err := field.Random()
	if err != nil {
		return IssuedCertificate{}, err
	}
	payload := CertificatePayload{
		CertificateID:           certificateID,
		PassportCommitment:      first.PassportCommitment,
		AgentManifestCommitment: first.AgentManifestCommitment,
		TaskDomain:              first.TaskDomain,
		AggregationEpoch:        req.AggregationEpoch,
		ScoreCommitment:         scoreCommitment,
		ReceiptCount:            field.FromInt(int64(len(req.Receipts))),
		IssuedAt:                field.FromInt(req.IssuedAt),
		ExpiresAt:               field.FromInt(req.ExpiresAt),
		CommitteeKeysetID:       CommitteeKeysetID,
	}
	hash, err := CertificateHash(payload)
	if err != nil {
		return IssuedCertificate{}, err
	}
	msg, err := field.Bytes(hash)
	if err != nil {
		return IssuedCertificate{}, err
	}
	cert := ScoreCertificate{CertificatePayload: payload}
	for _, node := range committee[:Quorum] {
		cert.Signatures = append(cert.Signatures, CommitteeSignature{
			NodeID:    node.NodeID,
			Signature: node.Sign(msg),
		})
	}
	return IssuedCertificate{Certificate: cert, Score: score, ScoreSalt: scoreSalt}, nil
}
