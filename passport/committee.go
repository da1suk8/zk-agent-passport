package passport

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"

	"github.com/da1suk8/zk-agent-passport/field"
	"github.com/da1suk8/zk-agent-passport/zkp"
)

// CommitteeKeysetID identifies the committee key set used by this MVP.
const CommitteeKeysetID field.Element = "1"

// CommitteeSize and Quorum mirror the circuit: a keyset has CommitteeSize
// nodes and a certificate needs Quorum distinct signatures.
const (
	CommitteeSize = zkp.CommitteeSize
	Quorum        = zkp.Quorum
)

// Committee errors.
var (
	ErrEmptyBatch         = errors.New("at least one receipt is required")
	ErrBatchMismatch      = errors.New("receipt does not match aggregation batch")
	ErrBatchAlreadyIssued = errors.New("a certificate was already issued for this aggregation batch")
	ErrKeysetSize         = errors.New("a committee keyset needs exactly three nodes")
)

// CommitteeNode holds one additive share of every rating in a batch and
// signs certificates with an EdDSA key on BabyJubJub, which the passport
// circuit can verify. A node is not safe for concurrent use: its partial sums
// are a plain map.
type CommitteeNode struct {
	NodeID    string
	PublicKey []byte // compressed EdDSA public key
	private   *eddsa.PrivateKey
	partials  map[string]field.Element
}

// NewCommitteeNode creates a committee node with a fresh signing key.
func NewCommitteeNode(nodeID string) (*CommitteeNode, error) {
	key, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("committee node %s: %w", nodeID, err)
	}
	return &CommitteeNode{
		NodeID:    nodeID,
		PublicKey: key.PublicKey.Bytes(),
		private:   key,
		partials:  map[string]field.Element{},
	}, nil
}

// Public returns the node's shareable key.
func (n *CommitteeNode) Public() CommitteePublicKey {
	return CommitteePublicKey{NodeID: n.NodeID, PublicKey: n.PublicKey}
}

// Sign produces an EdDSA signature over a certificate hash. The challenge
// hash is MiMC, matching the in-circuit verifier.
func (n *CommitteeNode) Sign(hash field.Element) ([]byte, error) {
	msg, err := field.Bytes(hash)
	if err != nil {
		return nil, err
	}
	return n.private.Sign(msg, mimc.NewMiMC())
}

// ShareRating splits a rating into three additive shares over the field:
// rating = s1 + s2 + s3. Any two shares reveal nothing about the rating.
func ShareRating(rating int) ([CommitteeSize]field.Element, error) {
	var shares [CommitteeSize]field.Element
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

// hasBatch reports whether the node already holds shares for a batch.
func (n *CommitteeNode) hasBatch(batchKey string) bool {
	_, ok := n.partials[batchKey]
	return ok
}

// CommitteePublicKey is one node's verification key.
type CommitteePublicKey struct {
	NodeID    string `json:"nodeId"`
	PublicKey []byte `json:"publicKey"`
}

// CommitteeKeyset is the ordered set of committee keys a verifier trusts.
// Its entries are public inputs of the proof, and the same for every agent.
type CommitteeKeyset struct {
	ID   field.Element                     `json:"id"`
	Keys [CommitteeSize]CommitteePublicKey `json:"keys"`
}

// NewKeyset builds the keyset of a committee.
func NewKeyset(id field.Element, nodes []*CommitteeNode) (CommitteeKeyset, error) {
	if len(nodes) != CommitteeSize {
		return CommitteeKeyset{}, fmt.Errorf("%w: got %d", ErrKeysetSize, len(nodes))
	}
	ks := CommitteeKeyset{ID: id}
	for i, n := range nodes {
		ks.Keys[i] = n.Public()
	}
	return ks, nil
}

// Index returns the position of a node in the keyset.
func (k CommitteeKeyset) Index(nodeID string) (int, bool) {
	for i, key := range k.Keys {
		if key.NodeID == nodeID {
			return i, true
		}
	}
	return 0, false
}

// PublicKeys returns the raw keys in keyset order, as the circuit expects.
func (k CommitteeKeyset) PublicKeys() [CommitteeSize][]byte {
	var out [CommitteeSize][]byte
	for i, key := range k.Keys {
		out[i] = key.PublicKey
	}
	return out
}

// VerifyCommitteeSignature checks a committee signature natively. The
// circuit performs the same check; this is for tools and tests.
func VerifyCommitteeSignature(publicKey []byte, hash field.Element, signature []byte) (bool, error) {
	var pub eddsa.PublicKey
	if _, err := pub.SetBytes(publicKey); err != nil {
		return false, err
	}
	msg, err := field.Bytes(hash)
	if err != nil {
		return false, err
	}
	return pub.Verify(signature, msg, mimc.NewMiMC())
}

// BatchKey names one aggregation batch: one passport, one manifest, one
// domain, one epoch.
func BatchKey(passportCommitment, manifestCommitment, taskDomain, aggregationEpoch field.Element) string {
	return strings.Join([]string{passportCommitment, manifestCommitment, taskDomain, aggregationEpoch}, ":")
}

// CertificatePayload is the signed content of a score certificate. The score
// itself appears only as a hiding commitment. The whole payload stays with
// the agent; a verifier never sees it.
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

// CommitteeSignature is one node's EdDSA signature over the certificate hash.
type CommitteeSignature struct {
	NodeID    string `json:"nodeId"`
	Signature []byte `json:"signature"`
}

// ScoreCertificate is a payload plus a quorum of committee signatures.
type ScoreCertificate struct {
	CertificatePayload
	Signatures []CommitteeSignature `json:"signatures"`
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
	if len(committee) != CommitteeSize {
		return IssuedCertificate{}, fmt.Errorf("%w: got %d", ErrKeysetSize, len(committee))
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

	// A batch is aggregated once. The partial sums are running totals per
	// batch key, so a second issuance for the same key would report a score
	// covering both rounds next to a receiptCount covering only this one.
	for _, node := range committee {
		if node.hasBatch(batchKey) {
			return IssuedCertificate{}, fmt.Errorf("%w: %s", ErrBatchAlreadyIssued, batchKey)
		}
	}

	// Secret-share every rating; node i only ever receives share i.
	for _, v := range req.Receipts {
		shares, err := ShareRating(v.Receipt().Rating)
		if err != nil {
			return IssuedCertificate{}, err
		}
		for i := 0; i < CommitteeSize; i++ {
			if err := committee[i].Accumulate(batchKey, shares[i]); err != nil {
				return IssuedCertificate{}, err
			}
		}
	}

	// Reconstruct the score from the partial sums. Individual ratings are
	// never reconstructed, only their total.
	score := field.Element("0")
	for i := 0; i < CommitteeSize; i++ {
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
	cert := ScoreCertificate{CertificatePayload: payload}
	for _, node := range committee[:Quorum] {
		sig, err := node.Sign(hash)
		if err != nil {
			return IssuedCertificate{}, err
		}
		cert.Signatures = append(cert.Signatures, CommitteeSignature{NodeID: node.NodeID, Signature: sig})
	}
	return IssuedCertificate{Certificate: cert, Score: score, ScoreSalt: scoreSalt}, nil
}
