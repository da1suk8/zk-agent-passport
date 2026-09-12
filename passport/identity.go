package passport

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Identity is a signing party: a task provider (receipt issuer) or a
// reputation committee node. Signatures are Ed25519 and are verified outside
// the ZK circuit.
type Identity struct {
	NodeID     string
	PublicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// NewIdentity generates a fresh Ed25519 key pair.
func NewIdentity(nodeID string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity %s: %w", nodeID, err)
	}
	return &Identity{NodeID: nodeID, PublicKey: pub, privateKey: priv}, nil
}

// Sign returns a base64 Ed25519 signature over msg.
func (id *Identity) Sign(msg []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(id.privateKey, msg))
}

// VerifySignature checks a base64 Ed25519 signature.
func VerifySignature(pub ed25519.PublicKey, msg []byte, signature string) bool {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}
