package passport

import "github.com/da1suk8/zk-agent-passport/field"

// DefaultChallengeTTL is how long a proof may be used after issuance.
const DefaultChallengeTTL int64 = 300

// Challenge binds a proof to one verifier, one nonce, and one expiry.
type Challenge struct {
	VerifierID     field.Element `json:"verifierId"`
	Nonce          field.Element `json:"nonce"`
	ProofExpiresAt field.Element `json:"proofExpiresAt"`
}

// NewChallenge issues a fresh random nonce for a verifier.
func NewChallenge(verifierName string, now int64, ttl int64) (Challenge, error) {
	nonce, err := field.Random()
	if err != nil {
		return Challenge{}, err
	}
	return Challenge{
		VerifierID:     field.FromText(verifierName),
		Nonce:          nonce,
		ProofExpiresAt: field.FromInt(now + ttl),
	}, nil
}
