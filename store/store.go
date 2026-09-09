// Package store defines the JSON files exchanged between the single-shot
// agent process and the service process. The agent's only state is its
// passport and its certificate; nonce bookkeeping lives with the service.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/da1suk8/zk-agent-passport/field"
	"github.com/da1suk8/zk-agent-passport/passport"
	"github.com/da1suk8/zk-agent-passport/verifier"
)

// File names inside a state directory.
const (
	PassportName    = "passport.json"
	DeclarationName = "declaration.json"
	CertificateName = "certificate.json"
	ServiceName     = "service.json"
	ChallengeName   = "challenge.json"
	ProofName       = "proof.json"
)

// Passport is the agent's secret identity. Keep it private.
type Passport struct {
	AgentSecret  field.Element     `json:"agentSecret"`
	PassportSalt field.Element     `json:"passportSalt"`
	Manifest     passport.Manifest `json:"manifest"`
}

// Agent rebuilds the in-memory agent from the file.
func (p Passport) Agent() (*passport.Agent, error) {
	return passport.RestoreAgent(p.AgentSecret, p.PassportSalt, p.Manifest)
}

// Declaration is what the agent tells a service about itself: its current
// manifest and the two commitments. It carries no secret.
type Declaration struct {
	PassportCommitment      field.Element     `json:"passportCommitment"`
	AgentManifestCommitment field.Element     `json:"agentManifestCommitment"`
	Manifest                passport.Manifest `json:"manifest"`
}

// Certificate is the agent's credential with the opening of its score.
type Certificate struct {
	CertifiedManifest passport.Manifest         `json:"certifiedManifest"`
	Certificate       passport.ScoreCertificate `json:"certificate"`
	Score             field.Element             `json:"score"`
	ScoreSalt         field.Element             `json:"scoreSalt"`
}

// CommitteeKey is one trusted committee public key.
type CommitteeKey struct {
	NodeID    string `json:"nodeId"`
	PublicKey []byte `json:"publicKey"`
}

// Service is the verifier's persistent state.
type Service struct {
	Name      string         `json:"name"`
	Committee []CommitteeKey `json:"committee"`
	Nonces    verifier.State `json:"nonces"`
}

// Challenge is what the service publishes for one access attempt.
type Challenge struct {
	Policy        passport.Policy                `json:"policy"`
	PolicyHash    field.Element                  `json:"policyHash"`
	VersionPolicy passport.ManifestVersionPolicy `json:"versionPolicy"`
	Challenge     passport.Challenge             `json:"challenge"`
}

// Bundle rebuilds the policy bundle and checks it is self-consistent.
func (c Challenge) Bundle() (passport.PolicyBundle, error) {
	return passport.RebuildPolicy(c.Policy, c.PolicyHash, c.VersionPolicy)
}

// Load reads a JSON file into v.
func Load(dir, name string, v any) error {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// Save writes v as indented JSON with the given permissions.
func Save(dir, name string, v any, perm os.FileMode) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), append(raw, '\n'), perm)
}

// Exists reports whether a file is present.
func Exists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return !errors.Is(err, os.ErrNotExist)
}
