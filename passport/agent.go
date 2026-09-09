package passport

import (
	"fmt"

	"github.com/da1suk8/zk-agent-passport/field"
)

// Manifest declares what an agent is: its model, prompt, tools, and permission
// scope. Reputation binds to the manifest commitment, so changing any of these
// yields a new commitment and no inherited reputation.
type Manifest struct {
	ModelID          string `json:"modelId"`
	SystemPromptHash string `json:"systemPromptHash"`
	ToolPolicyHash   string `json:"toolPolicyHash"`
	PermissionScope  string `json:"permissionScope"`
}

// ManifestCommitment hashes the manifest fields, in circuit order, into the
// field.
func ManifestCommitment(m Manifest) (field.Element, error) {
	fields := ManifestFields(m)
	return field.Hash(fields[:]...)
}

// Agent holds the passport secret. The unit of identity is the holder of
// agentSecret together with the declared manifest, not a running process: a
// single-shot execution that loads the same secret and manifest is the same
// agent.
type Agent struct {
	AgentSecret             field.Element
	PassportSalt            field.Element
	PassportCommitment      field.Element
	AgentManifestCommitment field.Element
	Manifest                Manifest
}

// UpdateManifest replaces the agent's declared manifest. Reputation stays
// bound to the manifest that was certified; whether the new manifest may use
// it is decided by the service's ManifestVersionPolicy inside the proof.
func (a *Agent) UpdateManifest(m Manifest) error {
	commitment, err := ManifestCommitment(m)
	if err != nil {
		return fmt.Errorf("manifest commitment: %w", err)
	}
	a.Manifest = m
	a.AgentManifestCommitment = commitment
	return nil
}

// NewAgent creates a passport for a manifest.
func NewAgent(m Manifest) (*Agent, error) {
	secret, err := field.Random()
	if err != nil {
		return nil, err
	}
	salt, err := field.Random()
	if err != nil {
		return nil, err
	}
	passport, err := field.Commit(secret, salt)
	if err != nil {
		return nil, fmt.Errorf("passport commitment: %w", err)
	}
	manifest, err := ManifestCommitment(m)
	if err != nil {
		return nil, fmt.Errorf("manifest commitment: %w", err)
	}
	return &Agent{
		AgentSecret:             secret,
		PassportSalt:            salt,
		PassportCommitment:      passport,
		AgentManifestCommitment: manifest,
		Manifest:                m,
	}, nil
}
