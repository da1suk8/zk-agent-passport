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

// ManifestCommitment hashes the canonical manifest fields into the field.
func ManifestCommitment(m Manifest) (field.Element, error) {
	return field.Hash(
		field.FromText(m.ModelID),
		field.FromText(m.SystemPromptHash),
		field.FromText(m.ToolPolicyHash),
		field.FromText(m.PermissionScope),
	)
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
