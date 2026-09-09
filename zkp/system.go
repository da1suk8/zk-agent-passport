package zkp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/da1suk8/zk-agent-passport/field"
)

// ErrInvalidProof is returned when a proof does not verify for a statement.
var ErrInvalidProof = errors.New("ZK proof is invalid for this statement")

// PublicInputs is the statement a verifier checks a proof against. Field
// order matches PassportCircuit.
type PublicInputs struct {
	CertificateHash         field.Element
	CertificateID           field.Element
	PassportCommitment      field.Element
	AgentManifestCommitment field.Element
	TaskDomain              field.Element
	AggregationEpoch        field.Element
	ScoreCommitment         field.Element
	CertificateIssuedAt     field.Element
	CertificateExpiresAt    field.Element
	CommitteeKeysetID       field.Element

	PolicyHash                  field.Element
	PolicyVersion               field.Element
	RequiredThreshold           field.Element
	MinimumReceiptCount         field.Element
	RequestedTaskDomain         field.Element
	RequestedManifestCommitment field.Element
	RequestedAggregationEpoch   field.Element
	ManifestMutableMask         field.Element
	ManifestAllowlistRoot       field.Element

	VerifierID     field.Element
	Nonce          field.Element
	ProofExpiresAt field.Element
}

// MerkleWitness is one allowlist inclusion path.
type MerkleWitness struct {
	Index    field.Element
	Siblings [AllowlistDepth]field.Element
}

// Witness is the full assignment: the public statement plus the secrets.
type Witness struct {
	PublicInputs
	Score        field.Element
	ScoreSalt    field.Element
	AgentSecret  field.Element
	PassportSalt field.Element
	ReceiptCount field.Element

	CertifiedManifest [ManifestFieldCount]field.Element
	CurrentManifest   [ManifestFieldCount]field.Element
	AllowlistPaths    [ManifestFieldCount]MerkleWitness
}

// Proof is a Groth16 proof for the passport circuit.
type Proof struct {
	Groth16 groth16.Proof
}

// MarshalBinary serializes the proof.
func (p *Proof) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	if _, err := p.Groth16.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes a proof.
func (p *Proof) UnmarshalBinary(data []byte) error {
	p.Groth16 = groth16.NewProof(ecc.BN254)
	_, err := p.Groth16.ReadFrom(bytes.NewReader(data))
	return err
}

// MarshalJSON encodes the proof as a base64 string.
func (p Proof) MarshalJSON() ([]byte, error) {
	raw, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(raw))
}

// UnmarshalJSON decodes a base64 proof.
func (p *Proof) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	return p.UnmarshalBinary(raw)
}

// System is a compiled circuit with its proving and verifying keys.
type System struct {
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
}

// Compile builds the R1CS for the passport circuit.
func Compile() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &PassportCircuit{})
}

// Setup compiles the circuit and runs a single-party Groth16 setup. The
// resulting keys are for development only: whoever ran the setup could forge
// proofs.
func Setup() (*System, error) {
	ccs, err := Compile()
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("setup: %w", err)
	}
	return &System{ccs: ccs, pk: pk, vk: vk}, nil
}

// LoadOrSetup reuses keys cached under dir, or runs Setup and caches them.
// The cache file names carry the circuit's constraint and public-input
// counts, so keys generated for an older circuit are never reused.
func LoadOrSetup(dir string) (*System, error) {
	ccs, err := Compile()
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	tag := fmt.Sprintf("passport-c%d-p%d", ccs.GetNbConstraints(), ccs.GetNbPublicVariables())
	pkPath := filepath.Join(dir, tag+".pk")
	vkPath := filepath.Join(dir, tag+".vk")
	if pk, vk, err := loadKeys(pkPath, vkPath); err == nil {
		return &System{ccs: ccs, pk: pk, vk: vk}, nil
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("setup: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := writeTo(pkPath, pk); err != nil {
		return nil, err
	}
	if err := writeTo(vkPath, vk); err != nil {
		return nil, err
	}
	return &System{ccs: ccs, pk: pk, vk: vk}, nil
}

func loadKeys(pkPath, vkPath string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pkFile, err := os.Open(pkPath)
	if err != nil {
		return nil, nil, err
	}
	defer pkFile.Close()
	vkFile, err := os.Open(vkPath)
	if err != nil {
		return nil, nil, err
	}
	defer vkFile.Close()
	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(pkFile); err != nil {
		return nil, nil, err
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(vkFile); err != nil {
		return nil, nil, err
	}
	return pk, vk, nil
}

func writeTo(path string, w io.WriterTo) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = w.WriteTo(f)
	return err
}

// NbConstraints reports the circuit size.
func (s *System) NbConstraints() int {
	return s.ccs.GetNbConstraints()
}

// NbPublicInputs reports the number of public inputs, excluding the constant one.
func (s *System) NbPublicInputs() int {
	return s.ccs.GetNbPublicVariables() - 1
}

// Prove generates a proof for a full witness.
func (s *System) Prove(w Witness) (*Proof, error) {
	assignment, err := toAssignment(w, false)
	if err != nil {
		return nil, err
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness: %w", err)
	}
	proof, err := groth16.Prove(s.ccs, s.pk, full)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return &Proof{Groth16: proof}, nil
}

// Verify checks a proof against the verifier's own statement. Because the
// public witness is built from the statement rather than taken from the
// prover, a proof for any other statement fails here.
func (s *System) Verify(p *Proof, statement PublicInputs) error {
	assignment, err := toAssignment(Witness{PublicInputs: statement}, true)
	if err != nil {
		return err
	}
	public, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("public witness: %w", err)
	}
	if err := groth16.Verify(p.Groth16, s.vk, public); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	return nil
}

func toAssignment(w Witness, publicOnly bool) (*PassportCircuit, error) {
	conv := func(e field.Element) (*big.Int, error) { return field.ToBig(e) }
	var c PassportCircuit
	var err error
	set := func(dst *frontend.Variable, e field.Element) {
		if err != nil {
			return
		}
		var v *big.Int
		if v, err = conv(e); err == nil {
			*dst = v
		}
	}
	p := w.PublicInputs
	set(&c.CertificateHash, p.CertificateHash)
	set(&c.CertificateID, p.CertificateID)
	set(&c.PassportCommitment, p.PassportCommitment)
	set(&c.AgentManifestCommitment, p.AgentManifestCommitment)
	set(&c.TaskDomain, p.TaskDomain)
	set(&c.AggregationEpoch, p.AggregationEpoch)
	set(&c.ScoreCommitment, p.ScoreCommitment)
	set(&c.CertificateIssuedAt, p.CertificateIssuedAt)
	set(&c.CertificateExpiresAt, p.CertificateExpiresAt)
	set(&c.CommitteeKeysetID, p.CommitteeKeysetID)
	set(&c.PolicyHash, p.PolicyHash)
	set(&c.PolicyVersion, p.PolicyVersion)
	set(&c.RequiredThreshold, p.RequiredThreshold)
	set(&c.MinimumReceiptCount, p.MinimumReceiptCount)
	set(&c.RequestedTaskDomain, p.RequestedTaskDomain)
	set(&c.RequestedManifestCommitment, p.RequestedManifestCommitment)
	set(&c.RequestedAggregationEpoch, p.RequestedAggregationEpoch)
	set(&c.ManifestMutableMask, p.ManifestMutableMask)
	set(&c.ManifestAllowlistRoot, p.ManifestAllowlistRoot)
	set(&c.VerifierID, p.VerifierID)
	set(&c.Nonce, p.Nonce)
	set(&c.ProofExpiresAt, p.ProofExpiresAt)
	if !publicOnly {
		set(&c.Score, w.Score)
		set(&c.ScoreSalt, w.ScoreSalt)
		set(&c.AgentSecret, w.AgentSecret)
		set(&c.PassportSalt, w.PassportSalt)
		set(&c.ReceiptCount, w.ReceiptCount)
		for i := 0; i < ManifestFieldCount; i++ {
			set(&c.CertifiedManifest[i], w.CertifiedManifest[i])
			set(&c.CurrentManifest[i], w.CurrentManifest[i])
			set(&c.AllowlistIndex[i], w.AllowlistPaths[i].Index)
			for k := 0; k < AllowlistDepth; k++ {
				set(&c.AllowlistSiblings[i][k], w.AllowlistPaths[i].Siblings[k])
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("assignment: %w", err)
	}
	return &c, nil
}
