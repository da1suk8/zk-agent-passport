// Command bench measures the passport circuit: a constraint breakdown by
// component, obtained by compiling each gadget in isolation, and proving and
// verification times averaged over repeated runs. Output is Markdown.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/hash/poseidon2"

	"github.com/da1suk8/zk-agent-passport/demo"
	"github.com/da1suk8/zk-agent-passport/zkp"
)

func main() {
	n := flag.Int("n", 20, "number of proofs to time")
	artifacts := flag.String("artifacts", "artifacts", "directory for cached Groth16 keys")
	flag.Parse()
	logger.Disable()
	if err := run(*n, *artifacts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(n int, artifacts string) error {
	start := time.Now()
	ccs, err := zkp.Compile()
	if err != nil {
		return err
	}
	compileTook := time.Since(start)
	total := ccs.GetNbConstraints()

	fmt.Printf("## Circuit\n\n| Item | Value |\n|---|---|\n")
	fmt.Printf("| Constraints (Groth16 / BN254) | %d |\n", total)
	fmt.Printf("| Public inputs | %d |\n", ccs.GetNbPublicVariables()-1)
	fmt.Printf("| Private inputs | %d |\n", ccs.GetNbSecretVariables())
	fmt.Printf("| Compile | %s |\n\n", round(compileTook))

	// Breakdown: each row is one gadget compiled alone, multiplied by how
	// many times the passport circuit uses it.
	rows := []struct {
		name  string
		times int
		probe frontend.Circuit
	}{
		{"Certificate hash (Poseidon2, 10 inputs)", 1, hashProbe(10)},
		{"Policy hash (Poseidon2, 8 inputs)", 1, hashProbe(8)},
		{"Score commitment opening (2 inputs)", 1, hashProbe(2)},
		{"Passport commitment opening (2 inputs)", 1, hashProbe(2)},
		{"Manifest opening (4 inputs)", 2, hashProbe(4)},
		{"Manifest version policy, per field (leaf + depth-4 Merkle + checks)", zkp.ManifestFieldCount, &versionPolicyProbe{}},
		{"32-bit comparison (score, receipt count)", 2, &compareProbe{}},
		{"Challenge binding (3 non-zero checks)", 1, &bindingProbe{}},
	}
	fmt.Printf("## Constraint breakdown (gadgets compiled in isolation)\n\n")
	fmt.Printf("| Component | Uses | Each | Subtotal | Share |\n|---|---:|---:|---:|---:|\n")
	accounted := 0
	for _, r := range rows {
		each, err := count(r.probe)
		if err != nil {
			return fmt.Errorf("%s: %w", r.name, err)
		}
		sub := each * r.times
		accounted += sub
		fmt.Printf("| %s | %d | %d | %d | %.1f%% |\n", r.name, r.times, each, sub, 100*float64(sub)/float64(total))
	}
	other := total - accounted
	fmt.Printf("| Other (mask bits, equality wiring, probe overlap) | | | %d | %.1f%% |\n", other, 100*float64(other)/float64(total))
	fmt.Printf("| **Total** | | | **%d** | 100%% |\n\n", total)

	// Timing on the demo world.
	start = time.Now()
	sys, err := zkp.LoadOrSetup(artifacts)
	if err != nil {
		return err
	}
	setupTook := time.Since(start)
	world, err := demo.NewWorld(sys)
	if err != nil {
		return err
	}
	var prove, verify []time.Duration
	proofBytes := 0
	for i := 0; i < n; i++ {
		ch, err := world.NewChallenge()
		if err != nil {
			return err
		}
		t := time.Now()
		pkg, err := world.Prove(ch)
		if err != nil {
			return err
		}
		prove = append(prove, time.Since(t))
		raw, err := pkg.Proof.MarshalBinary()
		if err != nil {
			return err
		}
		proofBytes = len(raw)
		t = time.Now()
		if _, err := world.Access(ch, pkg); err != nil {
			return err
		}
		verify = append(verify, time.Since(t))
	}
	fmt.Printf("## Timing (%d runs, Apple Silicon unless noted)\n\n", n)
	fmt.Printf("| Item | Min | Median | Mean | Max |\n|---|---:|---:|---:|---:|\n")
	fmt.Printf("| Prove | %s |\n", statsRow(prove))
	fmt.Printf("| Verify | %s |\n", statsRow(verify))
	fmt.Printf("\n| Item | Value |\n|---|---|\n")
	fmt.Printf("| Proof size | %d bytes |\n", proofBytes)
	fmt.Printf("| Key setup or load | %s |\n", round(setupTook))
	fmt.Printf("| Receipts -> certificate (3 receipts) | %s |\n", provisionTime(sys))
	return nil
}

func count(c frontend.Circuit) (int, error) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		return 0, err
	}
	return ccs.GetNbConstraints(), nil
}

func provisionTime(sys *zkp.System) string {
	t := time.Now()
	if _, err := demo.NewWorld(sys); err != nil {
		return "n/a"
	}
	return round(time.Since(t))
}

func statsRow(d []time.Duration) string {
	sorted := append([]time.Duration(nil), d...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var sum time.Duration
	for _, v := range sorted {
		sum += v
	}
	return fmt.Sprintf("%s | %s | %s | %s", round(sorted[0]), round(sorted[len(sorted)/2]), round(sum/time.Duration(len(sorted))), round(sorted[len(sorted)-1]))
}

func round(d time.Duration) string {
	return d.Round(100 * time.Microsecond).String()
}

// hashProbeCircuit absorbs n inputs into Poseidon2.
type hashProbeCircuit struct {
	In  []frontend.Variable
	Out frontend.Variable `gnark:",public"`
}

func (c *hashProbeCircuit) Define(api frontend.API) error {
	h, err := poseidon2.New(api)
	if err != nil {
		return err
	}
	h.Write(c.In...)
	api.AssertIsEqual(h.Sum(), c.Out)
	return nil
}

func hashProbe(n int) frontend.Circuit {
	return &hashProbeCircuit{In: make([]frontend.Variable, n)}
}

// versionPolicyProbe replicates the per-field block of the manifest version
// policy check.
type versionPolicyProbe struct {
	Certified frontend.Variable
	Current   frontend.Variable
	Index     frontend.Variable
	Siblings  [zkp.AllowlistDepth]frontend.Variable
	Mutable   frontend.Variable `gnark:",public"`
	Root      frontend.Variable `gnark:",public"`
}

func (c *versionPolicyProbe) Define(api frontend.API) error {
	h, err := poseidon2.New(api)
	if err != nil {
		return err
	}
	hash := func(inputs ...frontend.Variable) frontend.Variable {
		h.Reset()
		h.Write(inputs...)
		return h.Sum()
	}
	same := api.IsZero(api.Sub(c.Certified, c.Current))
	node := hash(1, c.Current)
	bits := api.ToBinary(c.Index, zkp.AllowlistDepth)
	for k := 0; k < zkp.AllowlistDepth; k++ {
		left := api.Select(bits[k], c.Siblings[k], node)
		right := api.Select(bits[k], node, c.Siblings[k])
		node = hash(left, right)
	}
	inAllowlist := api.IsZero(api.Sub(node, c.Root))
	permitted := api.Mul(c.Mutable, inAllowlist)
	api.AssertIsEqual(api.Add(same, api.Mul(api.Sub(1, same), permitted)), 1)
	return nil
}

// compareProbe is one 32-bit "a >= b" check with both operands range-checked.
type compareProbe struct {
	A frontend.Variable
	B frontend.Variable `gnark:",public"`
}

func (c *compareProbe) Define(api frontend.API) error {
	api.ToBinary(c.A, zkp.ScoreBits)
	api.ToBinary(c.B, zkp.ScoreBits)
	api.ToBinary(api.Sub(c.A, c.B), zkp.ScoreBits)
	return nil
}

// bindingProbe is the three non-zero constraints on the challenge fields.
type bindingProbe struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
	Z frontend.Variable `gnark:",public"`
}

func (c *bindingProbe) Define(api frontend.API) error {
	api.AssertIsDifferent(c.X, 0)
	api.AssertIsDifferent(c.Y, 0)
	api.AssertIsDifferent(c.Z, 0)
	return nil
}
