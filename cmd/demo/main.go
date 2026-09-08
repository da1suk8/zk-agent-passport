// Command demo runs the zkAgent Passport flow end to end: one authorized
// access followed by two rejected attempts.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark/logger"

	"github.com/da1suk8/zk-agent-passport/demo"
	"github.com/da1suk8/zk-agent-passport/passport"
	"github.com/da1suk8/zk-agent-passport/verifier"
	"github.com/da1suk8/zk-agent-passport/zkp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	logger.Disable()
	artifacts := filepath.Join("artifacts")
	if len(os.Args) > 1 {
		artifacts = os.Args[1]
	}

	step("Setup: compile circuit and load Groth16 keys")
	start := time.Now()
	sys, err := zkp.LoadOrSetup(artifacts)
	if err != nil {
		return err
	}
	fmt.Printf("  constraints=%d publicInputs=%d took=%s\n", sys.NbConstraints(), sys.NbPublicInputs(), since(start))

	step("Provision: providers, gateway, committee, agent, receipts, certificate")
	start = time.Now()
	world, err := demo.NewWorld(sys)
	if err != nil {
		return err
	}
	fmt.Printf("  receipts=%d ratings=%v took=%s\n", len(world.Receipts), demo.Ratings, since(start))
	fmt.Printf("  certificate receiptCount=%s scoreCommitment=%s...\n", world.Issued.Certificate.ReceiptCount, world.Issued.Certificate.ScoreCommitment[:16])
	fmt.Printf("  (score=%s is known only to the agent and the committee)\n", world.Issued.Score)

	step("Case 1: valid passport, policy threshold 12, minimum 3 receipts")
	ch, err := world.NewChallenge()
	if err != nil {
		return err
	}
	start = time.Now()
	pkg, err := world.Prove(ch)
	if err != nil {
		return err
	}
	proveTook := since(start)
	raw, err := pkg.Proof.MarshalBinary()
	if err != nil {
		return err
	}
	start = time.Now()
	decision, err := world.Access(ch, pkg)
	if err != nil {
		return err
	}
	fmt.Printf("  prove=%s verify=%s proofBytes=%d\n", proveTook, since(start), len(raw))
	printJSON(map[string]any{
		"authorized":      decision.Authorized,
		"scoreDisclosed":  false,
		"receiptCount":    world.Issued.Certificate.ReceiptCount,
		"certificateHash": decision.CertificateHash,
	})

	step("Case 2: same agent, policy bound to a different manifest")
	mismatch, err := world.ManifestMismatchPolicy()
	if err != nil {
		return err
	}
	ch2, err := world.NewChallenge()
	if err != nil {
		return err
	}
	if _, err := world.ProveWith(ch2, mismatch, world.Issued); err != nil {
		expect(err, passport.ErrPolicyMismatch)
	} else {
		return errors.New("case 2 unexpectedly produced a proof")
	}

	step("Case 3: replay of the case 1 proof with the same nonce")
	if _, err := world.Access(ch, pkg); err != nil {
		expect(err, verifier.ErrNonceConsumed)
	} else {
		return errors.New("case 3 unexpectedly authorized a replay")
	}
	return nil
}

func step(title string) {
	fmt.Printf("\n== %s\n", title)
}

func since(t time.Time) string {
	return time.Since(t).Round(time.Millisecond).String()
}

func expect(err, want error) {
	if errors.Is(err, want) {
		fmt.Printf("  rejected as expected: %v\n", err)
		return
	}
	fmt.Printf("  rejected with an unexpected reason: %v\n", err)
}

func printJSON(v any) {
	out, _ := json.MarshalIndent(v, "  ", "  ")
	fmt.Println("  " + string(out))
}
