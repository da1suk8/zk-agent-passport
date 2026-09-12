// Command service is the verifier as a separate process. It issues
// challenges, persists its nonce bookkeeping between invocations, and
// verifies proofs produced by the agent process.
//
//	service challenge [-threshold 12] [-min 3]   publish a policy and a fresh nonce
//	service verify                                verify agent-state/proof.json
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/consensys/gnark/logger"

	"github.com/da1suk8/zk-agent-passport/internal/demo"
	"github.com/da1suk8/zk-agent-passport/internal/store"
	"github.com/da1suk8/zk-agent-passport/passport"
	"github.com/da1suk8/zk-agent-passport/verifier"
	"github.com/da1suk8/zk-agent-passport/zkp"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: service <challenge|verify> [flags]")
	}
	fs := flag.NewFlagSet("service "+args[0], flag.ContinueOnError)
	dir := fs.String("dir", envOr("AGENT_STATE_DIR", "agent-state"), "state directory shared with the agent")
	artifacts := fs.String("artifacts", "artifacts", "directory for cached Groth16 keys")
	threshold := fs.Int64("threshold", demo.RequiredThreshold, "required score (challenge)")
	minimum := fs.Int64("min", demo.MinimumReceiptCount, "minimum receipt count (challenge)")
	strict := fs.Bool("strict", false, "permit no manifest change (challenge)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	logger.Disable()

	switch args[0] {
	case "challenge":
		return challenge(*dir, *artifacts, *threshold, *minimum, *strict)
	case "verify":
		return verify(*dir, *artifacts)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func loadVerifier(dir, artifacts string) (*verifier.Verifier, store.Service, *zkp.System, error) {
	var svc store.Service
	if err := store.Load(dir, store.ServiceName, &svc); err != nil {
		return nil, svc, nil, fmt.Errorf("no service state; run `agent enroll` first: %w", err)
	}
	sys, err := zkp.LoadOrSetup(artifacts)
	if err != nil {
		return nil, svc, nil, err
	}
	v := verifier.New(sys, svc.Keyset, svc.Name)
	v.ImportState(svc.Nonces)
	return v, svc, sys, nil
}

func challenge(dir, artifacts string, threshold, minimum int64, strict bool) error {
	v, svc, _, err := loadVerifier(dir, artifacts)
	if err != nil {
		return err
	}
	var decl store.Declaration
	if err := store.Load(dir, store.DeclarationName, &decl); err != nil {
		return fmt.Errorf("no agent declaration; run `agent init` first: %w", err)
	}
	vp := demo.DefaultVersionPolicy()
	if strict {
		vp = passport.StrictManifestPolicy()
	}
	bundle, err := passport.NewPolicy(passport.PolicyRequest{
		RequiredThreshold:           threshold,
		MinimumReceiptCount:         minimum,
		RequestedTaskDomain:         demo.TaskDomain,
		RequestedManifestCommitment: decl.AgentManifestCommitment,
		RequestedAggregationEpoch:   demo.AggregationEpoch,
		ManifestVersionPolicy:       vp,
	})
	if err != nil {
		return err
	}
	ch, err := v.IssueChallenge(time.Now().Unix(), bundle.PolicyHash)
	if err != nil {
		return err
	}
	svc.Nonces = v.ExportState()
	if err := store.Save(dir, store.ServiceName, svc, 0o644); err != nil {
		return err
	}
	if err := store.Save(dir, store.ChallengeName, store.Challenge{
		Policy: bundle.Policy, PolicyHash: bundle.PolicyHash, VersionPolicy: vp, Keyset: v.Keyset(), Challenge: ch,
	}, 0o644); err != nil {
		return err
	}
	fmt.Printf("challenge published to %s/%s\n", dir, store.ChallengeName)
	fmt.Printf("  threshold=%d minimumReceipts=%d requestedManifest=%s… nonce=%s… expiresAt=%s\n",
		threshold, minimum, decl.AgentManifestCommitment[:14], ch.Nonce[:14], ch.ProofExpiresAt)
	fmt.Printf("  pending nonces=%d used=%d (persisted in service.json)\n", len(svc.Nonces.Pending), len(svc.Nonces.Used))
	return nil
}

func verify(dir, artifacts string) error {
	v, svc, _, err := loadVerifier(dir, artifacts)
	if err != nil {
		return err
	}
	var ch store.Challenge
	if err := store.Load(dir, store.ChallengeName, &ch); err != nil {
		return fmt.Errorf("no challenge; run `service challenge` first: %w", err)
	}
	bundle, err := ch.Bundle()
	if err != nil {
		return err
	}
	var pkg passport.ProofPackage
	if err := store.Load(dir, store.ProofName, &pkg); err != nil {
		return fmt.Errorf("no proof; run `agent prove` first: %w", err)
	}
	t := time.Now()
	decision, verr := v.VerifyAccess(verifier.AccessRequest{
		Policy:    bundle,
		Challenge: ch.Challenge,
		Proof:     &pkg,
		Now:       time.Now().Unix(),
	})
	took := time.Since(t)
	svc.Nonces = v.ExportState()
	if err := store.Save(dir, store.ServiceName, svc, 0o644); err != nil {
		return err
	}
	for _, c := range decision.Checks {
		mark := map[verifier.CheckStatus]string{verifier.CheckOK: "ok  ", verifier.CheckFailed: "FAIL", verifier.CheckSkipped: "-   "}[c.Status]
		if c.Err != nil {
			fmt.Printf("  %s %s: %v\n", mark, c.Key, c.Err)
		} else {
			fmt.Printf("  %s %s\n", mark, c.Key)
		}
	}
	if verr != nil {
		fmt.Printf("REJECTED (%s): %v\n", took.Round(time.Millisecond), verr)
		os.Exit(2)
	}
	fmt.Printf("AUTHORIZED (%s) nullifier=%s… nonce consumed; used nonces=%d\n", took.Round(time.Millisecond), decision.Nullifier[:14], len(svc.Nonces.Used))
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
