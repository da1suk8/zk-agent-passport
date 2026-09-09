// Command agent is the passport holder as a single-shot process. It keeps no
// daemon and no session: every invocation loads the passport (from a file or
// from environment variables), does one job, and exits. The unit of identity
// is the holder of agentSecret plus the declared manifest, not a running
// process, so a Lambda-style execution that loads the same secret and
// manifest is the same agent.
//
//	agent init                       create a passport and a declaration
//	agent enroll                     obtain a score certificate (simulated providers and committee)
//	agent update-manifest -model X   change the declared manifest
//	agent prove                      answer the service's challenge with a proof, then exit
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/consensys/gnark/logger"

	"github.com/da1suk8/zk-agent-passport/demo"
	"github.com/da1suk8/zk-agent-passport/field"
	"github.com/da1suk8/zk-agent-passport/passport"
	"github.com/da1suk8/zk-agent-passport/store"
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
		return errors.New("usage: agent <init|enroll|update-manifest|prove> [flags]")
	}
	fs := flag.NewFlagSet("agent "+args[0], flag.ContinueOnError)
	dir := fs.String("dir", envOr("AGENT_STATE_DIR", "agent-state"), "state directory")
	artifacts := fs.String("artifacts", "artifacts", "directory for cached Groth16 keys")
	force := fs.Bool("force", false, "overwrite an existing passport (init)")
	ratings := fs.String("ratings", "5,4,5", "ratings issued by providers A, B, C (enroll)")
	model := fs.String("model", "", "new modelId (update-manifest)")
	prompt := fs.String("prompt", "", "new systemPromptHash (update-manifest)")
	tools := fs.String("tools", "", "new toolPolicyHash (update-manifest)")
	scope := fs.String("scope", "", "new permissionScope (update-manifest)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	logger.Disable()

	switch args[0] {
	case "init":
		return initPassport(*dir, *force)
	case "enroll":
		return enroll(*dir, *ratings)
	case "update-manifest":
		return updateManifest(*dir, *model, *prompt, *tools, *scope)
	case "prove":
		return prove(*dir, *artifacts)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func initPassport(dir string, force bool) error {
	if store.Exists(dir, store.PassportName) && !force {
		return fmt.Errorf("%s/%s exists; use -force to replace it", dir, store.PassportName)
	}
	agent, err := passport.NewAgent(demo.DefaultManifest)
	if err != nil {
		return err
	}
	if err := savePassport(dir, agent); err != nil {
		return err
	}
	fmt.Printf("passport created in %s\n", dir)
	fmt.Printf("  passportCommitment=%s\n  manifestCommitment=%s\n", short(agent.PassportCommitment), short(agent.AgentManifestCommitment))
	fmt.Println("  the secret is in passport.json (mode 0600); AGENT_SECRET / PASSPORT_SALT can override it at prove time")
	return nil
}

func savePassport(dir string, agent *passport.Agent) error {
	if err := store.Save(dir, store.PassportName, store.Passport{
		AgentSecret: agent.AgentSecret, PassportSalt: agent.PassportSalt, Manifest: agent.Manifest,
	}, 0o600); err != nil {
		return err
	}
	return store.Save(dir, store.DeclarationName, store.Declaration{
		PassportCommitment:      agent.PassportCommitment,
		AgentManifestCommitment: agent.AgentManifestCommitment,
		Manifest:                agent.Manifest,
	}, 0o644)
}

// enroll simulates three registered providers, the gateway, and the
// committee to issue a certificate for this passport. Their private keys are
// discarded afterwards; the service only needs the committee public keys.
func enroll(dir, ratingList string) error {
	agent, err := loadAgent(dir)
	if err != nil {
		return err
	}
	var ratings []int
	for _, part := range strings.Split(ratingList, ",") {
		v, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return fmt.Errorf("ratings: %w", err)
		}
		ratings = append(ratings, v)
	}
	if len(ratings) > 3 {
		return errors.New("at most three providers are simulated")
	}
	now := time.Now().Unix()
	var issuers []*passport.Identity
	for _, name := range []string{"provider-a", "provider-b", "provider-c"} {
		id, err := passport.NewIdentity(name)
		if err != nil {
			return err
		}
		issuers = append(issuers, id)
	}
	gateway := passport.NewInputGateway(passport.NewIssuerRegistry(issuers...))
	var validated []passport.ValidatedReceipt
	for i, rating := range ratings {
		r, err := passport.IssueReceipt(issuers[i], agent, passport.ReceiptRequest{
			ReceiptID: fmt.Sprintf("receipt-%d-%d", now, i+1), TaskDomain: demo.TaskDomain, Rating: rating,
			IssuedAt: now, ExpiresAt: now + 3600,
		})
		if err != nil {
			return err
		}
		v, err := gateway.ValidateReceipt(r, demo.AggregationEpoch, now)
		if err != nil {
			return err
		}
		validated = append(validated, v)
	}
	var committee []*passport.CommitteeNode
	for _, name := range []string{"committee-1", "committee-2", "committee-3"} {
		node, err := passport.NewCommitteeNode(name)
		if err != nil {
			return err
		}
		committee = append(committee, node)
	}
	keyset, err := passport.NewKeyset(passport.CommitteeKeysetID, committee)
	if err != nil {
		return err
	}
	issued, err := passport.IssueScoreCertificate(committee, passport.AggregationRequest{
		Receipts: validated, AggregationEpoch: demo.AggregationEpoch, IssuedAt: now, ExpiresAt: now + 3600,
	})
	if err != nil {
		return err
	}
	if err := store.Save(dir, store.CertificateName, store.Certificate{
		CertifiedManifest: agent.Manifest, Certificate: issued.Certificate, Score: issued.Score, ScoreSalt: issued.ScoreSalt,
	}, 0o600); err != nil {
		return err
	}
	service := store.Service{Name: demo.VerifierName, Keyset: keyset}
	if err := store.Save(dir, store.ServiceName, service, 0o644); err != nil {
		return err
	}
	fmt.Printf("certificate issued for manifest %s (ratings %v, expires in 1h)\n", short(agent.AgentManifestCommitment), ratings)
	fmt.Printf("service.json now trusts committee keyset %s (%s, %s, %s)\n", keyset.ID, keyset.Keys[0].NodeID, keyset.Keys[1].NodeID, keyset.Keys[2].NodeID)
	return nil
}

func updateManifest(dir, model, prompt, tools, scope string) error {
	agent, err := loadAgent(dir)
	if err != nil {
		return err
	}
	m := agent.Manifest
	if model != "" {
		m.ModelID = model
	}
	if prompt != "" {
		m.SystemPromptHash = prompt
	}
	if tools != "" {
		m.ToolPolicyHash = tools
	}
	if scope != "" {
		m.PermissionScope = scope
	}
	if err := agent.UpdateManifest(m); err != nil {
		return err
	}
	if err := savePassport(dir, agent); err != nil {
		return err
	}
	fmt.Printf("manifest updated: modelId=%s systemPromptHash=%s toolPolicyHash=%s permissionScope=%s\n", m.ModelID, m.SystemPromptHash, m.ToolPolicyHash, m.PermissionScope)
	fmt.Printf("  manifestCommitment=%s (certificate stays bound to the certified manifest)\n", short(agent.AgentManifestCommitment))
	return nil
}

// prove is the single-shot job: load identity, read the challenge, write
// the proof, exit.
func prove(dir, artifacts string) error {
	start := time.Now()
	agent, err := loadAgent(dir)
	if err != nil {
		return err
	}
	var cert store.Certificate
	if err := store.Load(dir, store.CertificateName, &cert); err != nil {
		return fmt.Errorf("no certificate; run `agent enroll` first: %w", err)
	}
	var ch store.Challenge
	if err := store.Load(dir, store.ChallengeName, &ch); err != nil {
		return fmt.Errorf("no challenge; run `service challenge` first: %w", err)
	}
	bundle, err := ch.Bundle()
	if err != nil {
		return err
	}
	sys, err := zkp.LoadOrSetup(artifacts)
	if err != nil {
		return err
	}
	loaded := time.Since(start)
	t := time.Now()
	pkg, err := passport.Prove(sys, passport.ProofRequest{
		Agent:             agent,
		CertifiedManifest: cert.CertifiedManifest,
		Issued:            passport.IssuedCertificate{Certificate: cert.Certificate, Score: cert.Score, ScoreSalt: cert.ScoreSalt},
		Policy:            bundle,
		Challenge:         ch.Challenge,
		Keyset:            ch.Keyset,
	})
	if err != nil {
		return fmt.Errorf("cannot prove: %w", err)
	}
	proveTook := time.Since(t)
	if err := store.Save(dir, store.ProofName, pkg, 0o644); err != nil {
		return err
	}
	fmt.Printf("proof written to %s/%s (load %s, prove %s); nullifier=%s…; exiting\n", dir, store.ProofName, loaded.Round(time.Millisecond), proveTook.Round(time.Millisecond), pkg.Statement.Nullifier[:14])
	return nil
}

// loadAgent reads the passport file and lets environment variables override
// the secret, as a Lambda-style deployment would inject it.
func loadAgent(dir string) (*passport.Agent, error) {
	var p store.Passport
	if err := store.Load(dir, store.PassportName, &p); err != nil {
		if secret := os.Getenv("AGENT_SECRET"); secret == "" {
			return nil, fmt.Errorf("no passport; run `agent init` first: %w", err)
		}
	}
	if secret := os.Getenv("AGENT_SECRET"); secret != "" {
		p.AgentSecret = secret
	}
	if salt := os.Getenv("PASSPORT_SALT"); salt != "" {
		p.PassportSalt = salt
	}
	if p.Manifest == (passport.Manifest{}) {
		p.Manifest = demo.DefaultManifest
	}
	return p.Agent()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func short(v field.Element) string {
	if len(v) <= 14 {
		return v
	}
	return v[:14] + "…"
}
