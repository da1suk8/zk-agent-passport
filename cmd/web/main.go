// Command web serves a browser demo of zkAgent Passport. Every run executes
// the real protocol (receipts, gateway checks, secret sharing, certificate,
// Groth16 proof, verification) and returns a step-by-step trace that the
// page animates. No external assets are used, so it works offline.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/consensys/gnark/logger"

	"github.com/da1suk8/zk-agent-passport/demo"
	"github.com/da1suk8/zk-agent-passport/field"
	"github.com/da1suk8/zk-agent-passport/passport"
	"github.com/da1suk8/zk-agent-passport/verifier"
	"github.com/da1suk8/zk-agent-passport/zkp"
)

//go:embed index.html
var indexHTML []byte

// checkLabels maps the model layer's check keys to display labels. The
// order of checks is owned by passport.GatewayChecks and verifier.Checks.
var checkLabels = map[string]string{
	"issuer-registered":     "Issuer が Registry に登録済み",
	"receipt-signature":     "Ed25519 署名が有効",
	"receipt-unexpired":     "期限内",
	"rating-range":          "rating が 1〜5",
	"receipt-unused":        "receiptId が未使用",
	"issuer-once-per-epoch": "同じ Issuer・Passport・Domain・Epoch で 2 件目でない",
	"keyset-known":          "Committee の鍵セットが既知",
	"certificate-unexpired": "Certificate が期限内",
	"proof-unexpired":       "Proof が期限内",
	"policy-hash":           "policyHash が Policy と一致",
	"policy-match":          "Domain・Epoch が Policy と一致",
	"committee-quorum":      "異なる 2 ノードの署名が有効",
	"nonce-issued":          "nonce がこの Service の発行したもの",
	"nonce-unused":          "nonce が未使用",
	"proof-valid":           "ZK Proof が有効（Committee 2-of-3 署名・持ち主・score ≥ 閾値・receiptCount ≥ 最低件数・Certificate 期限内・Manifest の変更が許可範囲内）",
}

func label(key string) string {
	if l, ok := checkLabels[key]; ok {
		return l
	}
	return key
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	artifacts := flag.String("artifacts", "artifacts", "directory for cached Groth16 keys")
	flag.Parse()
	logger.Disable()

	sys, err := zkp.LoadOrSetup(*artifacts)
	if err != nil {
		log.Fatal(err)
	}
	s := &server{sys: sys}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /api/defaults", s.defaults)
	mux.HandleFunc("POST /api/run", s.run)
	mux.HandleFunc("POST /api/replay", s.replay)
	mux.HandleFunc("POST /api/attack", s.attack)
	mux.HandleFunc("POST /api/other-service", s.otherService)

	httpServer := &http.Server{Addr: *addr, Handler: mux}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	fmt.Printf("zkAgent Passport demo: http://%s  (constraints=%d)\n", *addr, sys.NbConstraints())
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

type server struct {
	sys  *zkp.System
	mu   sync.Mutex
	last *lastRun
}

type lastRun struct {
	world     *demo.World
	challenge passport.Challenge
	pkg       *passport.ProofPackage
}

// RunRequest is what the page sends. Zero values fall back to the defaults.
type RunRequest struct {
	Ratings             []int             `json:"ratings"`
	Threshold           int64             `json:"threshold"`
	MinimumReceiptCount int64             `json:"minimumReceiptCount"`
	CurrentManifest     passport.Manifest `json:"currentManifest"`
	AllowedModelIDs     []string          `json:"allowedModelIds"`
	AllowedPromptHashes []string          `json:"allowedPromptHashes"`
}

// KV is an ordered label/value pair for display.
type KV struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Secret bool   `json:"secret,omitempty"`
}

// Check is one verification item with its outcome.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | fail | skipped
	Detail string `json:"detail,omitempty"`
}

// Step is one animated stage of the flow.
type Step struct {
	ID     string  `json:"id"`
	From   string  `json:"from,omitempty"`
	To     string  `json:"to"`
	Title  string  `json:"title"`
	Gloss  string  `json:"gloss,omitempty"`
	Lines  []KV    `json:"lines,omitempty"`
	Checks []Check `json:"checks,omitempty"`
	Status string  `json:"status"` // ok | rejected | skipped
	Error  string  `json:"error,omitempty"`
}

// RunResponse is the full trace of one run.
type RunResponse struct {
	Steps   []Step            `json:"steps"`
	Outcome string            `json:"outcome"` // authorized | rejected
	Reason  string            `json:"reason,omitempty"`
	Visible []KV              `json:"visible"`
	Hidden  []KV              `json:"hidden"`
	Limit   string            `json:"limitation,omitempty"`
	Stats   map[string]string `json:"stats"`
}

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

func (s *server) defaults(w http.ResponseWriter, _ *http.Request) {
	opts := demo.DefaultOptions()
	vp := demo.DefaultVersionPolicy()
	writeJSON(w, map[string]any{
		"ratings":             opts.Ratings,
		"threshold":           opts.RequiredThreshold,
		"minimumReceiptCount": opts.MinimumReceiptCount,
		"manifest":            opts.Manifest,
		"allowedModelIds":     vp.Allowed[0],
		"allowedPromptHashes": vp.Allowed[1],
		"taskDomain":          demo.TaskDomain,
		"aggregationEpoch":    demo.AggregationEpoch,
		"constraints":         s.sys.NbConstraints(),
		"publicInputs":        s.sys.NbPublicInputs(),
	})
}

func (s *server) run(w http.ResponseWriter, r *http.Request) {
	var req RunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	resp, err := s.execute(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, resp)
}

func (s *server) replay(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil || s.last.pkg == nil {
		http.Error(w, "no proof to replay: run a successful case first", http.StatusBadRequest)
		return
	}
	last := s.last
	resp := &RunResponse{Stats: map[string]string{}}
	start := time.Now()
	decision, err := last.world.Access(last.challenge, last.pkg)
	resp.Stats["verifyTook"] = since(start)
	step := verifyStep(decision, err, "同じ nonce の証明をもう一度送信")
	step.ID = "replay"
	resp.Steps = append(resp.Steps, step)
	if err != nil {
		resp.Outcome = "rejected"
		resp.Reason = verifyReason(err)
	} else {
		resp.Outcome = "authorized"
	}
	resp.Visible, resp.Hidden, resp.Limit = panels(last.world, decision.Authorized)
	writeJSON(w, resp)
}

// AttackRequest names one malicious submission to the gateway.
type AttackRequest struct {
	Kind string `json:"kind"` // forged | unregistered | duplicate | same-issuer | expired
}

// attack submits a bad receipt to the gateway of the last run and reports
// which check stopped it. The gateway's state is untouched by a rejection,
// so attacks can be repeated in any order.
func (s *server) attack(w http.ResponseWriter, r *http.Request) {
	var req AttackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	world, err := s.currentWorld()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	receipt, title, err := craftAttack(world, req.Kind)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, checks, verr := world.Gateway.ValidateReceiptReport(receipt, demo.AggregationEpoch, demo.Now)
	step := Step{ID: "attack", From: "providers", To: "gateway", Title: "攻撃: " + title, Status: "rejected",
		Gloss: "Sybil や Review Farming は暗号では防げない。Gateway の 6 検査のうち、どれが止めたかを見る。"}
	step.Lines = []KV{{Key: "提出された Receipt", Value: fmt.Sprintf("issuer=%s rating=%d id=%s sig=%s", receipt.IssuerID, receipt.Rating, receipt.ReceiptID, short(receipt.Signature, 10))}}
	for _, c := range checks {
		check := Check{Name: label(c.Key), Status: string(c.Status)}
		if c.Err != nil {
			check.Detail = gatewayReason(c.Err)
		}
		step.Checks = append(step.Checks, check)
	}
	reason := "Gateway は受理した（想定外）"
	if verr != nil {
		reason = gatewayReason(verr)
		step.Error = "Gateway が拒否: " + reason
	} else {
		step.Status = "ok"
		step.Error = reason
	}
	writeJSON(w, map[string]any{"step": step, "outcome": step.Status, "reason": reason})
}

// craftAttack builds a malicious receipt against the demo world.
func craftAttack(world *demo.World, kind string) (passport.Receipt, string, error) {
	switch kind {
	case "forged":
		forged := world.Receipts[0]
		forged.Rating = 1
		forged.ReceiptID = "receipt-forged"
		return forged, "Provider A の Receipt の評価を書き換えて再提出（署名は元のまま）", nil
	case "unregistered":
		stranger, err := passport.NewIdentity("unregistered-provider")
		if err != nil {
			return passport.Receipt{}, "", err
		}
		r, err := passport.IssueReceipt(stranger, world.Agent, passport.ReceiptRequest{
			ReceiptID: "receipt-stranger", TaskDomain: demo.TaskDomain, Rating: 5, IssuedAt: demo.Now, ExpiresAt: demo.Now + 3600,
		})
		return r, "Registry に無い Provider が正しく署名した Receipt を提出", err
	case "duplicate":
		return world.Receipts[0], "Provider A の本物の Receipt をもう一度提出（二重集計）", nil
	case "same-issuer":
		r, err := passport.IssueReceipt(world.Issuers[0], world.Agent, passport.ReceiptRequest{
			ReceiptID: "receipt-1b", TaskDomain: demo.TaskDomain, Rating: 5, IssuedAt: demo.Now, ExpiresAt: demo.Now + 3600,
		})
		return r, "Provider A が同じ期間に 2 件目の Receipt を発行（Review Farming）", err
	case "expired":
		r, err := passport.IssueReceipt(world.Issuers[1], world.Agent, passport.ReceiptRequest{
			ReceiptID: "receipt-old", TaskDomain: demo.TaskDomain, Rating: 5, IssuedAt: demo.Now - 7200, ExpiresAt: demo.Now - 3600,
		})
		return r, "Provider B が期限切れの Receipt を提出", err
	default:
		return passport.Receipt{}, "", fmt.Errorf("unknown attack %q", kind)
	}
}

// otherService proves to a second service and shows what that service
// learns: a nullifier unrelated to the first service's, so the two visits
// cannot be linked.
func (s *server) otherService(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	world, err := s.currentWorld()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var nullifierA string
	if s.last != nil && s.last.pkg != nil {
		nullifierA = s.last.pkg.Statement.Nullifier
	}
	const otherName = "travel-insurance-service"
	other := verifier.New(s.sys, world.Keyset, otherName)
	ch, err := other.IssueChallenge(demo.Now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pkg, err := world.Prove(ch)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	decision, verr := other.VerifyAccess(verifier.AccessRequest{
		Policy: world.Policy, Challenge: ch, Proof: pkg, Now: demo.Now,
	})
	step := Step{ID: "link", From: "agent", To: "service",
		Title:  "別の Service（" + otherName + "）に、同じ証明書のまま証明",
		Gloss:  "nullifier = Hash(agentSecret, verifierId)。Service が変われば値も変わるので、2 つの Service が受け取った値を突き合わせても同一 Agent だとは分からない。",
		Status: "ok"}
	if verr != nil {
		step.Status = "rejected"
		step.Error = verr.Error()
	}
	nullifierB := pkg.Statement.Nullifier
	step.Lines = []KV{
		{Key: "判定", Value: map[bool]string{true: "authorized", false: "rejected"}[decision.Authorized]},
		{Key: "nonce（Service B が発行）", Value: short(ch.Nonce, 14)},
		{Key: "Service A が見た nullifier", Value: short(nullifierA, 14)},
		{Key: "Service B が見た nullifier", Value: short(nullifierB, 14)},
	}
	writeJSON(w, map[string]any{
		"step":     step,
		"outcome":  step.Status,
		"linkable": nullifierA != "" && nullifierA == nullifierB,
		"note":     "2 つの Service が受け取る値に共通するものは無い。nullifier は Service ごとに異なるので、両者が突き合わせても同一 Agent だとは分からない。",
	})
}

// currentWorld returns the world of the last run, provisioning a default
// one if the page has not run yet.
func (s *server) currentWorld() (*demo.World, error) {
	if s.last != nil && s.last.world != nil {
		return s.last.world, nil
	}
	world, err := demo.NewWorld(s.sys)
	if err != nil {
		return nil, err
	}
	s.last = &lastRun{world: world}
	return world, nil
}

func (s *server) execute(req RunRequest) (*RunResponse, error) {
	opts := demo.DefaultOptions()
	if len(req.Ratings) > 0 {
		opts.Ratings = req.Ratings
	}
	if req.Threshold > 0 {
		opts.RequiredThreshold = req.Threshold
	}
	if req.MinimumReceiptCount > 0 {
		opts.MinimumReceiptCount = req.MinimumReceiptCount
	}
	if req.CurrentManifest != (passport.Manifest{}) && req.CurrentManifest != opts.Manifest {
		m := req.CurrentManifest
		opts.CurrentManifest = &m
	}
	// Absent allowlists mean the demo default; present-but-empty ones mean
	// the field is immutable.
	if req.AllowedModelIDs != nil || req.AllowedPromptHashes != nil {
		vp := passport.ManifestVersionPolicy{Allowed: map[int][]string{}}
		if len(req.AllowedModelIDs) > 0 {
			vp.Allowed[0] = req.AllowedModelIDs
		}
		if len(req.AllowedPromptHashes) > 0 {
			vp.Allowed[1] = req.AllowedPromptHashes
		}
		opts.VersionPolicy = &vp
	}

	start := time.Now()
	world, err := demo.NewWorldWith(s.sys, opts)
	if err != nil {
		return nil, err
	}
	provisionTook := since(start)
	resp := &RunResponse{Stats: map[string]string{
		"constraints":   fmt.Sprint(s.sys.NbConstraints()),
		"provisionTook": provisionTook,
	}}

	// Step 1: providers issue receipts.
	var receiptLines []KV
	for i, rc := range world.Receipts {
		receiptLines = append(receiptLines, KV{
			Key:   fmt.Sprintf("Provider %s", providerLabel(i)),
			Value: fmt.Sprintf("rating=%d  id=%s  sig=%s", rc.Rating, rc.ReceiptID, short(rc.Signature, 10)),
		})
	}
	resp.Steps = append(resp.Steps, Step{
		ID: "receipts", From: "providers", To: "gateway",
		Title: "1. Task Provider が署名付き Receipt を発行",
		Gloss: "仕事を依頼した側が、この Agent への評価に Ed25519 で署名する。rating が平文で存在するのはこの区間だけ。このデモの Provider は 3 社だが、件数はいくつでもよい。",
		Lines: receiptLines, Status: "ok",
	})

	// Step 2: gateway checks (already passed during provisioning) and sharing.
	var gatewayChecks []Check
	for _, key := range passport.GatewayChecks {
		gatewayChecks = append(gatewayChecks, Check{Name: label(key), Status: "ok"})
	}
	resp.Steps = append(resp.Steps, Step{
		ID: "gateway", From: "gateway", To: "committee",
		Title: "2. Input Gateway が 6 つの検査を通し、rating を Committee の 3 ノードへ share に分割",
		Gloss: "偽造・未登録・重複・同一 Provider の 2 件目・期限切れは、暗号ではなくここで止める。分割数が 3 なのは Committee のノード数が 3 だからで、Provider の社数とは関係ない。Gateway 以降は誰も平文を見ない。",
		Lines: []KV{{Key: "検査した Receipt", Value: fmt.Sprintf("%d 件すべて合格（Provider 1 社につき 1 件）", len(world.Receipts))},
			{Key: "秘密分散", Value: "rating = s1 + s2 + s3（Committee の各ノードは自分の share だけを受け取る）"}},
		Checks: gatewayChecks, Status: "ok",
	})

	// Step 3: committee partial sums and certificate.
	batch := world.BatchKey()
	var committeeLines []KV
	for i, node := range world.Committee {
		committeeLines = append(committeeLines, KV{
			Key:   fmt.Sprintf("Node %d の部分和（share の合計）", i+1),
			Value: short(node.PartialSum(batch), 14),
		})
	}
	cert := world.Issued.Certificate
	committeeLines = append(committeeLines,
		KV{Key: "合計 score（3 つの部分和の和）", Value: world.Issued.Score, Secret: true},
		KV{Key: "scoreCommitment（封筒。合計点は出ない）", Value: short(cert.ScoreCommitment, 14)},
		KV{Key: "receiptCount（Receipt の件数）", Value: cert.ReceiptCount, Secret: true},
		KV{Key: "Certificate への署名", Value: fmt.Sprintf("%s, %s（3 ノード中 2。BabyJubJub の EdDSA）", cert.Signatures[0].NodeID, cert.Signatures[1].NodeID)},
	)
	resp.Steps = append(resp.Steps, Step{
		ID: "committee", From: "committee", To: "agent",
		Title: "3. Committee が部分和だけで合計を出し、2-of-3 で Certificate に署名",
		Gloss: "各ノードが出すのは自分の share の合計だけ。どのノードも個別の評価を復元できない。3 ノード・2-of-3 は回路に焼き込まれた固定値。合計 score は封筒（scoreCommitment）に入り、Agent だけが開ける。",
		Lines: committeeLines, Status: "ok",
	})

	// Step 4: service policy and challenge.
	ch, err := world.NewChallenge()
	if err != nil {
		return nil, err
	}
	pol := world.Policy.Policy
	policyLines := []KV{
		{Key: "分野 requestedTaskDomain", Value: "Travel Booking (" + pol.RequestedTaskDomain + ")"},
		{Key: "求める構成 requestedManifest", Value: short(pol.RequestedManifestCommitment, 14)},
		{Key: "閾値 requiredThreshold", Value: "score ≥ " + pol.RequiredThreshold},
		{Key: "最低件数 minimumReceiptCount", Value: "receiptCount ≥ " + pol.MinimumReceiptCount},
		{Key: "構成変更をどこまで許すか", Value: describeVersionPolicy(*world.Options.VersionPolicy)},
	}
	policyLines = append(policyLines, allowlistLines(*world.Options.VersionPolicy)...)
	policyLines = append(policyLines,
		KV{Key: "許可リストの Merkle root", Value: short(pol.ManifestAllowlistRoot, 14)},
		KV{Key: "使い捨て nonce", Value: short(ch.Nonce, 14)},
		KV{Key: "証明の有効期限 proofExpiresAt", Value: ch.ProofExpiresAt},
	)
	resp.Steps = append(resp.Steps, Step{
		ID: "policy", From: "service", To: "agent",
		Title:  "4. Service が Policy と使い捨て nonce を提示",
		Gloss:  "条件を決めるのは Service。閾値も許す構成も Service ごとに違ってよく、Committee に依頼し直す必要はない。ここが署名方式ではなく ZK を使う理由。",
		Lines:  policyLines,
		Status: "ok",
	})

	// Step 5: agent proves.
	start = time.Now()
	pkg, err := world.Prove(ch)
	proveTook := since(start)
	if err != nil {
		// The proof never leaves the agent, so the failure is shown there.
		resp.Steps = append(resp.Steps, Step{
			ID: "prove", To: "agent",
			Title:  "5. Agent が ZK Proof を生成",
			Gloss:  "条件を満たさないときは、そもそも成立する証明が存在しない。Service に送る前に Agent 側で止まる。",
			Status: "rejected", Error: proveReason(err),
		})
		resp.Steps = append(resp.Steps, Step{
			ID: "verify", To: "service", Title: "6. Service が 5 つの検査で検証", Status: "skipped", Error: "証明が届かないため、Service には何も起きない",
		})
		resp.Outcome = "rejected"
		resp.Reason = proveReason(err)
		resp.Visible, resp.Hidden, resp.Limit = panels(world, false)
		s.last = &lastRun{world: world, challenge: ch}
		return resp, nil
	}
	raw, err := pkg.Proof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	resp.Stats["proveTook"] = proveTook
	resp.Stats["proofBytes"] = fmt.Sprint(len(raw))
	resp.Steps = append(resp.Steps, Step{
		ID: "prove", From: "agent", To: "service",
		Title: "5. Agent が ZK Proof を生成（証明書は手元に残す）",
		Gloss: "合計 score・件数・取引先・agentSecret・証明書そのものは、すべて回路の中の private witness。外へ出るのは証明 1 個と公開入力 20 個だけ。",
		Lines: []KV{
			{Key: "証明時間", Value: proveTook},
			{Key: "Proof サイズ", Value: fmt.Sprintf("%d bytes", len(raw))},
			{Key: "回路が示すこと", Value: "Committee 2-of-3 署名 / Policy のハッシュ一致 / 封筒の中身を知っている / 持ち主である / nullifier の導出 / 分野・期間の一致 / Manifest の変更が許可範囲内 / score ≥ 閾値 / receiptCount ≥ 最低件数 / Certificate が Proof より長く有効"},
			{Key: "Service へ渡すもの", Value: "Proof 164 bytes + 公開入力 20 個（Policy 9・challenge 3・Committee 鍵セット 4・nullifier 1）。証明書は渡さない"},
		},
		Status: "ok",
	})

	// Step 6: service verifies.
	start = time.Now()
	decision, verr := world.Access(ch, pkg)
	resp.Stats["verifyTook"] = since(start)
	resp.Steps = append(resp.Steps, verifyStep(decision, verr, ""))
	if verr != nil {
		resp.Outcome = "rejected"
		resp.Reason = verifyReason(verr)
	} else {
		resp.Outcome = "authorized"
	}
	resp.Visible, resp.Hidden, resp.Limit = panels(world, decision.Authorized)
	s.last = &lastRun{world: world, challenge: ch, pkg: pkg}
	return resp, nil
}

// verifyStep renders the verifier's own check report. The order and the
// outcomes come from the verifier; this function only attaches labels.
func verifyStep(decision verifier.Decision, err error, subtitle string) Step {
	var checks []Check
	for _, c := range decision.Checks {
		check := Check{Name: label(c.Key), Status: string(c.Status)}
		if c.Err != nil {
			check.Detail = verifyReason(c.Err)
		}
		checks = append(checks, check)
	}
	title := "6. Service が 5 つの検査で検証"
	gloss := "証明書は届いていないので、Service が見るのは Policy・challenge・Committee の鍵セット・nullifier だけ。残りはすべて Groth16 の検証が担う。"
	if subtitle != "" {
		title = "Replay: " + subtitle
		gloss = "ZK 証明そのものは今も有効。Replay は暗号ではなく、使い捨て nonce の記録で止める。"
	}
	step := Step{ID: "verify", To: "service", Title: title, Gloss: gloss, Checks: checks, Status: "ok"}
	if err != nil {
		step.Status = "rejected"
		step.Error = verifyReason(err)
		return step
	}
	step.Lines = []KV{
		{Key: "結果", Value: "authorized（Policy の条件をすべて満たしている）"},
		{Key: "この Service 専用の nullifier", Value: short(decision.Nullifier, 14)},
		{Key: "使い捨て nonce", Value: "消費済みとして記録（次は同じ証明を受け付けない）"},
	}
	return step
}

// panels lists what the verifier learns, what it never sees, and the one
// privacy limitation that survives the unlinkability work.
func panels(world *demo.World, authorized bool) (visible, hidden []KV, limitation string) {
	cert := world.Issued.Certificate
	pol := world.Policy.Policy
	result := "rejected"
	if authorized {
		result = "authorized"
	}
	visible = []KV{
		{Key: "判定", Value: result},
		{Key: "受け取ったもの", Value: "Proof と公開入力 20 個だけ（証明書は届かない）"},
		{Key: "分野（自分で指定）", Value: "Travel Booking (" + pol.RequestedTaskDomain + ")"},
		{Key: "評価期間（自分で指定）", Value: pol.RequestedAggregationEpoch},
		{Key: "満たすべき閾値", Value: "score ≥ " + pol.RequiredThreshold + "（実際の score は不明）"},
		{Key: "満たすべき件数", Value: "receiptCount ≥ " + pol.MinimumReceiptCount + "（実際の件数は不明）"},
		{Key: "Agent の現在の構成", Value: short(pol.RequestedManifestCommitment, 14) + manifestDelta(world)},
		{Key: "許した構成変更", Value: describeVersionPolicy(*world.Options.VersionPolicy)},
		{Key: "Committee の鍵セット", Value: world.Keyset.ID + "（全 Agent 共通なので識別子にならない）"},
		{Key: "この Service 専用の nullifier", Value: "他の Service が見る値とは無関係"},
	}
	limitation = "唯一残る限界: 現在の構成のハッシュだけは公開入力に残る。Policy が「この構成であること」を要求する設計だから。同じ製品の Agent 群は同じ値を共有するので、今あるのは「同じ構成のグループの中での匿名性」。個体まで隠すには Policy を「許可された構成の集合」に変える。"

	certifiedManifest := "証明書が結び付いた構成"
	if cert.AgentManifestCommitment == pol.RequestedManifestCommitment {
		certifiedManifest += "（今回は現在の構成と同じ値）"
	} else {
		certifiedManifest += "（現在の構成とは別の値）"
	}
	hidden = []KV{
		{Key: "合計 score", Value: world.Issued.Score, Secret: true},
		{Key: "Receipt の件数", Value: cert.ReceiptCount, Secret: true},
		{Key: "Agent の識別子（passportCommitment）", Value: short(cert.PassportCommitment, 14), Secret: true},
		{Key: certifiedManifest, Value: short(cert.AgentManifestCommitment, 14), Secret: true},
		{Key: "certificateId", Value: short(cert.CertificateID, 14), Secret: true},
		{Key: "scoreCommitment（封筒）", Value: short(cert.ScoreCommitment, 14), Secret: true},
		{Key: "Certificate の期限", Value: cert.ExpiresAt, Secret: true},
	}
	for i, rc := range world.Receipts {
		hidden = append(hidden, KV{Key: fmt.Sprintf("Provider %s が付けた評価", providerLabel(i)), Value: fmt.Sprint(rc.Rating), Secret: true})
		hidden = append(hidden, KV{Key: fmt.Sprintf("取引先 %d の名前", i+1), Value: rc.IssuerID, Secret: true})
	}
	hidden = append(hidden,
		KV{Key: "agentSecret（持ち主の秘密）", Value: short(world.Agent.AgentSecret, 14), Secret: true},
		KV{Key: "scoreSalt（封筒の乱数）", Value: short(world.Issued.ScoreSalt, 14), Secret: true},
	)
	return visible, hidden, limitation
}

// gatewayReason renders the gateway's rejection in the page's language.
func gatewayReason(err error) string {
	switch {
	case errors.Is(err, passport.ErrIssuerAlreadyContributed):
		return "この Provider は同じ Passport・分野・期間ですでに 1 件出している（2 件目は数えない）"
	case errors.Is(err, passport.ErrIssuerNotRegistered):
		return "この Provider は Registry に登録されていない"
	case errors.Is(err, passport.ErrReceiptSignature):
		return "Ed25519 署名が内容と一致しない（評価が書き換えられている）"
	case errors.Is(err, passport.ErrReceiptExpired):
		return "Receipt の有効期限が切れている"
	case errors.Is(err, passport.ErrReceiptReused):
		return "この receiptId はすでに集計に使われている"
	case errors.Is(err, passport.ErrRatingRange):
		return "rating が 1〜5 の範囲にない"
	default:
		return err.Error()
	}
}

// verifyReason renders the verifier's rejection in the page's language.
func verifyReason(err error) string {
	switch {
	case errors.Is(err, verifier.ErrNonceConsumed):
		return "この nonce はすでに使われている。同じ証明は二度受け付けない（Replay 防止）"
	case errors.Is(err, verifier.ErrUnknownNonce):
		return "この Service が発行した nonce ではない"
	case errors.Is(err, verifier.ErrProofExpired):
		return "証明の有効期限が切れている"
	case errors.Is(err, verifier.ErrPolicyHash):
		return "証明が束縛している Policy が、この Service の Policy と一致しない"
	case errors.Is(err, verifier.ErrInvalidProof):
		return "ZK Proof が成立しない（" + trimPrefix(err) + "）"
	default:
		return err.Error()
	}
}

func proveReason(err error) string {
	switch {
	case errors.Is(err, passport.ErrThresholdNotMet):
		return "score が閾値に届かないため、証明を作れない"
	case errors.Is(err, passport.ErrReceiptCountNotMet):
		return "Receipt 件数が Policy の最低件数に届かないため、証明を作れない"
	case errors.Is(err, passport.ErrManifestFieldImmutable):
		return "Policy が変更を許可していない Manifest 項目が変わっているため、証明を作れない（" + trimPrefix(err) + "）"
	case errors.Is(err, passport.ErrManifestValueNotAllowed):
		return "Manifest の新しい値が Policy の許可リストに無いため、証明を作れない（" + trimPrefix(err) + "）"
	case errors.Is(err, passport.ErrPolicyMismatch):
		return "Certificate の Domain・Epoch・Manifest が Policy の要求と一致しないため、証明を作れない"
	default:
		return err.Error()
	}
}

// trimPrefix keeps only the innermost detail of a wrapped manifest error.
func trimPrefix(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return msg
}

// describeVersionPolicy renders which manifest fields may change.
func describeVersionPolicy(vp passport.ManifestVersionPolicy) string {
	var mutable []string
	for i := 0; i < passport.ManifestFieldCount; i++ {
		if vp.Mutable(i) {
			mutable = append(mutable, passport.ManifestFieldNames[i])
		}
	}
	if len(mutable) == 0 {
		return "一切の変更を許さない（strict）"
	}
	return strings.Join(mutable, ", ") + " だけ許可リスト内で変更可 / 他は変更不可"
}

// allowlistLines lists the permitted values per mutable field.
func allowlistLines(vp passport.ManifestVersionPolicy) []KV {
	var lines []KV
	for i := 0; i < passport.ManifestFieldCount; i++ {
		if vp.Mutable(i) {
			lines = append(lines, KV{Key: "  許可: " + passport.ManifestFieldNames[i], Value: strings.Join(vp.Allowed[i], ", ")})
		}
	}
	return lines
}

// manifestDelta notes whether the current manifest differs from the
// certified one.
func manifestDelta(world *demo.World) string {
	if world.Policy.Policy.RequestedManifestCommitment == world.Issued.Certificate.AgentManifestCommitment {
		return "（証明書の発行時と同じ）"
	}
	return "（証明書の発行後に変更あり）"
}

func providerLabel(i int) string {
	return string(rune('A' + i))
}

func short(v field.Element, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n] + "…"
}

func since(t time.Time) string {
	return time.Since(t).Round(100 * time.Microsecond).String()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
