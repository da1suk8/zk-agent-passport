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
		resp.Reason = err.Error()
	} else {
		resp.Outcome = "authorized"
	}
	resp.Visible, resp.Hidden = panels(last.world, decision.Authorized)
	writeJSON(w, resp)
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
		Title: "1. Task Provider が署名付き Receipt を発行", Lines: receiptLines, Status: "ok",
	})

	// Step 2: gateway checks (already passed during provisioning) and sharing.
	var gatewayChecks []Check
	for _, key := range passport.GatewayChecks {
		gatewayChecks = append(gatewayChecks, Check{Name: label(key), Status: "ok"})
	}
	resp.Steps = append(resp.Steps, Step{
		ID: "gateway", From: "gateway", To: "committee",
		Title: "2. Input Gateway が検査し、rating を 3 つの share に分割",
		Lines: []KV{{Key: "検査した Receipt", Value: fmt.Sprintf("%d 件すべて合格", len(world.Receipts))},
			{Key: "分割", Value: "rating = s1 + s2 + s3（各ノードは自分の share だけを受け取る）"}},
		Checks: gatewayChecks, Status: "ok",
	})

	// Step 3: committee partial sums and certificate.
	batch := world.BatchKey()
	var committeeLines []KV
	for i, node := range world.Committee {
		committeeLines = append(committeeLines, KV{
			Key:   fmt.Sprintf("Node %d の部分和", i+1),
			Value: short(node.PartialSum(batch), 14),
		})
	}
	cert := world.Issued.Certificate
	committeeLines = append(committeeLines,
		KV{Key: "合計 score", Value: world.Issued.Score, Secret: true},
		KV{Key: "scoreCommitment", Value: short(cert.ScoreCommitment, 14)},
		KV{Key: "receiptCount", Value: cert.ReceiptCount, Secret: true},
		KV{Key: "署名", Value: fmt.Sprintf("%s, %s（3 ノード中 2）", cert.Signatures[0].NodeID, cert.Signatures[1].NodeID)},
	)
	resp.Steps = append(resp.Steps, Step{
		ID: "committee", From: "committee", To: "agent",
		Title: "3. Committee が部分和から score を集計し、Certificate に署名",
		Lines: committeeLines, Status: "ok",
	})

	// Step 4: service policy and challenge.
	ch, err := world.NewChallenge()
	if err != nil {
		return nil, err
	}
	pol := world.Policy.Policy
	policyLines := []KV{
		{Key: "requestedTaskDomain", Value: "Travel Booking (" + pol.RequestedTaskDomain + ")"},
		{Key: "requestedManifest", Value: short(pol.RequestedManifestCommitment, 14)},
		{Key: "requiredThreshold", Value: pol.RequiredThreshold},
		{Key: "minimumReceiptCount", Value: pol.MinimumReceiptCount},
		{Key: "Manifest 変更ポリシー", Value: describeVersionPolicy(*world.Options.VersionPolicy)},
	}
	policyLines = append(policyLines, allowlistLines(*world.Options.VersionPolicy)...)
	policyLines = append(policyLines,
		KV{Key: "allowlist root", Value: short(pol.ManifestAllowlistRoot, 14)},
		KV{Key: "nonce", Value: short(ch.Nonce, 14)},
		KV{Key: "proofExpiresAt", Value: ch.ProofExpiresAt},
	)
	resp.Steps = append(resp.Steps, Step{
		ID: "policy", From: "service", To: "agent",
		Title:  "4. Service が Policy と使い捨て nonce を提示",
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
			Status: "rejected", Error: proveReason(err),
		})
		resp.Steps = append(resp.Steps, Step{
			ID: "verify", To: "service", Title: "6. Service が検証", Status: "skipped", Error: "証明が届かないため検証なし",
		})
		resp.Outcome = "rejected"
		resp.Reason = proveReason(err)
		resp.Visible, resp.Hidden = panels(world, false)
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
		Title: "5. Agent が ZK Proof を生成（score と agentSecret は回路の中だけ）",
		Lines: []KV{
			{Key: "証明時間", Value: proveTook},
			{Key: "Proof サイズ", Value: fmt.Sprintf("%d bytes", len(raw))},
			{Key: "回路が示すこと", Value: "Committee 2-of-3 署名 / Policy のハッシュ一致 / 封筒の中身を知っている / 持ち主である / nullifier の導出 / 分野・期間の一致 / Manifest の変更が許可範囲内 / score ≥ 閾値 / receiptCount ≥ 最低件数 / Certificate が Proof より長く有効"},
			{Key: "Service へ渡すもの", Value: "Proof + 公開入力（Policy・nonce・nullifier・keyset）。証明書は渡さない"},
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
		resp.Reason = verr.Error()
	} else {
		resp.Outcome = "authorized"
	}
	resp.Visible, resp.Hidden = panels(world, decision.Authorized)
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
			check.Detail = c.Err.Error()
		}
		checks = append(checks, check)
	}
	title := "6. Service が検証"
	if subtitle != "" {
		title = "Replay: " + subtitle
	}
	step := Step{ID: "verify", To: "service", Title: title, Checks: checks, Status: "ok"}
	if err != nil {
		step.Status = "rejected"
		step.Error = err.Error()
		return step
	}
	step.Lines = []KV{
		{Key: "結果", Value: "authorized"},
		{Key: "nullifier（この Service 専用の識別子）", Value: short(decision.Nullifier, 14)},
		{Key: "nonce", Value: "消費済みとして記録"},
	}
	return step
}

// panels lists what the verifier learns and what it never sees.
func panels(world *demo.World, authorized bool) (visible, hidden []KV) {
	cert := world.Issued.Certificate
	pol := world.Policy.Policy
	result := "rejected"
	if authorized {
		result = "authorized"
	}
	visible = []KV{
		{Key: "判定", Value: result},
		{Key: "分野（Policy）", Value: "Travel Booking (" + pol.RequestedTaskDomain + ")"},
		{Key: "評価期間（Policy）", Value: pol.RequestedAggregationEpoch},
		{Key: "閾値の条件", Value: "score ≥ " + pol.RequiredThreshold},
		{Key: "件数の条件", Value: "receiptCount ≥ " + pol.MinimumReceiptCount + "（件数自体は非開示）"},
		{Key: "要求した Manifest", Value: short(pol.RequestedManifestCommitment, 14) + manifestDelta(world)},
		{Key: "変更ポリシー", Value: describeVersionPolicy(*world.Options.VersionPolicy)},
		{Key: "Committee keyset", Value: world.Keyset.ID + "（全 Agent 共通）"},
		{Key: "nullifier", Value: "この Service 専用。他の Service とは無関係"},
	}
	hidden = []KV{
		{Key: "合計 score", Value: world.Issued.Score, Secret: true},
		{Key: "Receipt 件数", Value: cert.ReceiptCount, Secret: true},
		{Key: "Passport commitment", Value: short(cert.PassportCommitment, 14), Secret: true},
		{Key: "Certificate の Manifest", Value: short(cert.AgentManifestCommitment, 14), Secret: true},
		{Key: "certificateId", Value: short(cert.CertificateID, 14), Secret: true},
		{Key: "scoreCommitment（封筒）", Value: short(cert.ScoreCommitment, 14), Secret: true},
		{Key: "Certificate の期限", Value: cert.ExpiresAt, Secret: true},
	}
	for i, rc := range world.Receipts {
		hidden = append(hidden, KV{Key: fmt.Sprintf("Provider %s の評価", providerLabel(i)), Value: fmt.Sprint(rc.Rating), Secret: true})
		hidden = append(hidden, KV{Key: fmt.Sprintf("取引先 %d", i+1), Value: rc.IssuerID, Secret: true})
	}
	hidden = append(hidden,
		KV{Key: "agentSecret", Value: short(world.Agent.AgentSecret, 14), Secret: true},
		KV{Key: "scoreSalt", Value: short(world.Issued.ScoreSalt, 14), Secret: true},
	)
	return visible, hidden
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
		return "変更不可（strict）"
	}
	return strings.Join(mutable, ", ") + " は許可リスト内で変更可 / 他は不可"
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
		return "（発行時と同じ）"
	}
	return "（発行時から変更あり）"
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
