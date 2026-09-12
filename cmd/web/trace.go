// The wire types the page consumes, and the code that turns one protocol run
// into them. A step is one stage of the flow; panels list what the verifier
// learns and what it never sees.
package main

import (
	"fmt"
	"time"

	"github.com/da1suk8/zk-agent-passport/field"
	"github.com/da1suk8/zk-agent-passport/internal/demo"
	"github.com/da1suk8/zk-agent-passport/passport"
	"github.com/da1suk8/zk-agent-passport/verifier"
)

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
