// HTTP handlers. Each one decodes a request, runs the real protocol through
// the demo world, and writes a trace the page can animate.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/da1suk8/zk-agent-passport/internal/demo"
	"github.com/da1suk8/zk-agent-passport/verifier"
)

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
	ch, err := other.IssueChallenge(demo.Now, world.Policy.PolicyHash)
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
