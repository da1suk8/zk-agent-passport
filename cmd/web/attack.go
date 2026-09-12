// The malicious receipts the page can submit to the gateway. Each one is a
// real receipt that fails exactly one of the gateway's six checks.
package main

import (
	"fmt"

	"github.com/da1suk8/zk-agent-passport/internal/demo"
	"github.com/da1suk8/zk-agent-passport/passport"
)

// AttackRequest names one malicious submission to the gateway.
type AttackRequest struct {
	Kind string `json:"kind"` // forged | unregistered | duplicate | same-issuer | expired
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
