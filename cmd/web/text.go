// Every string the page shows the reader: the labels for the model layer's
// check keys, and the rejection reasons in the page's language. Keeping them
// here means the protocol packages never carry display text.
package main

import (
	"errors"
	"strings"

	"github.com/da1suk8/zk-agent-passport/internal/demo"
	"github.com/da1suk8/zk-agent-passport/passport"
	"github.com/da1suk8/zk-agent-passport/verifier"
)

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
	"nonce-issued":          "nonce がこの Service がこの Policy 向けに発行したもの",
	"nonce-unused":          "nonce が未使用",
	"proof-valid":           "ZK Proof が有効（Committee 2-of-3 署名・持ち主・score ≥ 閾値・receiptCount ≥ 最低件数・Certificate 期限内・Manifest の変更が許可範囲内）",
}

func label(key string) string {
	if l, ok := checkLabels[key]; ok {
		return l
	}
	return key
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
	case errors.Is(err, verifier.ErrPolicyNotChallenged):
		return "この nonce は別の Policy 向けに発行されたもの（Policy をすり替えた証明は受け付けない）"
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
