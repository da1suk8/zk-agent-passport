// Package passport is the protocol layer of zkAgent Passport: the parties, the
// messages they exchange, and the prover. It knows nothing about processes,
// files, or user interfaces; those live under internal/ and cmd/.
//
// A run of the protocol moves through the package in this order.
//
//   - An [Agent] holds agentSecret and passportSalt and declares a [Manifest].
//     Its passport commitment and manifest commitment are what receipts and
//     certificates bind to.
//   - A registered task provider, an [Identity] in an [IssuerRegistry],
//     signs a [Receipt] for a completed task with [IssueReceipt].
//   - The [InputGateway] runs the six [GatewayChecks] on each receipt, turns
//     it into a [ValidatedReceipt], and splits the rating into three additive
//     shares with [ShareRating]. Only the gateway can produce a validated
//     receipt, so nothing unchecked reaches a score.
//   - Three [CommitteeNode] values add their shares and, with
//     [IssueScoreCertificate], sign a [ScoreCertificate] over a
//     [CertificatePayload]. The score itself is returned to the agent as an
//     opening of the certificate's score commitment, and the [CommitteeKeyset]
//     is what a verifier will trust.
//   - A service publishes a [Policy] through [NewPolicy], whose
//     [ManifestVersionPolicy] says which manifest fields may change and to
//     which values, and issues a [Challenge] with [NewChallenge].
//   - [Prove] takes a [ProofRequest] and returns a [ProofPackage]: a Groth16
//     proof plus the public inputs that [BuildStatement] assembles. The
//     certificate stays in the request; the only agent-specific public value
//     is the [Nullifier] for that verifier.
//
// The verifier side of the exchange is package verifier, and the circuit the
// proof is made against is package zkp. Constants shared with the circuit
// ([CommitteeSize], [Quorum], [ManifestFieldCount], [AllowlistDepth]) are
// re-exported here so callers need not import zkp.
//
// The gateway and the verifier report their checks through [CheckRun], one
// entry per check in a fixed order, so user interfaces render outcomes rather
// than re-deriving them.
package passport
