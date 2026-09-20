# Design notes

Why the protocol is shaped the way it is, what the circuit actually enforces,
and where it stops. The entry point is [the README](../README.md); the Japanese
version of this document is [design-notes.ja.md](design-notes.ja.md).

## Stack

| Layer | Choice |
|---|---|
| Language and runtime | Go 1.25, no external services |
| Proof system | Groth16 on BN254, via gnark |
| In-circuit hash and commitments | Poseidon2 |
| Committee signatures | EdDSA on BabyJubJub, MiMC challenge, verified in-circuit |
| Provider signatures | Ed25519, verified by the gateway |
| Score aggregation | Three-party additive secret sharing |
| Browser demo | Go `net/http` plus one embedded HTML page, no CDN |

## Circuit

- All in-circuit hashing and commitments use Poseidon2. SHA-256 is used only at
  the application boundary to map identifiers into the field. The EdDSA
  challenge hash is MiMC, which is what gnark's signature gadget expects.
- The twenty public inputs are nine policy fields, three challenge fields, the
  nullifier, the keyset id, and three public keys of two coordinates each.
  Everything about the certificate is a private witness.
- Committee signatures are verified inside the circuit against that keyset. Each
  of the two signatures carries a private index into the keyset, selected with a
  two-bit decomposition that also rejects the out-of-range value; the two
  indices must differ, so one node cannot sign twice.
- Provider signatures on receipts stay Ed25519 and are verified by the gateway
  outside the circuit. They never reach a verifier. Verifying them in-circuit
  would mean reading every receipt, which is neither needed nor affordable.
- Score, receipt count, and the certificate expiry are compared against their
  public counterparts as unsigned 32-bit values, with both operands
  range-checked so the difference cannot wrap around the field.
- Groth16 does not bind public inputs that appear in no constraint. Every public
  input here is used by some constraint except the nonce, which is therefore
  constrained to be non-zero. That is what makes replay fail at the proof level
  rather than only at the verifier's bookkeeping.
- The verifier rebuilds the public witness from its own policy, challenge and
  keyset, taking only the nullifier from the prover, so a proof for any other
  statement is rejected by the pairing check itself.

## Manifest binding

Reputation binds to `Hash(modelId, systemPromptHash, toolPolicyHash,
permissionScope)`, not to a name. Change any of them and the commitment changes,
so a reconfigured agent does not silently inherit the record of the one it
replaced. This is the property a human reputation system does not need and an
agent one cannot do without.

Strict binding would make every prompt fix cost the agent its history, so a
policy may permit change. It carries a bit mask of mutable fields and the Merkle
root of an allowlist of (field, value) pairs, both bound by the policy hash. The
circuit opens the certified and the current manifest commitments and, for every
field, requires either equality or a set mutable bit together with a valid
inclusion path for the new value. A strict policy is the mask zero, which
reduces to plain equality.

## Replay protection

A proof is a transferable object, so the nonce alone is not enough. The verifier
issues the nonce, records it as pending together with the hash of the policy it
published alongside it, accepts only nonces it issued for that policy, and
consumes it on success. The proof is bound to `verifierId`, `nonce`,
`proofExpiresAt` and `policyHash`, which rejects reuse at another service, under
another policy, after expiry, or a second time.

## Integrity lives in the model layer

- Only the gateway can produce a `ValidatedReceipt`, and the committee
  aggregates nothing else, so an unchecked receipt cannot reach a score.
- Only the verifier issues challenges, and it accepts only nonces it issued, so
  a proof cannot be bound to a self-made nonce. A nonce carries the policy it
  was issued for, so a proof made for some weaker policy cannot be presented
  against this verifier's challenge either.
- The verifier and the gateway own the order of their checks and report each
  outcome; user interfaces render that report instead of re-deriving it.
- With the certificate hidden, the verifier's own checks reduce to five: the
  proof is unexpired, the policy hash matches the policy, the nonce was issued
  here for this policy, the nonce is unused, and the proof verifies. Certificate
  expiry, the committee quorum and the policy match are proven, not checked.

## Where the constraints go

| Component | Constraints | Share |
|---|---:|---:|
| Committee signatures (EdDSA on BabyJubJub, 2 of them) | 15,538 | 54% |
| Manifest version policy (4 fields, each leaf + depth-4 Merkle + checks) | 6,776 | 24% |
| Certificate hash (10 inputs) | 1,861 | 7% |
| Manifest openings (2 × 4 inputs) | 1,490 | 5% |
| Policy hash (8 inputs) | 1,489 | 5% |
| Commitment openings (score, passport, nullifier) | 1,119 | 4% |
| 32-bit comparisons (score, receipt count, expiry) | 297 | 1% |
| Keyset selection and signer distinctness | 22 | 0% |

The circuit grew in two steps, which makes the cost of each privacy property
visible. Proving a threshold against a public certificate takes 3,829
constraints and about 17 ms. Adding the manifest version policy brings it to
12,570 and 34 ms. Verifying the committee quorum in-circuit, which is what hides
the certificate, accounts for the rest.

Regenerate the table with `go run ./cmd/bench -n 20`.

## Trust assumptions and non-goals

The MVP keeps the Issuer Registry, the Input Gateway and the Committee fixed and
trusted.

- Registered providers issue honest receipts. Fake reviews, review farming,
  Sybil identities and collusion with an issuer are outside what cryptography
  settles here; the gateway's checks raise the cost but do not remove it.
- The gateway sees plaintext ratings. Secret sharing hides them from the
  committee nodes, not from the gateway. Removing the gateway would mean
  providers sharing directly to the committee, with the rating range proven
  rather than inspected.
- The committee is semi-honest and its three nodes run in one process here, so
  the aggregation is a faithful simulation rather than a distributed protocol.
  Additive sharing also needs all three partial sums, which a Shamir scheme
  would relax.
- Two signatures prevent a single node from issuing a certificate. They do not
  withstand two malicious nodes.
- A manifest binds a declaration, not an execution. Whether the agent really ran
  that model with those tools is a remote-attestation question, and TEE work
  composes with this rather than competing with it.
- The Groth16 setup here is single-party and for development only.
- Certificate revocation and real threshold signatures are not implemented.
- The verifier's nonce bookkeeping only grows: a pending nonce that is never
  used is never swept, and a consumed one is remembered forever. Dropping
  entries past `proofExpiresAt` would be sound, because `proof-unexpired`
  rejects an expired proof before the nonce checks run.
- The protocol types are not safe for concurrent use, and `cmd/service` rewrites
  its state file in place rather than atomically. The browser demo serializes
  requests with a mutex instead of making the packages concurrent.

Circuit-bound identifiers use finite-field encodings, so the demo uses numeric
identifiers for `taskDomain`, `aggregationEpoch` and keyset versions;
human-readable names stay at the application boundary.

## Relation to the specification

The project implements the proposal in
[zk-tokyo/advanced-cryptography-2026#124](https://github.com/zk-tokyo/advanced-cryptography-2026/issues/124).
Every item in its Scope is built: the passport and manifest commitments, signed
receipts with the six gateway checks, additive three-party aggregation with a
2-of-3 certificate, the policy-bound proof, and stateful replay protection. The
proposal also named its own privacy limits and listed the extensions that would
lift them, and the MVP went on to build those, so the proposal's limitation
section no longer describes the code.

| The proposal | The code |
|---|---|
| The verifier checks the certificate's signatures and expiry itself and reads `passportCommitment` and `agentManifestCommitment` from it, so visits to two services are linkable | The certificate never leaves the agent. Signatures, quorum and expiry are verified in-circuit, and the verifier learns a per-service nullifier instead of the passport commitment |
| `receiptCount` is public and the verifier compares it with the policy | `receiptCount` is a private witness, compared in-circuit |
| The proof is bound to a public `certificateHash` | There is no public certificate hash. The certificate is a private witness whose hash the circuit recomputes and checks the signatures against |
| Certificate signatures verified in ZK, per-service nullifiers, hidden receipt counts: future work | Built |
| Manifest Version Policy: future work | Built. The policy gains a mutable-field mask and an allowlist root, so it has eight fields rather than six |
| Web UI: a stretch goal | `cmd/web` |
| Agent Alpha as a CLI process or a script | `cmd/agent` and `cmd/service` as separate single-shot processes, and `cmd/demo` as the script |

The non-goals stand: no revocation, no threshold signatures, no FHE, no real
LLM agent, one domain, no testnet, and a single-party setup.

The review on that issue asked for three things: a diagram naming the
stakeholders and the stack, a position on what an agent *is* when it runs as a
single-shot function rather than a resident process, and a quantitative account
of the cost the privacy stack adds. They are answered by the
[README's architecture diagram](../README.md#how-it-works), by `cmd/agent`
(the unit of identity is the holder of `agentSecret` plus the declared
manifest, so a serverless execution that loads the same secret and manifest is
the same agent), and by `cmd/bench` with the
[constraint breakdown above](#where-the-constraints-go).
