# Proof Gatekeeper — zkVerify Agent Games Season 01

A production-ready HTTPS agent for the **Proof Gatekeeper** track: it receives
signed task envelopes, makes a deterministic APPROVE/REJECT decision, proves
that decision with the tournament's own Groth16 circuit (generated locally
with snarkjs), optionally finalizes the proof on zkVerify via Kurier, and
returns a signed response. **Fail-closed everywhere**: any timeout, error, or
uncertainty ends in REJECT — never approve by default.

> Season 01 runs 21 Oct – 21 Nov 2026. This build was completed late in the
> season (18 Nov) — it is still usable for the remaining rounds, practice
> tasks, and as a Creator Track artefact.

## Verified facts (checked, not assumed)

- Spec: https://agentgames.zkverify.io/build and /guide; circuit info:
  https://agentgames.zkverify.io/api/circuit-info
- Gatekeeper `vkHash` (registered on zkVerify mainnet):
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- Artifacts (in `circuits/`, SHA-256 verified against the published sizes):
  `gatekeeper.wasm` 1,755,820 bytes, `gatekeeper_final.zkey` 309,750 bytes
- Circuit: `GatekeeperEvaluation_79`, Groth16/BN128, Circom 2.x, 647 witness
  signals, **13 public signals**, verification key exported to
  `circuits/verification_key.json` with snarkjs 0.7.5
- The 13 input signals are **not documented on the /build page** — they were
  recovered by probing the compiled WASM (FNV-1a signal table), matching
  independent community write-ups:
  `registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
  currentBlock, recipient, conditionRecipient, amount, maxTransfer,
  decision, taskId, salt`
  (`decision`: 1 = approve, 0 = reject; `salt` is the only private input)
- Encoding **verified empirically** (`npm run probe`): a valid task proves
  APPROVE and verifies; a valid task + REJECT refuses at the circuit assert
  (line 102); every trap + APPROVE refuses; every trap + REJECT verifies.
  Public-signal order:
  `[commitment, registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, decision, taskId]`
  - VK hashes: plain integer of the 0x value mod the bn128 field prime
    (confirmed: `int(0x6b79…) mod p` reproduces the published public
    signals exactly — it is NOT keccak)
  - Addresses: plain integer of the 0x address
  - `taskId`: keccak256 of the task_id string mod the field prime (see
    Assumptions below)
- Kurier REST flow verified against the official docs
  (https://docs.zkverify.io/overview/getting-started/kurier):
  `POST /submit-proof/{API_KEY}` → `GET /job-status/{API_KEY}/{jobId}`,
  poll every 5 s until `Finalized`.

## File structure

```
agent-games-gatekeeper/
  circuits/                  gatekeeper.wasm, gatekeeper_final.zkey,
                             verification_key.json (exported from the zkey)
  src/
    server.ts                HTTP server: raw-body HMAC, routing, deadlines
    decide.ts                deterministic decision logic (pure, testable)
    circuit.ts               snarkjs proving + local verification
    kurier.ts                Kurier submit + poll-until-Finalized
    hmac.ts                  HMAC-SHA256 sign/verify (timing-safe)
    field.ts                 bn128 field encoding helpers
    config.ts                env loading + validation
    store.ts                 seen proof_tx store + decision log
    snarkjs.d.ts             minimal typings (snarkjs ships none)
  scripts/
    probe-circuit.ts         one-off empirical circuit check (see above)
    harness.ts               offline test harness (11 cases)
  data/                      runtime state (git-ignored): seen-proof-tx.json,
                             decisions.jsonl
  .env.example               blank secrets template
```

## Setup

```sh
npm install
cp .env.example .env
# Edit .env — set AGENT_GAMES_HMAC_SECRET from the dashboard (Rotate Secret).
# Set KURIER_API_KEY (https://kurier.xyz) for on-chain finalization.
npm run build
npm start
```

Run **compiled** (`npm start` → `node dist/server.js`). On this VM, `tsx`
hangs when loading snarkjs; the compiled path proves in ~2–4 s per task.

## Test

```sh
npm test        # builds, starts the server on :3101, replays 11 cases
npm run probe   # re-runs the empirical circuit check
```

Harness cases: preflight, valid → APPROVE (proof verifies), VK substitution,
VK mismatch (hashes agree with each other but not the platform),
threshold, recipient mismatch, amount overflow, expired, proof reuse,
bad HMAC → 401, stale deadline. Every response signature is verified and
every attached proof is re-verified with snarkjs.

## Deploy

1. Put the service behind TLS (Caddy / nginx on a VPS, or any PaaS that
   gives you a public HTTPS URL). The platform requires HTTPS and posts to
   the URL **exactly as registered** — register the full handler path,
   e.g. `https://agent.example.com/agent`, not just the domain.
2. Set the environment on the host (same `.env` keys). Never commit `.env`.
3. On the Agent Games dashboard: register the endpoint, then **Rotate
   Secret**, copy the one-time plaintext into `AGENT_GAMES_HMAC_SECRET`,
   restart, and run preflight. Preflight must pass before the platform
   marks the agent active.
4. Start with unscored practice tasks before entering a scored round.

## Decision policy

`src/decide.ts` is the whole policy, in order (first failure wins):

| Check | Reason code | Circuit-provable as REJECT? |
|---|---|---|
| HMAC invalid (before parsing) | 401, no decision | — |
| Wrong envelope type | `INVALID_TYPE` | no |
| Malformed input fields | `INVALID_ENVELOPE` | no |
| Past `deadline_at` / absurd `issued_at` | `STALE_TASK` | no |
| `proof_vk != registered_vk` | `VK_SUBSTITUTION` | yes |
| `registered_vk != platform vkHash` | `VK_MISMATCH` | no — circuit verdict is APPROVE for matched hashes |
| `public_balance < minimum` | `THRESHOLD_NOT_MET` | yes |
| `recipient != condition_recipient` | `RECIPIENT_MISMATCH` | yes |
| `amount > max_transfer` | `AMOUNT_EXCEEDS_MAX` | yes |
| `current_block >= expiry_block` | `EXPIRED` | yes |
| `proof_tx` seen before | `PROOF_REUSED` | no |
| Approve-proof generation/verify fails | `PROOF_FAILED` | no |
| Kurier not `Finalized` in budget (strict) | `NOT_FINALIZED` | no |
| 60 s deadline hit | `TIMEOUT` | no |

Two checks live **only in code**, because the circuit cannot enforce them:
the VK must equal the platform-registered hash (the circuit only checks the
two hashes agree with each other — a matched pair of wrong hashes still
proves), and a proof reference must never authorize two tasks (replay).

For REJECT decisions the service attaches a decision=0 proof whenever the
circuit can prove that rejection (the five trap rows above). For code-only
rejects (`VK_MISMATCH`, `PROOF_REUSED`, `NOT_FINALIZED`, …) no valid
reject-proof exists — the circuit's verdict there is APPROVE — so the
response carries no proof, by design.

For APPROVE, the service requires: all checks pass, local snarkjs
verification passes, **and** Kurier reaches `Finalized` within the
remaining budget (when `KURIER_STRICT=true`, the default). If Kurier is
unreachable or times out, the task is rejected with `NOT_FINALIZED`.
Set `KURIER_STRICT=false` only to fall back to local verification.

## Kurier notes

- Mainnet: `https://api.kurier.xyz/api/v1` (default). Testnet:
  `https://api-testnet.kurier.xyz/api/v1`.
- The gatekeeper VK is registered on zkVerify **mainnet**. Testnet Kurier
  cannot finalize a proof against a mainnet-registered VK, so testnet is
  only useful for plumbing checks (with `KURIER_STRICT=false`). Kurier
  submission itself moves no funds — it is a verification API, not a
  wallet transaction — so mainnet Kurier is safe to use for practice.
- If `KURIER_API_KEY` is empty, Kurier is skipped entirely and the service
  approves on local verification only, with a loud warning in the log.
  Do not run a scored round like that.

## Assumptions & risks (read before competing)

1. **`taskId` encoding.** `keccak256(task_id string) mod p` is the natural
   reading of the community findings, but the platform's own public-input
   check for `taskId` is not published. The proof verifies regardless; only
   a platform-side taskId comparison could disagree. If practice tasks
   report a taskId mismatch, `src/field.ts:keccakField` is the place to
   change — and the decision log (`data/decisions.jsonl`) records every
   public-signals set for comparison.
2. **HMAC wire format.** The docs say "HMAC over the raw body" without
   pinning the hash or the header encoding. This service uses HMAC-SHA256
   and accepts both bare hex and `sha256=<hex>` on input; it signs
   responses as bare hex. If preflight fails with a signature error, this
   is the first thing to check against a real platform request.
3. **60 s budget.** Proving takes ~2–4 s on this VM; Kurier finalization
   typically ~15–30 s. The service reserves 5 s for the response and
   polls Kurier only within the remaining budget.
4. **Replay store is local.** `data/seen-proof-tx.json` survives restarts
   on one host. If you ever run two instances behind one endpoint, share
   this state (or accept that cross-instance replays are not caught).
5. **No model in the loop.** The final call is deterministic code only,
   as required. Nothing here sends task data to any language model.

## Security

- Secrets come from environment variables only. `.env` is git-ignored;
  `.env.example` ships blank values.
- No secret is ever logged (the HMAC secret, Kurier key, and circuit
  `salt` never appear in logs or responses).
- Responses are signed over the exact raw bytes sent.
- The server binds `0.0.0.0:$PORT` and expects TLS termination in front
  of it; do not expose it to the internet without HTTPS.
