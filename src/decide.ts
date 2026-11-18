// Deterministic decision logic — pure function, no I/O, no model calls.
// APPROVE only when EVERY check passes. The first failing check decides
// the reason_code. This is the final safety layer: the circuit is the
// referee, and this code must agree with it — a disagreement surfaces as
// PROOF_FAILED (witness generation refuses) and fails closed to REJECT.
//
// Check order matters: cheap, unambiguous traps first. The circuit itself
// enforces five of these (VK match, threshold, recipient, amount cap,
// expiry); the two it CANNOT enforce are checked here and only here:
//   - the VK must equal the PLATFORM-registered hash (the circuit only
//     checks the two hashes equal each other), and
//   - the proof reference must not have been used before (replay).
// Timestamp freshness and the HMAC are enforced by the server before this
// runs; expiry_block is a circuit check, deadline_at is a server check.
import type { GatekeeperTaskInput } from "./circuit";

export type Decision = "APPROVE" | "REJECT";

export type ReasonCode =
  | "OK"
  | "VK_SUBSTITUTION" // proof_vk != registered_vk
  | "VK_MISMATCH" // registered_vk != platform-registered vkHash
  | "THRESHOLD_NOT_MET" // public_balance < minimum
  | "RECIPIENT_MISMATCH" // recipient != condition_recipient
  | "AMOUNT_EXCEEDS_MAX" // amount > max_transfer
  | "EXPIRED" // current_block >= expiry_block
  | "PROOF_REUSED" // proof_tx seen before
  | "NOT_FINALIZED" // Kurier did not reach Finalized in budget
  | "PROOF_FAILED" // proof generation / local verification failed
  | "INVALID_ENVELOPE" // missing / malformed fields
  | "INVALID_TYPE" // wrong envelope type
  | "STALE_TASK" // issued_at unusable / deadline already passed
  | "TIMEOUT"; // 60s hard deadline hit

/** Reasons the circuit itself can prove as REJECT (decision=0). For these,
 *  a decision=0 proof verifies. All other REJECT reasons have no valid
 *  reject-proof (the circuit's verdict is APPROVE), so the response must
 *  carry no proof.
 *
 *  NOTE: VK_MISMATCH is deliberately NOT in this set. When the two VK
 *  hashes agree with each other but not with the platform's registered key,
 *  the circuit's verdict is APPROVE (it can only check the hashes agree) —
 *  so a decision=0 proof cannot be generated for it. Verified empirically
 *  in the harness: the server correctly falls back to a proof-less REJECT. */
export const CIRCUIT_PROVABLE_REJECTS: ReadonlySet<ReasonCode> = new Set([
  "VK_SUBSTITUTION",
  "THRESHOLD_NOT_MET",
  "RECIPIENT_MISMATCH",
  "AMOUNT_EXCEEDS_MAX",
  "EXPIRED",
]);

export interface DecisionResult {
  decision: Decision;
  reasonCode: ReasonCode;
  /** Human-readable detail for the log only — never sent to the platform. */
  detail: string;
}

function isHexAddress(v: unknown): v is string {
  return typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v);
}

function isHexHash(v: unknown): v is string {
  return typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v);
}

function isUintString(v: unknown): v is string {
  return typeof v === "string" && /^\d+$/.test(v);
}

function isUint(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0;
}

export function validateTaskInput(input: unknown): input is GatekeeperTaskInput {
  if (!input || typeof input !== "object") return false;
  const i = input as Record<string, unknown>;
  return (
    isHexHash(i.registered_vk) &&
    isHexHash(i.proof_vk) &&
    isUintString(i.minimum) &&
    isUintString(i.public_balance) &&
    isUint(i.expiry_block) &&
    isUint(i.current_block) &&
    isHexAddress(i.recipient) &&
    isHexAddress(i.condition_recipient) &&
    isUintString(i.amount) &&
    isUintString(i.max_transfer) &&
    (i.proof_tx === undefined || typeof i.proof_tx === "string")
  );
}

/** Pure decision. `nowMs` is injected for testability. */
export function decideTask(
  input: GatekeeperTaskInput,
  opts: {
    platformVkHash: string;
    isProofTxSeen: (proofTx: string) => boolean;
    nowMs: number;
    deadlineAtMs: number | null;
    issuedAtMs: number | null;
  },
): DecisionResult {
  const fail = (reasonCode: ReasonCode, detail: string): DecisionResult => ({
    decision: "REJECT",
    reasonCode,
    detail,
  });

  // Timestamp: the platform's own deadline is authoritative.
  if (opts.deadlineAtMs !== null && opts.nowMs > opts.deadlineAtMs) {
    return fail("STALE_TASK", "now is past deadline_at");
  }
  if (opts.issuedAtMs !== null && opts.issuedAtMs > opts.nowMs + 5 * 60_000) {
    return fail("STALE_TASK", "issued_at is more than 5 min in the future");
  }

  // 1. VK substitution: the proof's VK differs from the registered VK.
  if (input.proof_vk.toLowerCase() !== input.registered_vk.toLowerCase()) {
    return fail(
      "VK_SUBSTITUTION",
      `proof_vk ${input.proof_vk} != registered_vk ${input.registered_vk}`,
    );
  }
  // 2. The registered VK must be the platform's own registered key. The
  //    circuit cannot check this — it only checks the two hashes agree.
  if (input.registered_vk.toLowerCase() !== opts.platformVkHash.toLowerCase()) {
    return fail(
      "VK_MISMATCH",
      `registered_vk ${input.registered_vk} != platform vk ${opts.platformVkHash}`,
    );
  }
  // 3. Threshold: disclosed balance must meet the minimum.
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    return fail(
      "THRESHOLD_NOT_MET",
      `public_balance ${input.public_balance} < minimum ${input.minimum}`,
    );
  }
  // 4. Recipient must match the condition's recipient.
  if (input.recipient.toLowerCase() !== input.condition_recipient.toLowerCase()) {
    return fail(
      "RECIPIENT_MISMATCH",
      `recipient ${input.recipient} != condition_recipient ${input.condition_recipient}`,
    );
  }
  // 5. Amount must not exceed the maximum transfer.
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    return fail(
      "AMOUNT_EXCEEDS_MAX",
      `amount ${input.amount} > max_transfer ${input.max_transfer}`,
    );
  }
  // 6. Expiry: the condition must still be live at the current block.
  if (input.current_block >= input.expiry_block) {
    return fail(
      "EXPIRED",
      `current_block ${input.current_block} >= expiry_block ${input.expiry_block}`,
    );
  }
  // 7. Replay: a proof reference must never authorize two tasks.
  if (input.proof_tx && opts.isProofTxSeen(input.proof_tx)) {
    return fail("PROOF_REUSED", `proof_tx ${input.proof_tx} already seen`);
  }

  return { decision: "APPROVE", reasonCode: "OK", detail: "all checks pass" };
}
