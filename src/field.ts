// Field-element encoding for the gatekeeper circuit (bn128 / Groth16).
//
// Verified empirically against the official artifacts (see
// scripts/probe-circuit.ts): the published public signals for the sample
// task reproduce exactly with these encodings.
//   - VK hashes: plain integer of the 0x hex value, reduced mod the field
//     prime. (NOT keccak — the raw 256-bit hash exceeds the prime, so a
//     plain mod-p reduction is what the circuit expects.)
//   - Addresses: plain integer of the 0x address.
//   - taskId: keccak256 of the task_id string, reduced mod the field prime.
//     ASSUMPTION: the platform binds the proof to the task this way. The
//     proof itself verifies for any consistent encoding; only the platform's
//     own public-input check for taskId depends on this choice. If practice
//     tasks show a taskId mismatch, this is the first place to look.
//   - Numbers (minimum, balance, blocks, amount, cap): plain decimal.
//   - salt: random private field element, never logged, never returned.
import { keccak256 } from "js-sha3";
import { randomBytes } from "node:crypto";

export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Reduce a bigint into the bn128 scalar field, as a decimal string. */
export function fieldMod(n: bigint): string {
  return (((n % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME).toString();
}

/** keccak256 of UTF-8 text, reduced mod the field prime. */
export function keccakField(text: string): string {
  return fieldMod(BigInt("0x" + keccak256(text)));
}

/** A 0x hex value (VK hash or address) as a field element. */
export function hexField(hex: string): string {
  if (!/^0x[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`not a 0x hex value: ${String(hex).slice(0, 24)}`);
  }
  return fieldMod(BigInt(hex));
}

/** A fresh private salt: 31 random bytes reduced mod the field prime. */
export function randomSalt(): string {
  return fieldMod(BigInt("0x" + randomBytes(31).toString("hex")));
}
