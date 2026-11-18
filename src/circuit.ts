// Local Groth16 proving with snarkjs against the official gatekeeper
// artifacts. The circuit (GatekeeperEvaluation_79, 647 witness signals,
// 13 public signals) enforces, symmetrically, that `decision` equals the
// computed verdict: APPROVE (1) iff every check passes, REJECT (0) iff at
// least one fails. A wrong decision cannot even build a witness —
// fullProve throws instead of producing a bad proof.
//
// Input signals (13, recovered by probing the compiled WASM):
//   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
//   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
//   decision, taskId, salt (private — never in the public signals).
// Public signals (13) come back in this order:
//   [commitment, registeredVkHash, proofVkHash, minimum, publicBalance,
//    expiryBlock, currentBlock, recipient, conditionRecipient, amount,
//    maxTransfer, decision, taskId]
import * as snarkjs from "snarkjs";
import fs from "node:fs";
import { fieldMod, hexField, keccakField, randomSalt } from "./field";

export interface GatekeeperTaskInput {
  registered_vk: string;
  proof_vk: string;
  minimum: string;
  public_balance: string;
  expiry_block: number;
  current_block: number;
  recipient: string;
  condition_recipient: string;
  amount: string;
  max_transfer: string;
  proof_tx?: string;
}

export interface CircuitInput {
  registeredVkHash: string;
  proofVkHash: string;
  minimum: string;
  publicBalance: string;
  expiryBlock: string;
  currentBlock: string;
  recipient: string;
  conditionRecipient: string;
  amount: string;
  maxTransfer: string;
  decision: string;
  taskId: string;
  salt: string;
}

export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

export function buildCircuitInput(
  task: GatekeeperTaskInput,
  taskId: string,
  decision: 0 | 1,
): CircuitInput {
  return {
    registeredVkHash: hexField(task.registered_vk),
    proofVkHash: hexField(task.proof_vk),
    minimum: fieldMod(BigInt(task.minimum)),
    publicBalance: fieldMod(BigInt(task.public_balance)),
    expiryBlock: fieldMod(BigInt(task.expiry_block)),
    currentBlock: fieldMod(BigInt(task.current_block)),
    recipient: hexField(task.recipient),
    conditionRecipient: hexField(task.condition_recipient),
    amount: fieldMod(BigInt(task.amount)),
    maxTransfer: fieldMod(BigInt(task.max_transfer)),
    decision: String(decision),
    taskId: keccakField(taskId),
    salt: randomSalt(),
  };
}

export class Prover {
  private vk: unknown | null = null;

  constructor(
    private wasmPath: string,
    private zkeyPath: string,
    private vkJsonPath: string,
  ) {}

  private loadVk(): unknown {
    if (!this.vk) {
      this.vk = JSON.parse(fs.readFileSync(this.vkJsonPath, "utf8"));
    }
    return this.vk;
  }

  /** Generate a Groth16 proof for the given circuit input. Throws if the
   *  decision does not match the circuit's computed verdict. */
  async prove(input: CircuitInput): Promise<{
    proof: Groth16Proof;
    publicSignals: string[];
  }> {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input as unknown as Record<string, string>,
      this.wasmPath,
      this.zkeyPath,
    );
    return { proof: proof as Groth16Proof, publicSignals: publicSignals as string[] };
  }

  /** Verify a proof locally against the verification key exported from the
   *  official zkey. This is the same math the chain runs. */
  async verifyLocal(
    proof: Groth16Proof,
    publicSignals: string[],
  ): Promise<boolean> {
    try {
      return await snarkjs.groth16.verify(this.loadVk(), publicSignals, proof);
    } catch {
      return false;
    }
  }
}
