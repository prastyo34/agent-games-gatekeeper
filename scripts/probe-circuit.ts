// One-off empirical check of the official gatekeeper circuit.
// Proves: (a) my input encoding matches the circuit (public signals layout),
// (b) a valid task proves APPROVE and verifies, (c) traps refuse APPROVE
//     but prove REJECT, (d) a wrong decision cannot build a witness.
// Run: npx tsx scripts/probe-circuit.ts
import * as snarkjs from "snarkjs";
import { randomBytes } from "node:crypto";
import { keccak256 } from "js-sha3";
import fs from "node:fs";

const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const WASM = "circuits/gatekeeper.wasm";
const ZKEY = "circuits/gatekeeper_final.zkey";
const VK_JSON = "circuits/verification_key.json";

function fieldMod(n: bigint): string {
  return ((n % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME + "";
}

function keccak256Mod(data: string | Buffer): string {
  const hex = keccak256(data);
  return fieldMod(BigInt("0x" + hex));
}

function buildInput(o: {
  registeredVk: string;
  proofVk: string;
  minimum: string;
  publicBalance: string;
  expiryBlock: number;
  currentBlock: number;
  recipient: string;
  conditionRecipient: string;
  amount: string;
  maxTransfer: string;
  decision: number;
  taskId: string;
  salt?: bigint;
}) {
  return {
    registeredVkHash: fieldMod(BigInt(o.registeredVk)),
    proofVkHash: fieldMod(BigInt(o.proofVk)),
    minimum: o.minimum,
    publicBalance: o.publicBalance,
    expiryBlock: String(o.expiryBlock),
    currentBlock: String(o.currentBlock),
    recipient: BigInt(o.recipient).toString(),
    conditionRecipient: BigInt(o.conditionRecipient).toString(),
    amount: o.amount,
    maxTransfer: o.maxTransfer,
    decision: String(o.decision),
    taskId: keccak256Mod(o.taskId),
    salt: fieldMod(o.salt ?? BigInt("0x" + randomBytes(31).toString("hex"))),
  };
}

const RECIPIENT = "0xDe42000000000000000000000000000000009f01";
const BASE = {
  registeredVk: VK_HASH,
  proofVk: VK_HASH,
  minimum: "1000",
  publicBalance: "1460",
  expiryBlock: 8430000,
  currentBlock: 8420000,
  recipient: RECIPIENT,
  conditionRecipient: RECIPIENT,
  amount: "500",
  maxTransfer: "1000",
  taskId: "gk_8d31_probe001",
};

async function main() {
  const vk = JSON.parse(fs.readFileSync(VK_JSON, "utf8"));
  console.log("VK nPublic:", vk.nPublic);

  // 1. Valid task, APPROVE
  const inputApprove = buildInput({ ...BASE, decision: 1 });
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputApprove,
    WASM,
    ZKEY,
  );
  console.log("\nAPPROVE publicSignals:");
  publicSignals.forEach((s: string, i: number) => console.log(`  [${i}] ${s}`));
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  console.log("APPROVE verifies:", ok);

  // Expected layout checks
  const expectVk = fieldMod(BigInt(VK_HASH));
  const checks: Array<[string, boolean]> = [
    ["[1]==[2]==vkHash mod p", publicSignals[1] === expectVk && publicSignals[2] === expectVk],
    ["[3]==minimum 1000", publicSignals[3] === "1000"],
    ["[4]==balance 1460", publicSignals[4] === "1460"],
    ["[5]==expiry 8430000", publicSignals[5] === "8430000"],
    ["[6]==current 8420000", publicSignals[6] === "8420000"],
    ["[7]==[8]==recipient int", publicSignals[7] === publicSignals[8] && publicSignals[7] === BigInt(RECIPIENT).toString()],
    ["[9]==amount 500", publicSignals[9] === "500"],
    ["[10]==max 1000", publicSignals[10] === "1000"],
    ["[11]==decision 1", publicSignals[11] === "1"],
    ["[12]==keccak(taskId) mod p", publicSignals[12] === keccak256Mod(BASE.taskId)],
  ];
  for (const [name, pass] of checks) console.log(`  ${pass ? "PASS" : "FAIL"} ${name}`);
  if (!ok || checks.some(([, p]) => !p)) {
    console.error("ENCODING MISMATCH — stop, do not build on this.");
    process.exit(1);
  }

  // 2. Valid task, REJECT must fail witness generation
  try {
    await snarkjs.groth16.fullProve(buildInput({ ...BASE, decision: 0 }), WASM, ZKEY);
    console.log("\nFAIL: valid task + REJECT produced a proof (circuit did not refuse)");
    process.exit(1);
  } catch (e: any) {
    console.log("\nValid task + REJECT refused as expected:", String(e.message).slice(0, 120));
  }

  // 3. Trap (balance 900 < minimum 1000): APPROVE must fail, REJECT must verify
  try {
    await snarkjs.groth16.fullProve(
      buildInput({ ...BASE, publicBalance: "900", decision: 1 }),
      WASM,
      ZKEY,
    );
    console.log("FAIL: trap + APPROVE produced a proof");
    process.exit(1);
  } catch (e: any) {
    console.log("Trap + APPROVE refused as expected:", String(e.message).slice(0, 120));
  }
  const trapReject = await snarkjs.groth16.fullProve(
    buildInput({ ...BASE, publicBalance: "900", decision: 0 }),
    WASM,
    ZKEY,
  );
  const trapOk = await snarkjs.groth16.verify(vk, trapReject.publicSignals, trapReject.proof);
  console.log("Trap + REJECT verifies:", trapOk);
  if (!trapOk) process.exit(1);

  console.log("\nPROBE OK — encoding confirmed, circuit behaves as documented.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
