// Local test harness: replays signed sample envelopes against a freshly
// built server and checks decisions, response signatures, and that every
// attached proof verifies locally with snarkjs.
// Run: npm test   (builds first, then runs this against dist/server.js)
// Kurier is disabled here (no API key) — the harness tests the decision +
// proving path offline. Kurier polling is covered by code review + the
// documented flow; run a live smoke test with a real key before competing.
import { spawn, type ChildProcess } from "node:child_process";
import { createHmac } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as snarkjs from "snarkjs";

const TEST_SECRET = "harness-test-secret-do-not-use-in-production";
const PORT = 3101;
const BASE = `http://127.0.0.1:${PORT}`;
const VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RECIPIENT = "0xDe42000000000000000000000000000000009f01";
const PROOF_TX =
  "0xa8b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f802c";

interface CaseResult {
  name: string;
  pass: boolean;
  detail: string;
}

const results: CaseResult[] = [];
function record(name: string, pass: boolean, detail: string) {
  results.push({ name, pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name} — ${detail}`);
}

function sign(body: Buffer): string {
  return createHmac("sha256", TEST_SECRET).update(body).digest("hex");
}

function verifyResponseSignature(body: Buffer, header: string | null): boolean {
  if (!header) return false;
  const expected = Buffer.from(sign(body), "hex");
  const given = Buffer.from(header.replace(/^sha256=/, ""), "hex");
  return (
    given.length === expected.length && expected.equals(given) &&
    // timingSafeEqual equivalent for the harness (not security-critical here)
    true
  );
}

async function postAgent(
  envelope: unknown,
  secret: string = TEST_SECRET,
): Promise<{ status: number; body: Buffer; json: any; sigOk: boolean }> {
  const raw = Buffer.from(JSON.stringify(envelope), "utf8");
  const sig = createHmac("sha256", secret).update(raw).digest("hex");
  const res = await fetch(`${BASE}/agent`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": sig,
    },
    body: raw,
  });
  const body = Buffer.from(await res.arrayBuffer());
  let json: any = null;
  try {
    json = JSON.parse(body.toString("utf8"));
  } catch {
    /* leave null */
  }
  return {
    status: res.status,
    body,
    json,
    sigOk: verifyResponseSignature(body, res.headers.get("x-agent-games-signature")),
  };
}

function baseInput(overrides: Record<string, unknown> = {}) {
  return {
    registered_vk: VK_HASH,
    proof_vk: VK_HASH,
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: RECIPIENT,
    condition_recipient: RECIPIENT,
    amount: "500",
    max_transfer: "1000",
    proof_tx: PROOF_TX,
    ...overrides,
  };
}

function taskEnvelope(taskId: string, input: unknown, proofTx = PROOF_TX) {
  const now = new Date();
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: now.toISOString(),
    deadline_at: new Date(now.getTime() + 60_000).toISOString(),
    input: { ...(input as object), proof_tx: proofTx },
  };
}

async function verifyProofAttached(
  json: any,
  label: string,
): Promise<boolean> {
  if (!json?.proof || !json?.public_signals) return false;
  const vk = JSON.parse(
    fs.readFileSync("circuits/verification_key.json", "utf8"),
  );
  try {
    return await snarkjs.groth16.verify(vk, json.public_signals, json.proof);
  } catch (e) {
    console.error(`  [${label}] verify threw:`, e);
    return false;
  }
}

async function waitForHealth(timeoutMs = 15000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

async function main() {
  // Fresh state for the replay store.
  const dataDir = path.resolve("data-test");
  fs.rmSync(dataDir, { recursive: true, force: true });

  const server: ChildProcess = spawn("node", ["dist/src/server.js"], {
    env: {
      ...process.env,
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
      KURIER_API_KEY: "",
      KURIER_STRICT: "true",
      PORT: String(PORT),
      HOST: "127.0.0.1",
      DATA_DIR: dataDir,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  server.stdout?.on("data", (d) => process.stdout.write(`[srv] ${d}`));
  server.stderr?.on("data", (d) => process.stderr.write(`[srv:err] ${d}`));

  try {
    if (!(await waitForHealth())) {
      record("server starts", false, "health check never became ready");
      process.exitCode = 1;
      return;
    }
    record("server starts", true, "health OK");

    // 1. Preflight
    {
      const raw = Buffer.from(
        JSON.stringify({
          type: "agent-games.preflight.v1",
          agent_id: "agt_test",
          issued_at: new Date().toISOString(),
          nonce: "abc123",
        }),
        "utf8",
      );
      const res = await fetch(`${BASE}/agent`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": createHmac("sha256", TEST_SECRET)
            .update(raw)
            .digest("hex"),
        },
        body: raw,
      });
      const body = Buffer.from(await res.arrayBuffer());
      const json = JSON.parse(body.toString("utf8"));
      record(
        "preflight",
        res.status === 200 &&
          json.ok === true &&
          json.protocolVersion === "v1" &&
          verifyResponseSignature(body, res.headers.get("x-agent-games-signature")),
        `status=${res.status} body=${body.toString()}`,
      );
    }

    // 2. Valid task -> APPROVE + verifying proof
    {
      const r = await postAgent(taskEnvelope("gk_harness_valid", baseInput()));
      const proofOk = await verifyProofAttached(r.json, "valid");
      record(
        "valid task APPROVE",
        r.status === 200 &&
          r.json?.decision === "APPROVE" &&
          r.json?.reason_code === "OK" &&
          r.sigOk &&
          proofOk,
        `decision=${r.json?.decision} reason=${r.json?.reason_code} proofVerifies=${proofOk} sigOk=${r.sigOk}`,
      );
    }

    // 3. VK substitution -> REJECT + verifying reject-proof
    {
      const r = await postAgent(
        taskEnvelope(
          "gk_harness_vksub",
          baseInput({ proof_vk: "0x" + "11".repeat(32) }),
          "0x" + "b1".repeat(32),
        ),
      );
      const proofOk = await verifyProofAttached(r.json, "vksub");
      record(
        "VK substitution REJECT",
        r.json?.decision === "REJECT" &&
          r.json?.reason_code === "VK_SUBSTITUTION" &&
          r.sigOk &&
          proofOk,
        `reason=${r.json?.reason_code} proofVerifies=${proofOk}`,
      );
    }

    // 4. VK mismatch (hashes agree with each other, not with platform).
    //    The circuit CANNOT prove this rejection — its verdict for matched
    //    hashes is APPROVE — so the correct response carries NO proof.
    {
      const other = "0x" + "22".repeat(32);
      const r = await postAgent(
        taskEnvelope(
          "gk_harness_vkmis",
          baseInput({ registered_vk: other, proof_vk: other }),
          "0x" + "b2".repeat(32),
        ),
      );
      record(
        "VK mismatch (code-only check) REJECT, no proof",
        r.json?.decision === "REJECT" &&
          r.json?.reason_code === "VK_MISMATCH" &&
          r.sigOk &&
          !r.json?.proof,
        `reason=${r.json?.reason_code} proofAttached=${Boolean(r.json?.proof)}`,
      );
    }

    // 5. Threshold
    {
      const r = await postAgent(
        taskEnvelope("gk_harness_thresh", baseInput({ public_balance: "900" }), "0x" + "b3".repeat(32)),
      );
      const proofOk = await verifyProofAttached(r.json, "thresh");
      record(
        "threshold REJECT",
        r.json?.decision === "REJECT" &&
          r.json?.reason_code === "THRESHOLD_NOT_MET" &&
          proofOk,
        `reason=${r.json?.reason_code} proofVerifies=${proofOk}`,
      );
    }

    // 6. Recipient mismatch
    {
      const r = await postAgent(
        taskEnvelope(
          "gk_harness_recip",
          baseInput({ recipient: "0x1111111111111111111111111111111111111111" }),
          "0x" + "b4".repeat(32),
        ),
      );
      const proofOk = await verifyProofAttached(r.json, "recip");
      record(
        "recipient mismatch REJECT",
        r.json?.decision === "REJECT" &&
          r.json?.reason_code === "RECIPIENT_MISMATCH" &&
          proofOk,
        `reason=${r.json?.reason_code} proofVerifies=${proofOk}`,
      );
    }

    // 7. Amount overflow
    {
      const r = await postAgent(
        taskEnvelope("gk_harness_amt", baseInput({ amount: "1500" }), "0x" + "b5".repeat(32)),
      );
      const proofOk = await verifyProofAttached(r.json, "amt");
      record(
        "amount overflow REJECT",
        r.json?.decision === "REJECT" &&
          r.json?.reason_code === "AMOUNT_EXCEEDS_MAX" &&
          proofOk,
        `reason=${r.json?.reason_code} proofVerifies=${proofOk}`,
      );
    }

    // 8. Expired
    {
      const r = await postAgent(
        taskEnvelope("gk_harness_exp", baseInput({ current_block: 8430001 }), "0x" + "b6".repeat(32)),
      );
      const proofOk = await verifyProofAttached(r.json, "exp");
      record(
        "expired REJECT",
        r.json?.decision === "REJECT" &&
          r.json?.reason_code === "EXPIRED" &&
          proofOk,
        `reason=${r.json?.reason_code} proofVerifies=${proofOk}`,
      );
    }

    // 9. Proof reuse: same proof_tx as the valid task, new task_id
    {
      const r = await postAgent(taskEnvelope("gk_harness_reuse", baseInput()));
      record(
        "proof reuse REJECT (no proof)",
        r.json?.decision === "REJECT" &&
          r.json?.reason_code === "PROOF_REUSED" &&
          !r.json?.proof,
        `reason=${r.json?.reason_code} proofAttached=${Boolean(r.json?.proof)}`,
      );
    }

    // 10. Bad HMAC -> 401, no processing
    {
      const r = await postAgent(taskEnvelope("gk_harness_badh", baseInput(), "0x" + "b7".repeat(32)), "wrong-secret");
      record("bad HMAC -> 401", r.status === 401, `status=${r.status}`);
    }

    // 11. Stale deadline -> REJECT STALE_TASK
    {
      const env = taskEnvelope("gk_harness_stale", baseInput(), "0x" + "b8".repeat(32));
      env.deadline_at = new Date(Date.now() - 60_000).toISOString();
      const r = await postAgent(env);
      record(
        "stale deadline REJECT",
        r.json?.decision === "REJECT" && r.json?.reason_code === "STALE_TASK",
        `reason=${r.json?.reason_code}`,
      );
    }
  } finally {
    server.kill("SIGTERM");
  }

  const failed = results.filter((r) => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} cases passed`);
  if (failed.length) {
    console.log("FAILED:", failed.map((f) => f.name).join(", "));
  }
  // Explicit exit: undici's fetch keep-alive sockets would otherwise keep
  // the event loop alive indefinitely after the summary prints.
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
