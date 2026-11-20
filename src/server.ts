// Proof Gatekeeper HTTP service.
//
// POST /agent  — signed task envelopes + preflight (see README for the
//                protocol). HMAC is verified over the RAW body before any
//                JSON parsing. Every response to an authenticated request is
//                signed with x-agent-games-signature over its raw body.
// GET  /health — liveness only, unsigned, no secrets.
//
// Fail-closed everywhere: any timeout, error, or uncertainty ends in
// REJECT — never approve by default. The 60s hard deadline is enforced
// against the envelope's deadline_at (or 60s from receipt).
import http from "node:http";
import { loadConfig, type Config } from "./config";
import { signBody, verifyBody, SIGNATURE_HEADER } from "./hmac";
import {
  Prover,
  buildCircuitInput,
  type GatekeeperTaskInput,
  type Groth16Proof,
} from "./circuit";
import { KurierClient } from "./kurier";
import {
  decideTask,
  validateTaskInput,
  CIRCUIT_PROVABLE_REJECTS,
  type Decision,
  type ReasonCode,
} from "./decide";
import { SeenProofStore, DecisionLog } from "./store";

const GATEKEEPER_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const MAX_BODY_BYTES = 1_000_000;

interface GatekeeperResponse {
  decision: Decision;
  reason_code: ReasonCode;
  proof?: Groth16Proof;
  public_signals?: string[];
  proof_tx?: string;
}

export class GatekeeperServer {
  private prover: Prover;
  private kurier: KurierClient | null;
  private seen: SeenProofStore;
  private log: DecisionLog;
  private server: http.Server;

  constructor(private cfg: Config) {
    this.prover = new Prover(cfg.wasmPath, cfg.zkeyPath, cfg.vkJsonPath);
    this.kurier = cfg.kurierApiKey
      ? new KurierClient(cfg.kurierApiUrl, cfg.kurierApiKey)
      : null;
    this.seen = new SeenProofStore(cfg.dataDir);
    this.log = new DecisionLog(cfg.dataDir);
    this.server = http.createServer((req, res) => {
      void this.handle(req, res).catch((e) => {
        console.error("[server] unhandled handler error:", e);
        if (!res.headersSent) {
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "internal_error" }));
        }
      });
    });
  }

  listen(): Promise<void> {
    return new Promise((resolve) => {
      this.server.listen(this.cfg.port, this.cfg.host, () => {
        console.log(
          `[server] listening on ${this.cfg.host}:${this.cfg.port} ` +
            `(kurier: ${this.kurier ? "enabled" : "disabled — local verify only"}, ` +
            `strict: ${this.cfg.kurierStrict})`,
        );
        resolve();
      });
    });
  }

  close(): Promise<void> {
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  // ---- request plumbing -------------------------------------------------

  private async readBody(
    req: http.IncomingMessage,
  ): Promise<{ body: Buffer } | { error: string }> {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      const buf = chunk as Buffer;
      size += buf.length;
      if (size > MAX_BODY_BYTES) return { error: "body_too_large" };
      chunks.push(buf);
    }
    return { body: Buffer.concat(chunks) };
  }

  private sendSigned(
    res: http.ServerResponse,
    status: number,
    payload: unknown,
  ): void {
    const body = Buffer.from(JSON.stringify(payload), "utf8");
    res.writeHead(status, {
      "content-type": "application/json",
      "content-length": body.length,
      [SIGNATURE_HEADER]: signBody(this.cfg.hmacSecret, body),
    });
    res.end(body);
  }

  private sendUnsigned(
    res: http.ServerResponse,
    status: number,
    payload: unknown,
  ): void {
    const body = Buffer.from(JSON.stringify(payload), "utf8");
    res.writeHead(status, {
      "content-type": "application/json",
      "content-length": body.length,
    });
    res.end(body);
  }

  private async handle(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

    if (req.method === "GET" && url.pathname === "/health") {
      this.sendUnsigned(res, 200, {
        ok: true,
        service: "agent-games-gatekeeper",
        kurier: this.kurier ? "enabled" : "disabled",
        vkHash: this.cfg.gatekeeperVkHash,
      });
      return;
    }

    if (req.method !== "POST" || url.pathname !== "/agent") {
      this.sendUnsigned(res, 404, { error: "not_found" });
      return;
    }

    const read = await this.readBody(req);
    if ("error" in read) {
      this.sendUnsigned(res, 413, { error: read.error });
      return;
    }
    const rawBody = read.body;

    // 1. HMAC over the RAW body, before parsing anything.
    if (!verifyBody(this.cfg.hmacSecret, rawBody, req.headers[SIGNATURE_HEADER])) {
      this.sendUnsigned(res, 401, { error: "invalid_signature" });
      return;
    }

    let envelope: any;
    try {
      envelope = JSON.parse(rawBody.toString("utf8"));
    } catch {
      this.sendSigned(res, 400, {
        decision: "REJECT",
        reason_code: "INVALID_ENVELOPE",
      } satisfies GatekeeperResponse);
      return;
    }

    // 2. Preflight handshake.
    if (envelope?.type === PREFLIGHT_TYPE) {
      this.sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
      return;
    }

    if (envelope?.type !== GATEKEEPER_TYPE) {
      this.sendSigned(res, 200, {
        decision: "REJECT",
        reason_code: "INVALID_TYPE",
      } satisfies GatekeeperResponse);
      return;
    }

    await this.handleTask(envelope, res);
  }

  // ---- task handling ----------------------------------------------------

  private async handleTask(envelope: any, res: http.ServerResponse): Promise<void> {
    const startedAt = Date.now();
    const taskId: string | null =
      typeof envelope?.task_id === "string" ? envelope.task_id : null;
    const input: unknown = envelope?.input ?? null;

    const deadlineMs = (() => {
      const d = Date.parse(envelope?.deadline_at ?? "");
      const fromReceipt = startedAt + this.cfg.taskDeadlineSec * 1000;
      if (Number.isFinite(d)) return Math.min(d, fromReceipt);
      return fromReceipt;
    })();
    // Internal budget: stop expensive work early enough to still answer.
    const budgetMs =
      deadlineMs - this.cfg.responseReserveSec * 1000;
    const remainingMs = () => budgetMs - Date.now();

    const reply = (payload: GatekeeperResponse, logEntry: Partial<import("./store").DecisionLogEntry>) => {
      this.log.append({
        at: new Date().toISOString(),
        task_id: taskId,
        decision: payload.decision,
        reason_code: payload.reason_code,
        proof_tx: typeof input === "object" && input !== null && typeof (input as any).proof_tx === "string"
          ? (input as any).proof_tx
          : null,
        kurier_job_id: null,
        kurier_status: null,
        proof_verified_locally: null,
        ms: Date.now() - startedAt,
        detail: "",
        ...logEntry,
      });
      this.sendSigned(res, 200, payload);
    };

    const reject = (
      reason: ReasonCode,
      detail: string,
      extra: Partial<import("./store").DecisionLogEntry> = {},
    ) => {
      console.log(`[task ${taskId ?? "?"}] REJECT ${reason} — ${detail}`);
      reply(
        {
          decision: "REJECT",
          reason_code: reason,
          ...(typeof input === "object" && input !== null && typeof (input as any).proof_tx === "string"
            ? { proof_tx: (input as any).proof_tx }
            : {}),
        },
        { detail, ...extra },
      );
    };

    try {
      if (!validateTaskInput(input)) {
        reject("INVALID_ENVELOPE", "input fields missing or malformed");
        return;
      }
      const task = input as GatekeeperTaskInput;
      const issuedAtMs = Date.parse(envelope?.issued_at ?? "");
      const decision = decideTask(task, {
        platformVkHash: this.cfg.gatekeeperVkHash,
        isProofTxSeen: (tx) => this.seen.has(tx),
        nowMs: startedAt,
        deadlineAtMs: Number.isFinite(deadlineMs) ? deadlineMs : null,
        issuedAtMs: Number.isFinite(issuedAtMs) ? issuedAtMs : null,
      });

      // Replay gate: mark the reference the moment we accept the task, so
      // a concurrent duplicate cannot slip through.
      if (task.proof_tx) this.seen.mark(task.proof_tx);

      if (decision.decision === "APPROVE") {
        // Only expensive work (proving + Kurier) is gated on the remaining
        // budget. A REJECT decision below keeps its own reason even when
        // the deadline is already gone — overwriting it with TIMEOUT here
        // used to hide the real reason (e.g. STALE_TASK).
        if (remainingMs() <= 0) {
          reject("TIMEOUT", "deadline reached before proving");
          return;
        }
        await this.handleApprove(task, taskId, deadlineMs, budgetMs, startedAt, reply, reject);
        return;
      }

      // REJECT path: attach a decision=0 proof when the circuit can prove
      // this rejection; otherwise respond without a proof. When the
      // deadline is already gone, skip proving and keep the real reason.
      if (remainingMs() <= 0) {
        reject(decision.reasonCode, decision.detail);
        return;
      }
      if (!CIRCUIT_PROVABLE_REJECTS.has(decision.reasonCode)) {
        reject(decision.reasonCode, decision.detail);
        return;
      }
      try {
        const circuitInput = buildCircuitInput(task, taskId ?? "unknown", 0);
        const { proof, publicSignals } = await this.prover.prove(circuitInput);
        const ok = await this.prover.verifyLocal(proof, publicSignals);
        if (!ok) {
          reject(decision.reasonCode, decision.detail + " | reject-proof failed local verify");
          return;
        }
        console.log(`[task ${taskId ?? "?"}] REJECT ${decision.reasonCode} — ${decision.detail} (proof verified locally)`);
        reply(
          {
            decision: "REJECT",
            reason_code: decision.reasonCode,
            proof,
            public_signals: publicSignals,
            ...(task.proof_tx ? { proof_tx: task.proof_tx } : {}),
          },
          { detail: decision.detail, proof_verified_locally: true },
        );
      } catch (e) {
        // My decision disagrees with the circuit — fail closed, no proof.
        console.error(`[task ${taskId ?? "?"}] reject-proof generation failed:`, e);
        reject(decision.reasonCode, decision.detail + " | reject-proof generation failed");
      }
    } catch (e) {
      console.error(`[task ${taskId ?? "?"}] unexpected error:`, e);
      if (!res.headersSent) {
        reject("PROOF_FAILED", `unexpected error: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }

  private async handleApprove(
    task: GatekeeperTaskInput,
    taskId: string | null,
    _deadlineMs: number,
    budgetMs: number,
    startedAt: number,
    reply: (payload: GatekeeperResponse, logEntry: Partial<import("./store").DecisionLogEntry>) => void,
    reject: (reason: ReasonCode, detail: string, extra?: Partial<import("./store").DecisionLogEntry>) => void,
  ): Promise<void> {
    const remainingMs = () => budgetMs - Date.now();
    try {
      const circuitInput = buildCircuitInput(task, taskId ?? "unknown", 1);
      const { proof, publicSignals } = await this.prover.prove(circuitInput);
      const ok = await this.prover.verifyLocal(proof, publicSignals);
      if (!ok) {
        reject("PROOF_FAILED", "approve-proof failed local verification");
        return;
      }

      // Kurier finalization (the on-chain confirmation step).
      let kurierJobId: string | null = null;
      let kurierStatus: string | null = null;
      if (this.kurier) {
        try {
          const r = await this.kurier.submitAndWaitFinalized(
            proof,
            publicSignals,
            this.cfg.gatekeeperVkHash,
            budgetMs,
          );
          kurierJobId = r.jobId;
          kurierStatus = r.status;
        } catch (e) {
          kurierStatus = `ERROR: ${e instanceof Error ? e.message : String(e)}`;
        }
        if (kurierStatus !== "Finalized") {
          if (this.cfg.kurierStrict) {
            reject("NOT_FINALIZED", `kurier status: ${kurierStatus}`, {
              kurier_job_id: kurierJobId,
              kurier_status: kurierStatus,
              proof_verified_locally: true,
            });
            return;
          }
          console.warn(
            `[task ${taskId ?? "?"}] Kurier not finalized (${kurierStatus}) — ` +
              "KURIER_STRICT=false, approving on local verification only",
          );
        }
      } else {
        console.warn(
          `[task ${taskId ?? "?"}] Kurier disabled (no API key) — approving on local verification only`,
        );
      }

      console.log(
        `[task ${taskId ?? "?"}] APPROVE (proof verified locally` +
          (kurierStatus ? `, kurier: ${kurierStatus}` : "") +
          `, ${Date.now() - startedAt}ms)`,
      );
      reply(
        {
          decision: "APPROVE",
          reason_code: "OK",
          proof,
          public_signals: publicSignals,
          ...(task.proof_tx ? { proof_tx: task.proof_tx } : {}),
        },
        {
          detail: "all checks pass",
          kurier_job_id: kurierJobId,
          kurier_status: kurierStatus,
          proof_verified_locally: true,
        },
      );
    } catch (e) {
      // The circuit refused to prove APPROVE: my checks disagree with the
      // referee. Fail closed — REJECT, no proof.
      console.error(`[task ${taskId ?? "?"}] approve-proof generation failed:`, e);
      reject("PROOF_FAILED", "approve-proof generation failed (decision/circuit disagreement)");
    }
  }
}

// Run as a standalone server when executed directly.
if (require.main === module) {
  const cfg = loadConfig();
  const server = new GatekeeperServer(cfg);
  server.listen().catch((e) => {
    console.error("[server] failed to start:", e instanceof Error ? e.message : e);
    process.exit(1);
  });
}
