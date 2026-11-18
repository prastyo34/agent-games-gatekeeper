// Kurier REST client (zkVerify verification via Horizen Labs' Kurier).
// Docs: https://docs.zkverify.io/overview/getting-started/kurier
// Swagger: https://api.kurier.xyz/docs (mainnet), https://api-testnet.kurier.xyz/docs
//
// Flow: POST /submit-proof/{API_KEY} -> { jobId, optimisticVerify }
//       GET  /job-status/{API_KEY}/{jobId} -> { status, ... }
// Statuses: Queued, Valid, Submitted, IncludedInBlock, Finalized, Failed.
// Only "Finalized" counts as confirmed. Poll every 5s until the caller's
// deadline; never wait past it — the HTTP response deadline is sacred.
import type { Groth16Proof } from "./circuit";

export type KurierStatus =
  | "Queued"
  | "Valid"
  | "Submitted"
  | "IncludedInBlock"
  | "Finalized"
  | "Failed"
  | string;

export interface SubmitResult {
  jobId: string;
  optimisticVerify?: string;
}

export class KurierClient {
  constructor(
    private apiUrl: string,
    private apiKey: string,
  ) {}

  private async fetchJson(
    url: string,
    init: RequestInit,
    timeoutMs: number,
  ): Promise<any> {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...init, signal: ctrl.signal });
      const text = await res.text();
      let data: any = null;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        data = { raw: text };
      }
      if (!res.ok) {
        throw new Error(
          `Kurier HTTP ${res.status}: ${JSON.stringify(data)?.slice(0, 300)}`,
        );
      }
      return data;
    } finally {
      clearTimeout(t);
    }
  }

  async submitProof(
    proof: Groth16Proof,
    publicSignals: string[],
    vkHash: string,
    timeoutMs = 15000,
  ): Promise<SubmitResult> {
    const body = {
      proofType: "groth16",
      vkRegistered: true,
      proofOptions: { library: "snarkjs", curve: "bn128" },
      proofData: { proof, publicSignals, vk: vkHash },
    };
    const data = await this.fetchJson(
      `${this.apiUrl}/submit-proof/${this.apiKey}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      },
      timeoutMs,
    );
    if (!data?.jobId) {
      throw new Error(`Kurier submit returned no jobId: ${JSON.stringify(data)?.slice(0, 300)}`);
    }
    return { jobId: String(data.jobId), optimisticVerify: data.optimisticVerify };
  }

  async jobStatus(jobId: string, timeoutMs = 10000): Promise<KurierStatus> {
    const data = await this.fetchJson(
      `${this.apiUrl}/job-status/${this.apiKey}/${encodeURIComponent(jobId)}`,
      { method: "GET" },
      timeoutMs,
    );
    if (!data?.status) {
      throw new Error(`Kurier job-status returned no status: ${JSON.stringify(data)?.slice(0, 300)}`);
    }
    return String(data.status) as KurierStatus;
  }

  /** Submit and poll until Finalized or the deadline. Returns the final
   *  status ("Finalized" on success) and the jobId for the audit log. */
  async submitAndWaitFinalized(
    proof: Groth16Proof,
    publicSignals: string[],
    vkHash: string,
    deadlineMs: number,
  ): Promise<{ status: KurierStatus; jobId: string | null }> {
    const submit = await this.submitProof(proof, publicSignals, vkHash, 15000);
    if (submit.optimisticVerify && submit.optimisticVerify !== "success") {
      return { status: "Failed", jobId: submit.jobId };
    }
    for (;;) {
      const remaining = deadlineMs - Date.now();
      if (remaining <= 0) return { status: "TIMEOUT", jobId: submit.jobId };
      const status = await this.jobStatus(submit.jobId, Math.min(10000, remaining));
      if (status === "Finalized" || status === "Failed") {
        return { status, jobId: submit.jobId };
      }
      await new Promise((r) => setTimeout(r, Math.min(5000, Math.max(0, deadlineMs - Date.now()))));
      if (Date.now() >= deadlineMs) return { status: "TIMEOUT", jobId: submit.jobId };
    }
  }
}
