// Durable local state: seen proof_tx references (replay protection) and
// a JSONL decision log (dispute evidence). Files live under DATA_DIR and
// are git-ignored. Nothing here contains secrets.
import fs from "node:fs";
import path from "node:path";

export class SeenProofStore {
  private seen = new Set<string>();
  private file: string;
  private loaded = false;

  constructor(dataDir: string) {
    this.file = path.join(dataDir, "seen-proof-tx.json");
  }

  load(): void {
    if (this.loaded) return;
    this.loaded = true;
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, "utf8")) as unknown;
      if (Array.isArray(raw)) {
        for (const v of raw) if (typeof v === "string") this.seen.add(v);
      }
    } catch {
      // Missing or corrupt file: start empty (a corrupt file is renamed
      // aside rather than silently dropped, for later inspection).
      try {
        if (fs.existsSync(this.file)) {
          fs.renameSync(this.file, this.file + ".corrupt-" + Date.now());
        }
      } catch {
        /* ignore */
      }
    }
  }

  has(proofTx: string): boolean {
    this.load();
    return this.seen.has(proofTx.toLowerCase());
  }

  /** Mark seen and persist immediately (synchronous — this is the replay
   *  gate, it must not be lost to a crash between tasks). */
  mark(proofTx: string): void {
    this.load();
    const key = proofTx.toLowerCase();
    if (this.seen.has(key)) return;
    this.seen.add(key);
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      fs.writeFileSync(this.file, JSON.stringify([...this.seen], null, 2));
    } catch (e) {
      // Persistence failure must not approve anything by accident — the
      // in-memory set still guards this process; log loudly.
      console.error("[store] FAILED to persist seen proof_tx:", e);
    }
  }
}

export interface DecisionLogEntry {
  at: string;
  task_id: string | null;
  decision: string;
  reason_code: string;
  proof_tx: string | null;
  kurier_job_id: string | null;
  kurier_status: string | null;
  proof_verified_locally: boolean | null;
  ms: number;
  detail: string;
}

export class DecisionLog {
  private file: string;

  constructor(dataDir: string) {
    this.file = path.join(dataDir, "decisions.jsonl");
  }

  append(entry: DecisionLogEntry): void {
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      fs.appendFileSync(this.file, JSON.stringify(entry) + "\n");
    } catch (e) {
      console.error("[store] FAILED to append decision log:", e);
    }
  }
}
