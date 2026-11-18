// Configuration — everything from the environment, nothing hardcoded
// except public protocol constants. Secrets are never logged.
import "dotenv/config";
import path from "node:path";

export const PLATFORM_VK_HASH_DEFAULT =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

export interface Config {
  /** HMAC secret from the dashboard "Rotate Secret". Required to start. */
  hmacSecret: string;
  /** Kurier REST API key. Empty = Kurier disabled (local verify only). */
  kurierApiKey: string;
  kurierApiUrl: string;
  /** True (default): APPROVE requires Kurier "Finalized". */
  kurierStrict: boolean;
  host: string;
  port: number;
  /** The VK hash the platform registered for the gatekeeper circuit. */
  gatekeeperVkHash: string;
  wasmPath: string;
  zkeyPath: string;
  vkJsonPath: string;
  dataDir: string;
  /** Hard per-task deadline (seconds) from receipt, per the rulebook. */
  taskDeadlineSec: number;
  /** Seconds of the deadline kept in reserve for sending the response. */
  responseReserveSec: number;
}

function env(name: string, fallback: string): string {
  const v = process.env[name];
  return v === undefined || v === "" ? fallback : v;
}

function envBool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  return v.toLowerCase() === "true" || v === "1";
}

export function loadConfig(): Config {
  const hmacSecret = (process.env.AGENT_GAMES_HMAC_SECRET ?? "").trim();
  if (!hmacSecret) {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET is not set. Copy it from the Agent Games dashboard (Rotate Secret) into .env — never use a placeholder.",
    );
  }
  const root = process.cwd();
  return {
    hmacSecret,
    kurierApiKey: (process.env.KURIER_API_KEY ?? "").trim(),
    kurierApiUrl: env("KURIER_API_URL", "https://api.kurier.xyz/api/v1").replace(
      /\/$/,
      "",
    ),
    kurierStrict: envBool("KURIER_STRICT", true),
    host: env("HOST", "0.0.0.0"),
    port: Number(env("PORT", "3000")),
    gatekeeperVkHash: env(
      "GATEKEEPER_VK_HASH",
      PLATFORM_VK_HASH_DEFAULT,
    ).toLowerCase(),
    wasmPath: path.resolve(
      root,
      env("GATEKEEPER_WASM", "./circuits/gatekeeper.wasm"),
    ),
    zkeyPath: path.resolve(
      root,
      env("GATEKEEPER_ZKEY", "./circuits/gatekeeper_final.zkey"),
    ),
    vkJsonPath: path.resolve(
      root,
      env("GATEKEEPER_VK_JSON", "./circuits/verification_key.json"),
    ),
    dataDir: path.resolve(root, env("DATA_DIR", "./data")),
    taskDeadlineSec: 60,
    responseReserveSec: 5,
  };
}
