// HMAC-SHA256 over the RAW request/response body.
//
// The platform signs inbound bodies and verifies outbound bodies with the
// secret from dashboard "Rotate Secret". The header is
// `x-agent-games-signature`. The exact wire format of the header value is
// not pinned down in the public docs, so verification accepts both a bare
// lowercase hex digest and a `sha256=<hex>` prefix, and always compares in
// constant time. Signing always emits the bare hex digest.
import { createHmac, timingSafeEqual } from "node:crypto";

export const SIGNATURE_HEADER = "x-agent-games-signature";

export function signBody(secret: string, body: Buffer): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

function normalizeSignature(value: string | undefined): Buffer | null {
  if (!value) return null;
  const hex = value.trim().toLowerCase().replace(/^sha256=/, "");
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  return Buffer.from(hex, "hex");
}

export function verifyBody(
  secret: string,
  body: Buffer,
  headerValue: string | string[] | undefined,
): boolean {
  const given = normalizeSignature(
    Array.isArray(headerValue) ? headerValue[0] : headerValue,
  );
  if (!given) return false;
  const expected = Buffer.from(signBody(secret, body), "hex");
  if (given.length !== expected.length) return false;
  return timingSafeEqual(given, expected);
}
