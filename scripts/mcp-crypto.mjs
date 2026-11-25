// Same wrapping as the extension file apps/browser/src/authenticator/mcp/mcp-crypto.ts
// and the server in src/mcp/crypto.rs.

import { createHmac } from "node:crypto";

const INFO = new TextEncoder().encode("vaultwarden-mcp-totp-v1");
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function encodeBase64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

export function decodeBase64Url(value) {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

export function mcpAad(userId, source, sourceId, alias, field) {
  return new TextEncoder().encode(`v1|${field}|${userId}|${source}|${sourceId}|${alias}`);
}

export async function deriveMcpKey(token, saltB64, usages = ["encrypt"]) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(token), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: decodeBase64Url(saltB64), info: INFO },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

export async function sealField(token, saltB64, aad, plaintext) {
  const key = await deriveMcpKey(token, saltB64);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad },
      key,
      new TextEncoder().encode(plaintext),
    ),
  );
  const packed = new Uint8Array(nonce.length + cipher.length);
  packed.set(nonce, 0);
  packed.set(cipher, nonce.length);
  return encodeBase64Url(packed);
}

export function totp(algorithm, secret, digits, period, unixTime) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(unixTime / period)));
  const mac = hmac(algorithm, secret, counter);
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  const code = String(bin % 10 ** digits).padStart(digits, "0");
  const elapsed = unixTime % period;
  return { code, secondsRemaining: period - elapsed };
}

function hmac(algorithm, key, data) {
  const name = algorithm === "SHA256" ? "sha256" : algorithm === "SHA512" ? "sha512" : "sha1";
  return new Uint8Array(createHmac(name, Buffer.from(key)).update(data).digest());
}

export function decodeBase32(secret) {
  const cleaned = secret.replace(/[\s=-]/g, "").toUpperCase();
  let bits = "";
  for (const char of cleaned) {
    const value = BASE32.indexOf(char);
    if (value < 0) {
      throw new Error("bad base32");
    }
    bits += value.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}
