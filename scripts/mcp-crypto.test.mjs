import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeBase32, totp } from "./mcp-crypto.mjs";

const seed = Buffer.from("12345678901234567890");

test("RFC 6238 SHA1 8 digits and 6 digits", () => {
  assert.equal(totp("SHA1", seed, 8, 30, 59).code, "94287082");
  assert.equal(totp("SHA1", seed, 6, 30, 59).code, "287082");
  assert.equal(totp("SHA1", seed, 8, 30, 59).secondsRemaining, 1);
});

test("base32 of the RFC seed decodes to the same bytes", () => {
  assert.deepEqual(Buffer.from(decodeBase32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")), seed);
});
