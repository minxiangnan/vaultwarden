// Register, opt one authenticator entry into MCP, and read the code over /mcp.
// The wrapping uses the same WebCrypto steps as the browser extension.

import { decodeBase32, mcpAad, sealField, totp } from "./mcp-crypto.mjs";

const base = process.env.VW_BASE ?? "http://127.0.0.1:8123";
const email = process.env.VW_EMAIL ?? `mcp-${Date.now()}@example.com`;
const enc = "2.AAAA|AAAA|AAAA";
const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

function fail(message) {
  console.error(message);
  process.exit(1);
}

async function call(method, path, body, token, form = false) {
  const headers = { Accept: "application/json", "Bitwarden-Client-Version": "2026.1.0" };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  let payload;
  if (body != null) {
    if (form) {
      payload = new URLSearchParams(body);
    } else {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }
  }
  const response = await fetch(base + path, { method, headers, body: payload });
  const text = await response.text();
  const json = text && (response.headers.get("content-type") ?? "").includes("json") ? JSON.parse(text) : text;
  if (!response.ok) {
    fail(`${method} ${path} -> ${response.status} ${text}`);
  }
  return { status: response.status, json };
}

async function mcp(token, body) {
  const response = await fetch(base + "/mcp", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text;
  }
  return { status: response.status, json, text };
}

async function main() {
  const verification = await call("POST", "/identity/accounts/register/send-verification-email", {
    email,
    name: "MCP",
  });
  const registered = await call("POST", "/identity/accounts/register/finish", {
    email,
    name: "MCP",
    emailVerificationToken: verification.json,
    masterPasswordHash: "master-hash",
    masterPasswordHint: null,
    userSymmetricKey: enc,
    userAsymmetricKeys: { publicKey: "pub", encryptedPrivateKey: enc },
    kdf: 0,
    kdfIterations: 600000,
  });
  if (registered.json.object !== "registerFinish") {
    fail("registration failed");
  }

  const login = await call(
    "POST",
    "/identity/connect/token",
    {
      grant_type: "password",
      username: email,
      password: "master-hash",
      scope: "api offline_access",
      client_id: "cli",
      device_identifier: "33333333-3333-3333-3333-333333333333",
      device_name: "mcp-e2e",
      device_type: "14",
    },
    null,
    true,
  );
  const access = login.json.access_token;
  const profile = await call("GET", "/api/accounts/profile", null, access);
  const userId = profile.json.id;

  const gitlab = await call(
    "POST",
    "/api/authenticator",
    { name: enc, secret: enc, issuer: enc, algorithm: "SHA1", digits: 8, period: 30 },
    access,
  );
  const github = await call(
    "POST",
    "/api/authenticator",
    { name: enc, secret: enc, issuer: enc, algorithm: "SHA1", digits: 6, period: 30 },
    access,
  );

  const issued = await call("POST", "/api/mcp/token", { label: "e2e" }, access);
  const token = issued.json.token;
  const salt = issued.json.keySalt;
  if (!token.startsWith("vw_mcp_") || !salt) {
    fail("token was not issued");
  }

  async function optIn(entryId, alias, issuer, account, digits) {
    const seal = (field, value) => sealField(token, salt, mcpAad(userId, "authenticator", entryId, alias, field), value);
    await call(
      "PUT",
      `/api/mcp/entries/authenticator/${entryId}`,
      {
        alias,
        secretCt: await seal("secret", secret),
        issuerCt: await seal("issuer", issuer),
        accountCt: await seal("account", account),
        algorithm: "SHA1",
        digits,
        period: 30,
        steam: false,
      },
      access,
    );
  }

  await optIn(gitlab.json.id, "gitlab", "GitLab", "ada", 8);
  await optIn(github.json.id, "github", "GitHub", "ada", 6);

  const init = await mcp(token, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "e2e", version: "1.1.0" } },
  });
  if (init.status !== 200 || init.json.result.serverInfo.name !== "vaultwarden-mcp") {
    fail(`initialize failed ${init.status} ${init.text}`);
  }

  const listed = await mcp(token, { jsonrpc: "2.0", id: 2, method: "tools/list" });
  const names = listed.json.result.tools.map((tool) => tool.name).sort();
  if (names.join() !== "get_totp_code,list_totp_aliases,search_totp") {
    fail(`unexpected tools ${names}`);
  }

  const raw = decodeBase32(secret);
  let got = await mcp(token, {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "get_totp_code", arguments: { alias: "GitLab" } },
  });
  let body = got.json.result.structuredContent;
  const expected = totp("SHA1", raw, 8, 30, Math.floor(Date.now() / 1000));
  if (body.code !== expected.code) {
    const again = totp("SHA1", raw, 8, 30, Math.floor(Date.now() / 1000));
    got = await mcp(token, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "get_totp_code", arguments: { alias: "gitlab" } },
    });
    body = got.json.result.structuredContent;
    if (body.code !== again.code) {
      fail(`code mismatch server=${body.code} local=${again.code}`);
    }
  }
  if (body.issuer !== "GitLab" || body.account !== "ada" || body.match !== "exact" || body.seconds_remaining < 1) {
    fail(`unexpected code payload ${JSON.stringify(body)}`);
  }
  console.log("get_totp_code", body.alias, body.code, "remaining", body.seconds_remaining);

  const ambiguous = await mcp(token, {
    jsonrpc: "2.0",
    id: 5,
    method: "tools/call",
    params: { name: "get_totp_code", arguments: { alias: "ada" } },
  });
  const amb = ambiguous.json.result;
  if (!amb.isError || amb.structuredContent.error !== "ambiguous" || amb.structuredContent.code) {
    fail(`ambiguity should not return a code ${JSON.stringify(amb)}`);
  }
  const candidates = amb.structuredContent.candidates.map((item) => item.alias).sort();
  if (candidates.join() !== "github,gitlab") {
    fail(`candidates ${candidates}`);
  }
  if (!amb.content[0].text.includes("gitlab") || !amb.content[0].text.includes("github")) {
    fail("ambiguity text did not list candidates");
  }
  console.log("ambiguous alias listed", candidates.join(", "));

  await call("DELETE", "/api/mcp/token", null, access);
  const revoked = await mcp(token, { jsonrpc: "2.0", id: 6, method: "tools/list" });
  if (revoked.status !== 401) {
    fail(`revoked token should be 401, got ${revoked.status} ${revoked.text}`);
  }
  console.log("revoked token rejected");
  console.log("e2e ok", email);
}

main().catch((error) => fail(error.stack ?? String(error)));
