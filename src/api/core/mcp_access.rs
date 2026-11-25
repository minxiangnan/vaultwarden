//! Vault-session API the extension uses to opt entries into MCP.
//! These routes never return a TOTP code. The plaintext token is returned once, on create or rotate.

use rocket::{Route, serde::json::Json};
use serde_json::{Value, json};

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult, Notify, UpdateType},
    auth::Headers,
    db::{
        DbConn,
        models::{AuthenticatorEntry, AuthenticatorEntryId, Cipher, CipherId, McpAudit, McpEntry, McpToken, UserId},
    },
    mcp::{self, EntryInput},
};

pub fn routes() -> Vec<Route> {
    routes![mcp_status, create_token, put_token_enc, rotate, revoke, list_entries, put_entry, delete_entry, list_audit,]
}

fn require_enabled() -> EmptyResult {
    if CONFIG.mcp_enabled() {
        Ok(())
    } else {
        err_code!("MCP is disabled", 404)
    }
}

#[get("/mcp/status")]
async fn mcp_status(headers: Headers, conn: DbConn) -> JsonResult {
    require_enabled()?;
    let count = i64::try_from(McpEntry::find_by_user(&headers.user.uuid, &conn).await?.len()).unwrap_or(i64::MAX);
    let body = match McpToken::find_active_by_user(&headers.user.uuid, &conn).await {
        Some(token) => token.to_status_json(count),
        None => json!({
            "enabled": true,
            "configured": false,
            "revoked": false,
            "tokenId": null,
            "label": null,
            "keySalt": null,
            "tokenEnc": null,
            "createdAt": null,
            "entryCount": count,
            "object": "mcpStatus",
        }),
    };
    Ok(Json(body))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenBody {
    label: Option<String>,
    token_enc: Option<String>,
}

#[post("/mcp/token", data = "<body>")]
async fn create_token(body: Json<TokenBody>, headers: Headers, conn: DbConn) -> JsonResult {
    require_enabled()?;
    let body = body.into_inner();
    let issued = mcp::issue_token(&headers.user.uuid, body.label, body.token_enc, &conn).await?;
    Ok(Json(issued_json(&issued)))
}

#[put("/mcp/token/enc", data = "<body>")]
async fn put_token_enc(body: Json<TokenBody>, headers: Headers, conn: DbConn) -> EmptyResult {
    require_enabled()?;
    let Some(token_enc) = body.into_inner().token_enc.filter(|value| !value.is_empty()) else {
        err!("缺少 tokenEnc");
    };
    if token_enc.starts_with("vw_mcp_")
        || token_enc.len() > 100_000
        || !(token_enc.contains('|') || token_enc.contains('.'))
    {
        err!("tokenEnc 必须是用户密钥加密后的密文");
    }
    let Some(mut token) = McpToken::find_active_by_user(&headers.user.uuid, &conn).await else {
        err!("还没有 MCP 访问令牌");
    };
    token.set_token_enc(token_enc, &conn).await
}

#[post("/mcp/token/rotate", data = "<body>")]
async fn rotate(body: Json<TokenBody>, headers: Headers, conn: DbConn) -> JsonResult {
    require_enabled()?;
    let body = body.into_inner();
    let issued = mcp::rotate_token(&headers.user.uuid, body.label, body.token_enc, &conn).await?;
    Ok(Json(issued_json(&issued)))
}

#[delete("/mcp/token")]
async fn revoke(headers: Headers, conn: DbConn) -> EmptyResult {
    require_enabled()?;
    mcp::revoke_user(&headers.user.uuid, &conn).await
}

#[get("/mcp/entries")]
async fn list_entries(headers: Headers, conn: DbConn) -> JsonResult {
    require_enabled()?;
    let entries = McpEntry::find_by_user(&headers.user.uuid, &conn).await?;
    let data: Vec<Value> = entries.iter().map(McpEntry::to_summary_json).collect();
    Ok(Json(json!({"data": data, "object": "list"})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntryBody {
    alias: String,
    secret_ct: String,
    issuer_ct: Option<String>,
    account_ct: Option<String>,
    host_ct: Option<String>,
    algorithm: Option<String>,
    digits: Option<i32>,
    period: Option<i32>,
    steam: Option<bool>,
}

#[put("/mcp/entries/<source>/<source_id>", data = "<body>")]
async fn put_entry(
    source: &str,
    source_id: &str,
    body: Json<EntryBody>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    require_enabled()?;
    if McpToken::find_active_by_user(&headers.user.uuid, &conn).await.is_none() {
        err!("请先创建 MCP 访问令牌");
    }
    assert_owns(&headers.user.uuid, source, source_id, &conn).await?;
    let body = body.into_inner();
    let input = EntryInput {
        source: source.to_owned(),
        source_id: source_id.to_owned(),
        alias: body.alias,
        secret_ct: body.secret_ct,
        issuer_ct: empty_to_none(body.issuer_ct),
        account_ct: empty_to_none(body.account_ct),
        host_ct: empty_to_none(body.host_ct),
        algorithm: body.algorithm.unwrap_or_else(|| "SHA1".to_owned()),
        digits: body.digits.unwrap_or(6),
        period: body.period.unwrap_or(30),
        steam: body.steam.unwrap_or(false),
    };
    let entry = mcp::store_entry(&headers.user.uuid, input, &conn).await?;
    notify_authenticator(&headers, source, source_id, &conn, &nt).await;
    Ok(Json(entry.to_summary_json()))
}

#[delete("/mcp/entries/<source>/<source_id>")]
async fn delete_entry(source: &str, source_id: &str, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    require_enabled()?;
    mcp::delete_source(&headers.user.uuid, source, source_id, &conn).await?;
    notify_authenticator(&headers, source, source_id, &conn, &nt).await;
    Ok(())
}

/// Alias changes are not a new authenticator revision. Tell other devices to reload anyway.
async fn notify_authenticator(headers: &Headers, source: &str, source_id: &str, conn: &DbConn, nt: &Notify<'_>) {
    if source != "authenticator" {
        return;
    }
    let id = AuthenticatorEntryId::from(source_id.to_owned());
    if let Some(entry) = AuthenticatorEntry::find_by_uuid_and_user(&id, &headers.user.uuid, conn).await {
        nt.send_authenticator_update(UpdateType::SyncAuthenticatorUpdate, &entry, &headers.device, conn).await;
    }
}

#[get("/mcp/audit")]
async fn list_audit(headers: Headers, conn: DbConn) -> JsonResult {
    require_enabled()?;
    let rows = McpAudit::recent_for_user(&headers.user.uuid, &conn).await?;
    let data: Vec<Value> = rows.iter().map(McpAudit::to_json).collect();
    Ok(Json(json!({"data": data, "object": "list"})))
}

fn issued_json(issued: &mcp::IssuedToken) -> Value {
    json!({
        "token": issued.token,
        "tokenId": issued.token_id,
        "keySalt": issued.key_salt,
        "cleared": issued.cleared,
        "object": "mcpToken",
    })
}

fn empty_to_none(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

async fn assert_owns(user_id: &UserId, source: &str, source_id: &str, conn: &DbConn) -> EmptyResult {
    match source {
        "authenticator" => {
            let id = AuthenticatorEntryId::from(source_id.to_owned());
            if AuthenticatorEntry::find_by_uuid_and_user(&id, user_id, conn).await.is_some() {
                Ok(())
            } else {
                err!("验证器条目不存在")
            }
        }
        "cipher" => {
            let id = CipherId::from(source_id.to_owned());
            match Cipher::find_by_uuid(&id, conn).await {
                Some(cipher) if cipher.user_uuid.as_ref() == Some(user_id) && cipher.deleted_at.is_none() => Ok(()),
                _ => err!("登录条目不存在，或不属于这个账户"),
            }
        }
        _ => err!("source 只能是 authenticator 或 cipher"),
    }
}
