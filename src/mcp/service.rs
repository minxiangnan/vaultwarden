//! Opens an MCP session from a presented token and reads opted-in TOTP codes.
//! Plaintext lives in the vectors returned by `open` and is zeroed before those functions return.

use chrono::Utc;
use serde_json::{Value, json};

use crate::db::{
    DbConn,
    models::{AuditNote, McpAudit, McpEntry, McpSealed, McpToken, UserId},
};

use super::{
    alias::{self, AliasFields, Resolve},
    crypto::{self, McpKey},
    protocol, totp,
};

pub struct McpSession {
    pub user_uuid: UserId,
    pub token_uuid: String,
    key: McpKey,
}

#[derive(Debug)]
pub enum OpenError {
    Invalid,
    Revoked {
        user_uuid: UserId,
    },
}

pub struct IssuedToken {
    pub token: String,
    pub token_id: String,
    pub key_salt: String,
    pub cleared: Vec<Value>,
}

pub struct EntryInput {
    pub source: String,
    pub source_id: String,
    pub alias: String,
    pub secret_ct: String,
    pub issuer_ct: Option<String>,
    pub account_ct: Option<String>,
    pub host_ct: Option<String>,
    pub algorithm: String,
    pub digits: i32,
    pub period: i32,
    pub steam: bool,
}

impl McpSession {
    pub async fn open(token: &str, conn: &DbConn) -> Result<Self, OpenError> {
        let hash = crypto::token_hash(token);
        let Some(record) = McpToken::find_by_hash(&hash, conn).await else {
            return Err(OpenError::Invalid);
        };
        if record.revoked_at.is_some() {
            return Err(OpenError::Revoked {
                user_uuid: record.user_uuid,
            });
        }
        let Ok(salt) = crypto::decode_salt(&record.key_salt) else {
            return Err(OpenError::Invalid);
        };
        let Ok(key) = McpKey::derive(token, &salt) else {
            return Err(OpenError::Invalid);
        };
        Ok(Self {
            user_uuid: record.user_uuid,
            token_uuid: record.uuid,
            key,
        })
    }
}

pub async fn issue_token(
    user_uuid: &UserId,
    label: Option<String>,
    token_enc: Option<String>,
    conn: &DbConn,
) -> Result<IssuedToken, crate::Error> {
    if McpToken::find_active_by_user(user_uuid, conn).await.is_some() {
        err!("已经有 MCP 访问令牌。请轮换或吊销后再创建。");
    }
    let token = crypto::generate_token();
    if let Some(enc) = &token_enc
        && !crypto::looks_like_wrapped_secret(enc, &token)
    {
        err!("tokenEnc 必须是用户密钥加密后的 EncString，不能是令牌明文");
    }
    let mut record = McpToken::new(
        user_uuid.clone(),
        crypto::token_hash(&token),
        crypto::generate_salt(),
        token_enc,
        clean_label(label),
    );
    record.save(conn).await?;
    Ok(IssuedToken {
        token,
        token_id: record.uuid,
        key_salt: record.key_salt,
        cleared: Vec::new(),
    })
}

pub async fn rotate_token(
    user_uuid: &UserId,
    label: Option<String>,
    token_enc: Option<String>,
    conn: &DbConn,
) -> Result<IssuedToken, crate::Error> {
    let cleared = cleared_entries(user_uuid, conn).await?;
    let token = crypto::generate_token();
    if let Some(enc) = &token_enc
        && !crypto::looks_like_wrapped_secret(enc, &token)
    {
        err!("tokenEnc 必须是用户密钥加密后的 EncString，不能是令牌明文");
    }
    let hash = crypto::token_hash(&token);
    let salt = crypto::generate_salt();
    let label = clean_label(label);
    let record = conn
        .transaction(async || {
            McpToken::revoke_active(user_uuid, conn).await?;
            McpEntry::delete_all_by_user(user_uuid, conn).await?;
            let mut record = McpToken::new(user_uuid.clone(), hash, salt, token_enc, label);
            record.save(conn).await?;
            Ok(record)
        })
        .await?;
    Ok(IssuedToken {
        token,
        token_id: record.uuid,
        key_salt: record.key_salt,
        cleared,
    })
}

pub async fn revoke_user(user_uuid: &UserId, conn: &DbConn) -> Result<(), crate::Error> {
    conn.transaction(async || {
        McpToken::revoke_active(user_uuid, conn).await?;
        McpEntry::delete_all_by_user(user_uuid, conn).await?;
        Ok(())
    })
    .await
}

pub async fn delete_source(
    user_uuid: &UserId,
    source: &str,
    source_id: &str,
    conn: &DbConn,
) -> Result<(), crate::Error> {
    McpEntry::delete_by_source(user_uuid, source, source_id, conn).await
}

pub fn validate_input(input: &EntryInput) -> Result<String, &'static str> {
    let alias = alias::normalize_alias(&input.alias)?;
    if input.source != "authenticator" && input.source != "cipher" {
        return Err("source 只能是 authenticator 或 cipher");
    }
    if input.source_id.len() < 32 || input.source_id.len() > 36 {
        return Err("sourceId 无效");
    }
    match input.algorithm.as_str() {
        "SHA1" | "SHA256" | "SHA512" => {}
        _ => return Err("algorithm 只能是 SHA1、SHA256 或 SHA512"),
    }
    if !(5..=10).contains(&input.digits) || !(1..=86_400).contains(&input.period) {
        return Err("digits 或 period 超出范围");
    }
    if !crypto::ciphertext_well_formed(&input.secret_ct) {
        return Err("secretCt 不是有效的 MCP 密文");
    }
    for field in [&input.issuer_ct, &input.account_ct, &input.host_ct].into_iter().flatten() {
        if !crypto::ciphertext_well_formed(field) {
            return Err("展示字段密文无效");
        }
    }
    Ok(alias)
}

pub async fn store_entry(user_uuid: &UserId, mut input: EntryInput, conn: &DbConn) -> Result<McpEntry, crate::Error> {
    let alias = match validate_input(&input) {
        Ok(alias) => alias,
        Err(message) => err!(message),
    };
    input.alias = alias;
    if let Some(existing) = McpEntry::find_by_alias(user_uuid, &input.alias, conn).await
        && (existing.source != input.source || existing.source_id != input.source_id)
    {
        err!("这个别名已经用于另一条验证码");
    }
    let mut entry = McpEntry::find_by_source(user_uuid, &input.source, &input.source_id, conn)
        .await
        .unwrap_or_else(|| McpEntry::new(user_uuid.clone(), &input.source, &input.source_id));
    entry.apply_sealed(McpSealed {
        alias: input.alias,
        secret_ct: input.secret_ct,
        issuer_ct: input.issuer_ct,
        account_ct: input.account_ct,
        host_ct: input.host_ct,
        algorithm: input.algorithm,
        digits: input.digits,
        period: input.period,
        steam: input.steam,
    });
    entry.save(conn).await?;
    Ok(entry)
}

pub async fn list_aliases(session: &McpSession, ip: &str, conn: &DbConn) -> Result<Value, crate::Error> {
    let entries = McpEntry::find_by_user(&session.user_uuid, conn).await?;
    let mut aliases = Vec::with_capacity(entries.len());
    for entry in &entries {
        let fields = metadata(session, entry);
        aliases.push(json!({
            "alias": fields.alias,
            "issuer": fields.issuer,
            "account": fields.account,
            "host": fields.host,
            "digits": entry.digits,
            "period": entry.period,
            "steam": entry.steam,
            "source": entry.source,
        }));
    }
    audit(session, "list", None, true, &format!("{} entries", aliases.len()), ip, conn).await?;
    Ok(protocol::tool_ok(json!({ "aliases": aliases })))
}

pub async fn get_code(session: &McpSession, query: &str, ip: &str, conn: &DbConn) -> Result<Value, crate::Error> {
    read_code(session, query, "get", ip, conn).await
}

pub async fn search(session: &McpSession, query: &str, ip: &str, conn: &DbConn) -> Result<Value, crate::Error> {
    read_code(session, query, "search", ip, conn).await
}

/// Test hook: generate at a chosen unix time instead of the wall clock.
#[cfg(test)]
pub async fn get_code_at(
    session: &McpSession,
    query: &str,
    unix_time: u64,
    ip: &str,
    conn: &DbConn,
) -> Result<Value, crate::Error> {
    read_code_at(session, query, "get", unix_time, ip, conn).await
}

async fn read_code(
    session: &McpSession,
    query: &str,
    action: &str,
    ip: &str,
    conn: &DbConn,
) -> Result<Value, crate::Error> {
    let now = Utc::now().timestamp();
    let unix_time = u64::try_from(now).unwrap_or(0);
    read_code_at(session, query, action, unix_time, ip, conn).await
}

async fn read_code_at(
    session: &McpSession,
    query: &str,
    action: &str,
    unix_time: u64,
    ip: &str,
    conn: &DbConn,
) -> Result<Value, crate::Error> {
    let entries = McpEntry::find_by_user(&session.user_uuid, conn).await?;
    let views: Vec<(AliasFields, &McpEntry)> = entries.iter().map(|entry| (metadata(session, entry), entry)).collect();
    let fields: Vec<AliasFields> = views.iter().map(|(fields, _)| fields.clone()).collect();
    match alias::resolve(query, &fields) {
        Resolve::None => {
            audit(session, action, Some(query), false, "not_found", ip, conn).await?;
            Ok(protocol::tool_err(
                &format!("没有找到和「{query}」匹配的验证码。可以先调用 list_totp_aliases。"),
                json!({"error": "not_found", "query": query}),
            ))
        }
        Resolve::Ambiguous(candidates) => {
            audit(session, action, Some(query), false, "ambiguous", ip, conn).await?;
            let listed = candidates
                .iter()
                .map(|candidate| {
                    let name = display_name(candidate);
                    if name.is_empty() {
                        format!("- {}", candidate.alias)
                    } else {
                        format!("- {}：{name}", candidate.alias)
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(protocol::tool_err(
                &format!(
                    "「{query}」匹配到多条，没有返回验证码。请选用下面的精确别名，再次调用 get_totp_code：\n{listed}"
                ),
                json!({"error": "ambiguous", "query": query, "candidates": candidates}),
            ))
        }
        Resolve::Match {
            index,
            kind,
        } => {
            let entry = views[index].1;
            let alias = entry.alias.clone();
            match code_for_entry(session, entry, unix_time, kind) {
                Ok(code) => {
                    audit(session, action, Some(&alias), true, kind, ip, conn).await?;
                    Ok(code)
                }
                Err(message) => {
                    audit(session, action, Some(&alias), false, "decrypt", ip, conn).await?;
                    Ok(protocol::tool_err(&message, json!({"error": "decrypt", "alias": alias})))
                }
            }
        }
    }
}

fn code_for_entry(session: &McpSession, entry: &McpEntry, unix_time: u64, kind: &str) -> Result<Value, String> {
    let aad = crypto::aad(&session.user_uuid.to_string(), &entry.source, &entry.source_id, &entry.alias, "secret");
    let mut secret = session
        .key
        .open(&aad, &entry.secret_ct)
        .map_err(|()| "这条验证码无法用当前令牌解密。请在扩展里重新打开「允许 MCP 读取」。".to_owned())?;
    let secret_text = String::from_utf8(secret.clone()).map_err(|_| "密钥不是文本".to_owned())?;
    crypto::zeroize(&mut secret);
    let raw = totp::decode_base32_secret(&secret_text).map_err(|_| "密钥不是有效的 Base32".to_owned())?;
    let mut secret_bytes = secret_text.into_bytes();
    crypto::zeroize(&mut secret_bytes);
    let generated = totp::generate(
        &entry.algorithm,
        &raw,
        u32::try_from(entry.digits).unwrap_or(6),
        u64::try_from(entry.period).unwrap_or(30),
        entry.steam,
        unix_time,
    )
    .map_err(|_| "无法计算验证码".to_owned())?;
    let mut raw_secret = raw;
    crypto::zeroize(&mut raw_secret);
    let fields = metadata(session, entry);
    Ok(protocol::tool_ok(json!({
        "code": generated.code,
        "seconds_remaining": generated.seconds_remaining,
        "issuer": fields.issuer,
        "account": fields.account,
        "host": fields.host,
        "alias": entry.alias,
        "match": kind,
        "digits": entry.digits,
        "period": entry.period,
        "steam": entry.steam,
    })))
}

fn metadata(session: &McpSession, entry: &McpEntry) -> AliasFields {
    AliasFields {
        alias: entry.alias.clone(),
        issuer: open_optional(session, entry, "issuer", entry.issuer_ct.as_deref()),
        account: open_optional(session, entry, "account", entry.account_ct.as_deref()),
        host: open_optional(session, entry, "host", entry.host_ct.as_deref()),
    }
}

fn open_optional(session: &McpSession, entry: &McpEntry, field: &str, ciphertext: Option<&str>) -> String {
    let Some(ciphertext) = ciphertext else {
        return String::new();
    };
    let aad = crypto::aad(&session.user_uuid.to_string(), &entry.source, &entry.source_id, &entry.alias, field);
    match session.key.open(&aad, ciphertext) {
        Ok(mut bytes) => {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            crypto::zeroize(&mut bytes);
            text
        }
        Err(()) => String::new(),
    }
}

fn display_name(candidate: &alias::Candidate) -> String {
    match (candidate.issuer.as_str(), candidate.account.as_str()) {
        ("", "") => candidate.host.clone(),
        ("", account) => account.to_owned(),
        (issuer, "") => issuer.to_owned(),
        (issuer, account) => format!("{issuer} / {account}"),
    }
}

async fn cleared_entries(user_uuid: &UserId, conn: &DbConn) -> Result<Vec<Value>, crate::Error> {
    let entries = McpEntry::find_by_user(user_uuid, conn).await?;
    Ok(entries
        .iter()
        .map(|entry| {
            json!({
                "source": entry.source,
                "sourceId": entry.source_id,
                "alias": entry.alias,
            })
        })
        .collect())
}

fn clean_label(label: Option<String>) -> Option<String> {
    label.and_then(|label| {
        let label = label.trim();
        if label.is_empty() {
            None
        } else {
            Some(label.chars().take(64).collect())
        }
    })
}

async fn audit(
    session: &McpSession,
    action: &str,
    alias: Option<&str>,
    success: bool,
    detail: &str,
    ip: &str,
    conn: &DbConn,
) -> Result<(), crate::Error> {
    McpAudit::record(
        AuditNote {
            user_uuid: Some(&session.user_uuid),
            token_uuid: Some(&session.token_uuid),
            action,
            alias,
            success,
            detail,
            ip: Some(ip),
        },
        conn,
    )
    .await
}

pub async fn audit_anonymous(
    action: &str,
    success: bool,
    detail: &str,
    ip: &str,
    conn: &DbConn,
) -> Result<(), crate::Error> {
    McpAudit::record(
        AuditNote {
            user_uuid: None,
            token_uuid: None,
            action,
            alias: None,
            success,
            detail,
            ip: Some(ip),
        },
        conn,
    )
    .await
}

pub async fn audit_user(
    user_uuid: &UserId,
    action: &str,
    success: bool,
    detail: &str,
    ip: &str,
    conn: &DbConn,
) -> Result<(), crate::Error> {
    McpAudit::record(
        AuditNote {
            user_uuid: Some(user_uuid),
            token_uuid: None,
            action,
            alias: None,
            success,
            detail,
            ip: Some(ip),
        },
        conn,
    )
    .await
}

#[cfg(all(test, sqlite))]
mod tests {
    use super::*;
    use crate::{
        db::{models::User, test_db},
        mcp::crypto::{self, McpKey},
    };

    fn seal(key: &McpKey, user: &str, source_id: &str, alias: &str, field: &str, text: &str) -> String {
        key.seal(&crypto::aad(user, "authenticator", source_id, alias, field), text.as_bytes()).unwrap()
    }

    #[test]
    fn issue_read_revoke_and_ambiguous_alias() {
        test_db::run(async |db| {
            let conn = db.conn();
            let mut user = User::new("mcp@example.com", None);
            user.save(&conn).await.unwrap();
            let issued = issue_token(&user.uuid, Some("claude".into()), None, &conn).await.unwrap();
            let key = McpKey::derive(&issued.token, &crypto::decode_salt(&issued.key_salt).unwrap()).unwrap();
            let user_id = user.uuid.to_string();
            let secret = data_encoding::BASE32_NOPAD.encode(b"12345678901234567890");
            let gitlab = "11111111-1111-1111-1111-111111111111";
            let github = "22222222-2222-2222-2222-222222222222";
            store_entry(
                &user.uuid,
                EntryInput {
                    source: "authenticator".into(),
                    source_id: gitlab.into(),
                    alias: "GitLab".into(),
                    secret_ct: seal(&key, &user_id, gitlab, "gitlab", "secret", &secret),
                    issuer_ct: Some(seal(&key, &user_id, gitlab, "gitlab", "issuer", "GitLab")),
                    account_ct: Some(seal(&key, &user_id, gitlab, "gitlab", "account", "ada")),
                    host_ct: Some(seal(&key, &user_id, gitlab, "gitlab", "host", "gitlab.com")),
                    algorithm: "SHA1".into(),
                    digits: 8,
                    period: 30,
                    steam: false,
                },
                &conn,
            )
            .await
            .unwrap();
            store_entry(
                &user.uuid,
                EntryInput {
                    source: "authenticator".into(),
                    source_id: github.into(),
                    alias: "github".into(),
                    secret_ct: seal(&key, &user_id, github, "github", "secret", &secret),
                    issuer_ct: Some(seal(&key, &user_id, github, "github", "issuer", "GitHub")),
                    account_ct: Some(seal(&key, &user_id, github, "github", "account", "ada")),
                    host_ct: None,
                    algorithm: "SHA1".into(),
                    digits: 6,
                    period: 30,
                    steam: false,
                },
                &conn,
            )
            .await
            .unwrap();

            let session = McpSession::open(&issued.token, &conn).await.unwrap();
            let code = get_code_at(&session, "gitlab", 59, "127.0.0.1", &conn).await.unwrap();
            assert_eq!(code["isError"], false);
            assert_eq!(code["structuredContent"]["code"], "94287082");
            assert_eq!(code["structuredContent"]["issuer"], "GitLab");
            assert_eq!(code["structuredContent"]["account"], "ada");
            assert_eq!(code["structuredContent"]["seconds_remaining"], 1);
            assert_eq!(code["structuredContent"]["match"], "exact");

            let fuzzy = get_code_at(&session, "gitlab.com", 59, "127.0.0.1", &conn).await.unwrap();
            assert_eq!(fuzzy["structuredContent"]["alias"], "gitlab");
            assert_eq!(fuzzy["structuredContent"]["match"], "fuzzy");

            let ambiguous = get_code_at(&session, "ada", 59, "127.0.0.1", &conn).await.unwrap();
            assert_eq!(ambiguous["isError"], true);
            assert!(ambiguous["structuredContent"].get("code").is_none());
            assert_eq!(ambiguous["structuredContent"]["error"], "ambiguous");

            let rows = McpAudit::recent_for_user(&user.uuid, &conn).await.unwrap();
            assert!(rows.iter().any(|row| row.action == "get" && row.success));
            assert!(rows.iter().all(|row| row.detail.as_deref() != Some("94287082")));

            assert!(McpSession::open("vw_mcp_not-a-real-token", &conn).await.is_err());
            revoke_user(&user.uuid, &conn).await.unwrap();
            assert!(matches!(McpSession::open(&issued.token, &conn).await, Err(OpenError::Revoked { .. })));
            assert!(McpEntry::find_by_user(&user.uuid, &conn).await.unwrap().is_empty());
            assert!(issue_token(&user.uuid, None, None, &conn).await.is_ok());
        });
    }
}
