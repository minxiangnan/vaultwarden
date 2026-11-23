use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    db::{
        DbConn,
        schema::{mcp_audit, mcp_entries, mcp_tokens},
    },
    error::MapResult,
    util::{format_date, get_uuid},
};

use super::UserId;

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Clone, Debug)]
#[diesel(table_name = mcp_tokens)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct McpToken {
    pub uuid: String,
    pub user_uuid: UserId,
    pub token_hash: String,
    pub key_salt: String,
    pub token_enc: Option<String>,
    pub label: Option<String>,
    pub created_at: NaiveDateTime,
    pub revoked_at: Option<NaiveDateTime>,
}

impl McpToken {
    pub fn new(
        user_uuid: UserId,
        token_hash: String,
        key_salt: String,
        token_enc: Option<String>,
        label: Option<String>,
    ) -> Self {
        Self {
            uuid: get_uuid(),
            user_uuid,
            token_hash,
            key_salt,
            token_enc,
            label,
            created_at: Utc::now().naive_utc(),
            revoked_at: None,
        }
    }

    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            mysql {
                diesel::insert_into(mcp_tokens::table)
                    .values(&*self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving MCP token")
            }
            postgresql, sqlite {
                diesel::insert_into(mcp_tokens::table)
                    .values(&*self)
                    .on_conflict(mcp_tokens::uuid)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving MCP token")
            }
        }
    }

    pub async fn find_by_hash(token_hash: &str, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| mcp_tokens::table.filter(mcp_tokens::token_hash.eq(token_hash)).first::<Self>(conn).ok())
            .await
    }

    pub async fn find_active_by_user(user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            mcp_tokens::table
                .filter(mcp_tokens::user_uuid.eq(user_uuid))
                .filter(mcp_tokens::revoked_at.is_null())
                .order(mcp_tokens::created_at.desc())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn has_active(user_uuid: &UserId, conn: &DbConn) -> bool {
        Self::find_active_by_user(user_uuid, conn).await.is_some()
    }

    pub async fn revoke_active(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            diesel::update(
                mcp_tokens::table.filter(mcp_tokens::user_uuid.eq(user_uuid)).filter(mcp_tokens::revoked_at.is_null()),
            )
            .set(mcp_tokens::revoked_at.eq(now))
            .execute(conn)
            .map_res("Error revoking MCP token")
        })
        .await
    }

    pub async fn set_token_enc(&mut self, token_enc: String, conn: &DbConn) -> EmptyResult {
        self.token_enc = Some(token_enc);
        self.save(conn).await
    }

    pub fn to_status_json(&self, entry_count: i64) -> serde_json::Value {
        json!({
            "enabled": true,
            "configured": self.revoked_at.is_none(),
            "revoked": self.revoked_at.is_some(),
            "tokenId": self.uuid,
            "label": self.label,
            "keySalt": if self.revoked_at.is_none() { Some(self.key_salt.as_str()) } else { None },
            "tokenEnc": self.token_enc,
            "createdAt": format_date(&self.created_at),
            "entryCount": entry_count,
            "object": "mcpStatus",
        })
    }
}

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Clone, Debug)]
#[diesel(table_name = mcp_entries)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct McpEntry {
    pub uuid: String,
    pub user_uuid: UserId,
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
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

pub struct McpSealed {
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

impl McpEntry {
    pub fn new(user_uuid: UserId, source: &str, source_id: &str) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            uuid: get_uuid(),
            user_uuid,
            source: source.to_owned(),
            source_id: source_id.to_owned(),
            alias: String::new(),
            secret_ct: String::new(),
            issuer_ct: None,
            account_ct: None,
            host_ct: None,
            algorithm: "SHA1".to_owned(),
            digits: 6,
            period: 30,
            steam: false,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn apply_sealed(&mut self, sealed: McpSealed) {
        self.alias = sealed.alias;
        self.secret_ct = sealed.secret_ct;
        self.issuer_ct = sealed.issuer_ct;
        self.account_ct = sealed.account_ct;
        self.host_ct = sealed.host_ct;
        self.algorithm = sealed.algorithm;
        self.digits = sealed.digits;
        self.period = sealed.period;
        self.steam = sealed.steam;
    }

    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.updated_at = Utc::now().naive_utc();
        db_run! { conn:
            mysql {
                diesel::insert_into(mcp_entries::table)
                    .values(&*self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving MCP entry")
            }
            postgresql, sqlite {
                diesel::insert_into(mcp_entries::table)
                    .values(&*self)
                    .on_conflict(mcp_entries::uuid)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving MCP entry")
            }
        }
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Result<Vec<Self>, crate::Error> {
        conn.run(move |conn| {
            mcp_entries::table
                .filter(mcp_entries::user_uuid.eq(user_uuid))
                .order(mcp_entries::alias.asc())
                .load::<Self>(conn)
                .map_res("Error loading MCP entries")
        })
        .await
    }

    pub async fn find_by_alias(user_uuid: &UserId, alias: &str, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            mcp_entries::table
                .filter(mcp_entries::user_uuid.eq(user_uuid))
                .filter(mcp_entries::alias.eq(alias))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_source(user_uuid: &UserId, source: &str, source_id: &str, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            mcp_entries::table
                .filter(mcp_entries::user_uuid.eq(user_uuid))
                .filter(mcp_entries::source.eq(source))
                .filter(mcp_entries::source_id.eq(source_id))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn delete_by_source(user_uuid: &UserId, source: &str, source_id: &str, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(
                mcp_entries::table
                    .filter(mcp_entries::user_uuid.eq(user_uuid))
                    .filter(mcp_entries::source.eq(source))
                    .filter(mcp_entries::source_id.eq(source_id)),
            )
            .execute(conn)
            .map_res("Error deleting MCP entry")
        })
        .await
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(mcp_entries::table.filter(mcp_entries::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error deleting MCP entries")
        })
        .await
    }

    pub fn to_summary_json(&self) -> serde_json::Value {
        json!({
            "id": self.uuid,
            "source": self.source,
            "sourceId": self.source_id,
            "alias": self.alias,
            "algorithm": self.algorithm,
            "digits": self.digits,
            "period": self.period,
            "steam": self.steam,
            "updatedAt": format_date(&self.updated_at),
            "object": "mcpEntry",
        })
    }
}

#[derive(Identifiable, Queryable, Insertable, Clone, Debug)]
#[diesel(table_name = mcp_audit)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct McpAudit {
    pub uuid: String,
    pub user_uuid: Option<UserId>,
    pub token_uuid: Option<String>,
    pub action: String,
    pub alias: Option<String>,
    pub success: bool,
    pub detail: Option<String>,
    pub ip: Option<String>,
    pub created_at: NaiveDateTime,
}

pub struct AuditNote<'a> {
    pub user_uuid: Option<&'a UserId>,
    pub token_uuid: Option<&'a str>,
    pub action: &'a str,
    pub alias: Option<&'a str>,
    pub success: bool,
    pub detail: &'a str,
    pub ip: Option<&'a str>,
}

impl McpAudit {
    pub async fn record(note: AuditNote<'_>, conn: &DbConn) -> EmptyResult {
        let row = Self {
            uuid: get_uuid(),
            user_uuid: note.user_uuid.cloned(),
            token_uuid: note.token_uuid.map(str::to_owned),
            action: note.action.chars().take(32).collect(),
            alias: note.alias.map(|alias| alias.chars().take(64).collect()),
            success: note.success,
            detail: Some(note.detail.chars().take(300).collect()),
            ip: note.ip.map(|ip| ip.chars().take(64).collect()),
            created_at: Utc::now().naive_utc(),
        };
        conn.run(move |conn| {
            diesel::insert_into(mcp_audit::table).values(&row).execute(conn).map_res("Error writing MCP audit")
        })
        .await
    }

    pub async fn recent_for_user(user_uuid: &UserId, conn: &DbConn) -> Result<Vec<Self>, crate::Error> {
        conn.run(move |conn| {
            mcp_audit::table
                .filter(mcp_audit::user_uuid.eq(user_uuid))
                .order(mcp_audit::created_at.desc())
                .limit(50)
                .load::<Self>(conn)
                .map_res("Error loading MCP audit")
        })
        .await
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "action": self.action,
            "alias": self.alias,
            "success": self.success,
            "detail": self.detail,
            "ip": self.ip,
            "createdAt": format_date(&self.created_at),
            "object": "mcpAudit",
        })
    }
}
