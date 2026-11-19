use chrono::{NaiveDateTime, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use serde_json::Value;

use macros::UuidFromParam;

use crate::{
    api::EmptyResult,
    db::{DbConn, schema::authenticator_entries},
    error::MapResult,
    util::format_date,
};

use super::{User, UserId};

/// Validated authenticator content. Encrypted fields are opaque EncStrings and are never decrypted.
#[derive(Clone, Debug)]
pub struct AuthenticatorEntryFields {
    pub name: String,
    pub issuer: Option<String>,
    pub secret: String,
    pub algorithm: String,
    pub digits: i32,
    pub period: i32,
    pub notes: Option<String>,
    pub favorite: bool,
    pub sort_order: i32,
}

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = authenticator_entries)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct AuthenticatorEntry {
    pub uuid: AuthenticatorEntryId,
    pub user_uuid: UserId,
    pub name: String,
    pub issuer: Option<String>,
    pub secret: String,
    pub algorithm: String,
    pub digits: i32,
    pub period: i32,
    pub notes: Option<String>,
    pub favorite: bool,
    pub sort_order: i32,
    pub revision_date: NaiveDateTime,
    pub creation_date: NaiveDateTime,
}

/// Local methods
impl AuthenticatorEntry {
    pub fn new(user_uuid: UserId, fields: AuthenticatorEntryFields) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: AuthenticatorEntryId(crate::util::get_uuid()),
            user_uuid,
            name: fields.name,
            issuer: fields.issuer,
            secret: fields.secret,
            algorithm: fields.algorithm,
            digits: fields.digits,
            period: fields.period,
            notes: fields.notes,
            favorite: fields.favorite,
            sort_order: fields.sort_order,
            revision_date: now,
            creation_date: now,
        }
    }

    /// Replaces the user-editable content. `creation_date` stays unchanged; `save` bumps `revision_date`.
    pub fn apply(&mut self, fields: AuthenticatorEntryFields) {
        self.name = fields.name;
        self.issuer = fields.issuer;
        self.secret = fields.secret;
        self.algorithm = fields.algorithm;
        self.digits = fields.digits;
        self.period = fields.period;
        self.notes = fields.notes;
        self.favorite = fields.favorite;
        self.sort_order = fields.sort_order;
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "name": self.name,
            "issuer": self.issuer,
            "secret": self.secret,
            "algorithm": self.algorithm,
            "digits": self.digits,
            "period": self.period,
            "notes": self.notes,
            "favorite": self.favorite,
            "sortOrder": self.sort_order,
            "revisionDate": format_date(&self.revision_date),
            "creationDate": format_date(&self.creation_date),
            "object": "authenticatorEntry",
        })
    }
}

/// Database methods
impl AuthenticatorEntry {
    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn).await;
        self.revision_date = Utc::now().naive_utc();

        db_run! { conn:
            mysql {
                diesel::insert_into(authenticator_entries::table)
                    .values(&*self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving authenticator entry")
            }
            postgresql, sqlite {
                diesel::insert_into(authenticator_entries::table)
                    .values(&*self)
                    .on_conflict(authenticator_entries::uuid)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving authenticator entry")
            }
        }
    }

    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn).await;

        conn.run(move |conn| {
            diesel::delete(authenticator_entries::table.filter(authenticator_entries::uuid.eq(&self.uuid)))
                .execute(conn)
                .map_res("Error deleting authenticator entry")
        })
        .await
    }

    /// Removes every entry for a user that is itself being deleted. Does not bump the account revision.
    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(authenticator_entries::table.filter(authenticator_entries::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error deleting authenticator entries")
        })
        .await
    }

    /// Any entry with this id, including one owned by another user. Callers must check ownership.
    pub async fn find_by_uuid(uuid: &AuthenticatorEntryId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            authenticator_entries::table.filter(authenticator_entries::uuid.eq(uuid)).first::<Self>(conn).ok()
        })
        .await
    }

    pub async fn find_by_uuid_and_user(uuid: &AuthenticatorEntryId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            authenticator_entries::table
                .filter(authenticator_entries::uuid.eq(uuid))
                .filter(authenticator_entries::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            authenticator_entries::table
                .filter(authenticator_entries::user_uuid.eq(user_uuid))
                .order((
                    authenticator_entries::sort_order.asc(),
                    authenticator_entries::creation_date.asc(),
                    authenticator_entries::uuid.asc(),
                ))
                .load::<Self>(conn)
                .expect("Error loading authenticator entries")
        })
        .await
    }
}

#[derive(
    Clone,
    Debug,
    AsRef,
    Deref,
    DieselNewType,
    Display,
    From,
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    UuidFromParam,
)]
pub struct AuthenticatorEntryId(String);

#[cfg(test)]
mod json_tests {
    use super::*;

    #[test]
    fn entry_json_matches_the_contract() {
        let entry = AuthenticatorEntry {
            uuid: String::from("11111111-1111-1111-1111-111111111111").into(),
            user_uuid: String::from("22222222-2222-2222-2222-222222222222").into(),
            name: "2.name".into(),
            issuer: None,
            secret: "2.secret".into(),
            algorithm: "SHA256".into(),
            digits: 8,
            period: 60,
            notes: Some("2.notes".into()),
            favorite: true,
            sort_order: 4,
            revision_date: NaiveDateTime::parse_from_str("2026-11-15 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap(),
            creation_date: NaiveDateTime::parse_from_str("2026-11-15 00:00:01", "%Y-%m-%d %H:%M:%S").unwrap(),
        };

        let json = entry.to_json();
        assert_eq!(json["object"], "authenticatorEntry");
        assert_eq!(json["id"], "11111111-1111-1111-1111-111111111111");
        assert_eq!(json["name"], "2.name");
        assert_eq!(json["issuer"], Value::Null);
        assert_eq!(json["secret"], "2.secret");
        assert_eq!(json["algorithm"], "SHA256");
        assert_eq!(json["digits"], 8);
        assert_eq!(json["period"], 60);
        assert_eq!(json["notes"], "2.notes");
        assert_eq!(json["favorite"], true);
        assert_eq!(json["sortOrder"], 4);
        assert!(json["revisionDate"].as_str().unwrap().starts_with("2026-11-15"));
        assert!(json["creationDate"].as_str().unwrap().ends_with('Z'));
        assert!(json.get("userId").is_none());

        // Same keys `AuthenticatorEntryResponse` reads from a list item or a sync entry.
        let mut keys: Vec<_> = json.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "algorithm",
                "creationDate",
                "digits",
                "favorite",
                "id",
                "issuer",
                "name",
                "notes",
                "object",
                "period",
                "revisionDate",
                "secret",
                "sortOrder",
            ]
        );
    }
}
