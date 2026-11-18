use rocket::serde::json::Json;
use serde_json::Value;

use crate::{
    api::{ApiResult, EmptyResult, JsonResult, Notify, UpdateType},
    auth::Headers,
    db::{
        DbConn,
        models::{AuthenticatorEntry, AuthenticatorEntryFields, AuthenticatorEntryId},
    },
};

// WebSocket / push `Type` values for these routes: create = 30, update = 31, delete = 32.
//
// `name`, `issuer`, `secret`, and `notes` are client-encrypted EncStrings. They are stored and
// returned unchanged. `algorithm`, `digits`, and `period` are plaintext.
//
// PUT replaces the entry. Omitted optional fields use the same defaults as POST: issuer and notes
// become null, algorithm SHA1, digits 6, period 30, favorite false, sortOrder 0.

const DEFAULT_ALGORITHM: &str = "SHA1";
const DEFAULT_DIGITS: i32 = 6;
const DEFAULT_PERIOD: i32 = 30;
const MIN_DIGITS: i32 = 5;
const MAX_DIGITS: i32 = 10;
const MIN_PERIOD: i32 = 1;
const MAX_PERIOD: i32 = 86_400;
const MAX_ENCRYPTED_LEN: usize = 100_000;

pub fn routes() -> Vec<rocket::Route> {
    routes![
        get_authenticator_entries,
        get_authenticator_entry,
        post_authenticator_entry,
        put_authenticator_entry,
        delete_authenticator_entry,
    ]
}

#[get("/authenticator")]
async fn get_authenticator_entries(headers: Headers, conn: DbConn) -> Json<Value> {
    let entries = AuthenticatorEntry::find_by_user(&headers.user.uuid, &conn).await;
    let entries_json: Vec<Value> = entries.iter().map(AuthenticatorEntry::to_json).collect();

    Json(json!({
        "data": entries_json,
        "object": "list",
        "continuationToken": null,
    }))
}

#[get("/authenticator/<entry_id>")]
async fn get_authenticator_entry(entry_id: AuthenticatorEntryId, headers: Headers, conn: DbConn) -> JsonResult {
    if let Some(entry) = AuthenticatorEntry::find_by_uuid_and_user(&entry_id, &headers.user.uuid, &conn).await {
        Ok(Json(entry.to_json()))
    } else {
        err!("Invalid authenticator entry", "Authenticator entry does not exist or belongs to another user")
    }
}

#[post("/authenticator", data = "<data>")]
async fn post_authenticator_entry(
    data: Json<AuthenticatorEntryData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let mut entry = AuthenticatorEntry::new(headers.user.uuid, data.into_inner().into_fields()?);

    entry.save(&conn).await?;
    nt.send_authenticator_update(UpdateType::SyncAuthenticatorCreate, &entry, &headers.device, &conn).await;

    Ok(Json(entry.to_json()))
}

#[put("/authenticator/<entry_id>", data = "<data>")]
async fn put_authenticator_entry(
    entry_id: AuthenticatorEntryId,
    data: Json<AuthenticatorEntryData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let Some(mut entry) = AuthenticatorEntry::find_by_uuid_and_user(&entry_id, &headers.user.uuid, &conn).await else {
        err!("Invalid authenticator entry", "Authenticator entry does not exist or belongs to another user")
    };

    entry.apply(data.into_inner().into_fields()?);
    entry.save(&conn).await?;
    nt.send_authenticator_update(UpdateType::SyncAuthenticatorUpdate, &entry, &headers.device, &conn).await;

    Ok(Json(entry.to_json()))
}

#[delete("/authenticator/<entry_id>")]
async fn delete_authenticator_entry(
    entry_id: AuthenticatorEntryId,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let Some(entry) = AuthenticatorEntry::find_by_uuid_and_user(&entry_id, &headers.user.uuid, &conn).await else {
        err!("Invalid authenticator entry", "Authenticator entry does not exist or belongs to another user")
    };

    entry.delete(&conn).await?;
    nt.send_authenticator_update(UpdateType::SyncAuthenticatorDelete, &entry, &headers.device, &conn).await;

    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorEntryData {
    name: String,
    issuer: Option<String>,
    secret: String,
    algorithm: Option<String>,
    digits: Option<i32>,
    period: Option<i32>,
    notes: Option<String>,
    favorite: Option<bool>,
    sort_order: Option<i32>,
}

impl AuthenticatorEntryData {
    fn into_fields(self) -> ApiResult<AuthenticatorEntryFields> {
        Ok(AuthenticatorEntryFields {
            name: require_enc(self.name, "Name")?,
            issuer: optional_enc(self.issuer, "Issuer")?,
            secret: require_enc(self.secret, "Secret")?,
            algorithm: normalize_algorithm(self.algorithm)?,
            digits: normalize_digits(self.digits)?,
            period: normalize_period(self.period)?,
            notes: optional_enc(self.notes, "Notes")?,
            favorite: self.favorite.unwrap_or(false),
            sort_order: self.sort_order.unwrap_or(0),
        })
    }
}

fn require_enc(value: String, field: &str) -> ApiResult<String> {
    if value.is_empty() {
        err!(format!("The {field} field is required."))
    }
    validate_enc_string(value, field)
}

fn optional_enc(value: Option<String>, field: &str) -> ApiResult<Option<String>> {
    match value {
        None => Ok(None),
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => Ok(Some(validate_enc_string(value, field)?)),
    }
}

/// Accepts a Bitwarden EncString (`{type}.{payload}`, types 0 through 7) without decrypting it.
fn validate_enc_string(value: String, field: &str) -> ApiResult<String> {
    if value.len() > MAX_ENCRYPTED_LEN {
        err!(format!("The field {field} must be a string with a maximum length of {MAX_ENCRYPTED_LEN}."))
    }
    if !is_enc_string(&value) {
        err!(format!("The {field} field must be a client-encrypted EncString."))
    }
    Ok(value)
}

fn is_enc_string(value: &str) -> bool {
    let Some((enc_type, payload)) = value.split_once('.') else {
        return false;
    };
    matches!(enc_type, "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7")
        && !payload.is_empty()
        && payload.bytes().all(|byte| {
            matches!(
                byte,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' | b'-' | b'_' | b'|' | b'.'
            )
        })
}

fn normalize_algorithm(value: Option<String>) -> ApiResult<String> {
    let Some(value) = value else {
        return Ok(DEFAULT_ALGORITHM.to_owned());
    };
    if matches!(value.as_str(), "SHA1" | "SHA256" | "SHA512") {
        Ok(value)
    } else {
        err!("The Algorithm field must be one of SHA1, SHA256, or SHA512.")
    }
}

fn normalize_digits(value: Option<i32>) -> ApiResult<i32> {
    match value {
        None => Ok(DEFAULT_DIGITS),
        Some(digits) if (MIN_DIGITS..=MAX_DIGITS).contains(&digits) => Ok(digits),
        Some(_) => err!(format!("The Digits field must be an integer between {MIN_DIGITS} and {MAX_DIGITS}.")),
    }
}

fn normalize_period(value: Option<i32>) -> ApiResult<i32> {
    match value {
        None => Ok(DEFAULT_PERIOD),
        Some(period) if (MIN_PERIOD..=MAX_PERIOD).contains(&period) => Ok(period),
        Some(_) => {
            err!(format!("The Period field must be an integer between {MIN_PERIOD} and {MAX_PERIOD} seconds."))
        }
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    const ENC: &str = "2.iv|ct|mac";

    fn request(value: Value) -> AuthenticatorEntryData {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn defaults_and_accepts_encrypted_fields() {
        let fields = request(json!({"name": ENC, "secret": ENC})).into_fields().unwrap();
        assert_eq!(fields.name, ENC);
        assert_eq!(fields.secret, ENC);
        assert_eq!(fields.algorithm, "SHA1");
        assert_eq!(fields.digits, 6);
        assert_eq!(fields.period, 30);
        assert!(!fields.favorite);
        assert_eq!(fields.sort_order, 0);
        assert!(fields.issuer.is_none());
        assert!(fields.notes.is_none());

        let fields = request(json!({
            "name": "0.abc=",
            "secret": "7.abc-_",
            "issuer": "",
            "notes": "2.note",
            "algorithm": "SHA512",
            "digits": MIN_DIGITS,
            "period": MAX_PERIOD,
            "favorite": true,
            "sortOrder": -2
        }))
        .into_fields()
        .unwrap();
        assert_eq!(fields.algorithm, "SHA512");
        assert_eq!(fields.digits, MIN_DIGITS);
        assert_eq!(fields.period, MAX_PERIOD);
        assert!(fields.favorite);
        assert_eq!(fields.sort_order, -2);
        assert!(fields.issuer.is_none());
        assert_eq!(fields.notes.as_deref(), Some("2.note"));
    }

    #[test]
    fn rejects_plaintext_and_out_of_range_metadata() {
        for value in [
            json!({"name": "GitHub", "secret": ENC}),
            json!({"name": ENC, "secret": "JBSWY3DPEHPK3PXP"}),
            json!({"name": ENC, "secret": ENC, "issuer": "GitHub"}),
            json!({"name": ENC, "secret": ENC, "notes": "hello"}),
            json!({"name": "", "secret": ENC}),
            json!({"name": "2.", "secret": ENC}),
            json!({"name": "8.abc", "secret": ENC}),
            json!({"name": "2.has space", "secret": ENC}),
            json!({"name": ENC, "secret": ENC, "algorithm": "sha1"}),
            json!({"name": ENC, "secret": ENC, "algorithm": ""}),
            json!({"name": ENC, "secret": ENC, "digits": MIN_DIGITS - 1}),
            json!({"name": ENC, "secret": ENC, "digits": MAX_DIGITS + 1}),
            json!({"name": ENC, "secret": ENC, "period": 0}),
            json!({"name": ENC, "secret": ENC, "period": MAX_PERIOD + 1}),
        ] {
            assert!(request(value).into_fields().is_err());
        }

        let huge = format!("2.{}", "a".repeat(MAX_ENCRYPTED_LEN));
        assert!(request(json!({"name": huge, "secret": ENC})).into_fields().is_err());
        assert!(serde_json::from_value::<AuthenticatorEntryData>(json!({"secret": ENC})).is_err());
    }
}

#[cfg(all(test, sqlite))]
mod api_tests {
    use std::sync::Arc;

    use chrono::Datelike;
    use diesel::connection::SimpleConnection;
    use rocket::serde::json::Json;

    use super::*;
    use crate::{
        api::notifications::{WS_USERS, WebSocketUsers},
        auth::ClientIp,
        db::{
            models::{Device, User, UserId},
            test_db,
        },
    };

    const ENC: &str = "2.iv|ciphertext|mac";

    fn headers_for(user: User) -> Headers {
        Headers {
            host: "http://localhost".into(),
            device: Device::new("test".to_owned().into(), user.uuid.clone(), "test".into(), 1),
            user,
            ip: ClientIp {
                ip: "127.0.0.1".parse().unwrap(),
            },
        }
    }

    async fn headers(user_id: &UserId, conn: &DbConn) -> Headers {
        headers_for(User::find_by_uuid(user_id, conn).await.unwrap())
    }

    #[test]
    fn authenticator_api_is_owner_scoped_and_included_in_sync() {
        test_db::run(async |db| {
            let conn = db.conn();
            let mut owner = User::new("owner-authn@example.com", None);
            owner.save(&conn).await.unwrap();
            let owner_id = owner.uuid.clone();
            let mut other = User::new("other-authn@example.com", None);
            other.save(&conn).await.unwrap();
            let other_id = other.uuid.clone();

            let rocket = rocket::build().manage(Arc::clone(&WS_USERS));
            let notify: Notify<'_> = rocket.state::<Arc<WebSocketUsers>>().unwrap().into();

            conn.run(|c| c.batch_execute("UPDATE users SET updated_at='2000-01-01 00:00:00'")).await.unwrap();
            let rejected = serde_json::from_value(json!({"name": "GitHub", "secret": "JBSWY3DPEHPK3PXP"})).unwrap();
            assert!(
                post_authenticator_entry(Json(rejected), headers(&owner_id, &conn).await, db.conn(), notify)
                    .await
                    .is_err()
            );
            assert_eq!(AuthenticatorEntry::find_by_user(&owner_id, &conn).await.len(), 0);

            let created = post_authenticator_entry(
                Json(serde_json::from_value(json!({"name": ENC, "secret": ENC, "sortOrder": 5})).unwrap()),
                headers(&owner_id, &conn).await,
                db.conn(),
                notify,
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(created["object"], "authenticatorEntry");
            assert_eq!(created["secret"], ENC);
            assert_eq!(created["algorithm"], "SHA1");
            assert_eq!(created["digits"], 6);
            assert_eq!(created["period"], 30);
            assert_eq!(created["favorite"], false);
            assert_eq!(created["issuer"], Value::Null);
            assert!(User::find_by_uuid(&owner_id, &conn).await.unwrap().updated_at.year() > 2000);

            let first_id: AuthenticatorEntryId = created["id"].as_str().unwrap().to_owned().into();
            let second = post_authenticator_entry(
                Json(
                    serde_json::from_value(json!({
                        "name": "2.other",
                        "secret": "2.othersecret",
                        "issuer": "2.issuer",
                        "algorithm": "SHA256",
                        "digits": 8,
                        "period": 60,
                        "notes": "2.notes",
                        "favorite": true,
                        "sortOrder": 1
                    }))
                    .unwrap(),
                ),
                headers(&owner_id, &conn).await,
                db.conn(),
                notify,
            )
            .await
            .unwrap()
            .into_inner();
            let second_id: AuthenticatorEntryId = second["id"].as_str().unwrap().to_owned().into();
            assert_eq!(second["algorithm"], "SHA256");
            assert_eq!(second["issuer"], "2.issuer");

            let list = get_authenticator_entries(headers(&owner_id, &conn).await, db.conn()).await.into_inner();
            assert_eq!(list["object"], "list");
            assert!(list["continuationToken"].is_null());
            let data = list["data"].as_array().unwrap();
            assert_eq!(data.len(), 2);
            assert_eq!(data[0]["id"], second["id"]);
            assert_eq!(data[0]["sortOrder"], 1);
            assert_eq!(data[1]["id"], created["id"]);
            assert_eq!(data[1]["sortOrder"], 5);

            let fetched = get_authenticator_entry(second_id.clone(), headers(&owner_id, &conn).await, db.conn())
                .await
                .unwrap()
                .into_inner();
            assert_eq!(fetched["secret"], "2.othersecret");
            assert!(
                get_authenticator_entry(second_id.clone(), headers(&other_id, &conn).await, db.conn()).await.is_err()
            );
            assert_eq!(
                get_authenticator_entries(headers(&other_id, &conn).await, db.conn()).await.into_inner()["data"]
                    .as_array()
                    .unwrap()
                    .len(),
                0
            );

            let unchanged = serde_json::from_value(json!({"name": "2.nope", "secret": "2.nope"})).unwrap();
            assert!(
                put_authenticator_entry(
                    second_id.clone(),
                    Json(unchanged),
                    headers(&other_id, &conn).await,
                    db.conn(),
                    notify,
                )
                .await
                .is_err()
            );
            assert!(
                delete_authenticator_entry(second_id.clone(), headers(&other_id, &conn).await, db.conn(), notify)
                    .await
                    .is_err()
            );
            assert_eq!(
                AuthenticatorEntry::find_by_uuid_and_user(&second_id, &owner_id, &conn).await.unwrap().secret,
                "2.othersecret"
            );

            let updated = put_authenticator_entry(
                second_id.clone(),
                Json(serde_json::from_value(json!({"name": "2.renamed", "secret": "2.newsecret"})).unwrap()),
                headers(&owner_id, &conn).await,
                db.conn(),
                notify,
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(updated["name"], "2.renamed");
            assert_eq!(updated["secret"], "2.newsecret");
            assert_eq!(updated["issuer"], Value::Null);
            assert_eq!(updated["algorithm"], "SHA1");
            assert_eq!(updated["favorite"], false);
            assert_eq!(updated["creationDate"], second["creationDate"]);
            assert_ne!(updated["revisionDate"], second["revisionDate"]);

            let owner_sync = super::super::ciphers::sync(
                super::super::ciphers::SyncData::default(),
                headers(&owner_id, &conn).await,
                None,
                db.conn(),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(owner_sync["object"], "sync");
            let synced = owner_sync["authenticatorEntries"].as_array().unwrap();
            assert_eq!(synced.len(), 2);
            assert_eq!(synced[0]["id"], second["id"]);
            assert_eq!(synced[0]["object"], "authenticatorEntry");
            let other_sync = super::super::ciphers::sync(
                super::super::ciphers::SyncData::default(),
                headers(&other_id, &conn).await,
                None,
                db.conn(),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(other_sync["authenticatorEntries"].as_array().unwrap().len(), 0);

            conn.run(|c| c.batch_execute("UPDATE users SET updated_at='2000-01-01 00:00:00'")).await.unwrap();
            delete_authenticator_entry(first_id.clone(), headers(&owner_id, &conn).await, db.conn(), notify)
                .await
                .unwrap();
            assert!(User::find_by_uuid(&owner_id, &conn).await.unwrap().updated_at.year() > 2000);
            assert!(get_authenticator_entry(first_id, headers(&owner_id, &conn).await, db.conn()).await.is_err());

            User::find_by_uuid(&owner_id, &conn).await.unwrap().delete(&conn).await.unwrap();
            assert_eq!(AuthenticatorEntry::find_by_user(&owner_id, &conn).await.len(), 0);
        });
    }
}
