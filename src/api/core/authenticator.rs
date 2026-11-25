use rocket::serde::json::Json;
use serde_json::Value;

use crate::{
    api::{ApiResult, EmptyResult, JsonResult, Notify, UpdateType},
    auth::Headers,
    db::{
        DbConn,
        models::{AuthenticatorEntry, AuthenticatorEntryFields, AuthenticatorEntryId, User},
    },
};

// WebSocket / push `Type` values for these routes: create = 30, update = 31, delete = 32.
//
// `name`, `issuer`, `secret`, and `notes` are client-encrypted EncStrings. They are stored and
// returned unchanged. `algorithm`, `digits`, and `period` are plaintext.
//
// PUT replaces the entry. Omitted optional fields use the same defaults as POST: issuer and notes
// become null, algorithm SHA1, digits 6, period 30, favorite false, sortOrder 0.
//
// `to_json` is the Entry shape parsed by `AuthenticatorEntryResponse` in the forked browser
// extension (`apps/browser/src/authenticator/authenticator.models.ts`): id, name, issuer, secret,
// algorithm, digits, period, notes, favorite, sortOrder, revisionDate, creationDate, and
// object "authenticatorEntry". `GET /api/sync` returns that same object in `authenticatorEntries`.

const DEFAULT_ALGORITHM: &str = "SHA1";
const DEFAULT_DIGITS: i32 = 6;
const DEFAULT_PERIOD: i32 = 30;
// Kept in lockstep with the forked browser extension.
const MIN_DIGITS: i32 = 5;
const MAX_DIGITS: i32 = 10;
const MIN_PERIOD: i32 = 1;
const MAX_PERIOD: i32 = 86_400;
const MAX_ENCRYPTED_LEN: usize = 100_000;

pub fn routes() -> Vec<rocket::Route> {
    routes![
        get_authenticator_entries,
        get_authenticator_rotation,
        put_authenticator_rotation,
        get_authenticator_entry,
        post_authenticator_entry,
        put_authenticator_entry,
        delete_authenticator_entry,
    ]
}

#[get("/authenticator")]
async fn get_authenticator_entries(headers: Headers, conn: DbConn) -> JsonResult {
    let entries = AuthenticatorEntry::find_by_user(&headers.user.uuid, &conn).await?;
    let entries_json: Vec<Value> = entries.iter().map(AuthenticatorEntry::to_json).collect();

    Ok(Json(json!({
        "data": entries_json,
        "object": "list",
        "continuationToken": null,
    })))
}

/// Pending re-encryption left by `rotate-user-keys`, which cannot carry authenticator entries.
#[get("/authenticator/rotate")]
#[expect(clippy::needless_pass_by_value, reason = "Rocket extracts Headers by value")]
pub(crate) fn get_authenticator_rotation(headers: Headers) -> Json<Value> {
    Json(authenticator_key_rotation_json(&headers.user))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthenticatorRotateRequest {
    pub authenticator_entries: Vec<AuthenticatorRotationData>,
}

/// Finishes a `rotate-user-keys` deferral. The body is the same item shape as
/// `accountData.authenticatorEntries`.
#[put("/authenticator/rotate", data = "<data>")]
pub(crate) async fn put_authenticator_rotation(
    data: Json<AuthenticatorRotateRequest>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    if headers.user.authenticator_legacy_key.is_none() {
        err!("Authenticator entries are not waiting for re-encryption.")
    }
    let data = data.into_inner();
    let user_id = headers.user.uuid.clone();
    let existing = AuthenticatorEntry::find_by_user(&user_id, &conn).await?;
    super::accounts::validate_authenticator_rotation(&data.authenticator_entries, &existing, &user_id, &conn).await?;

    let user = conn
        .transaction(async || {
            let mut existing = AuthenticatorEntry::find_by_user(&user_id, &conn).await?;
            for item in &data.authenticator_entries {
                let Some(saved) = existing.iter_mut().find(|entry| entry.uuid == item.id) else {
                    err!("All existing authenticator entries must be included in the rotation")
                };
                let updated = reencrypted_content(saved, item)?;
                saved.name = updated.name;
                saved.issuer = updated.issuer;
                saved.secret = updated.secret;
                saved.notes = updated.notes;
                saved.save_without_user_revision(&conn).await?;
            }
            let Some(mut user) = User::find_by_uuid(&user_id, &conn).await else {
                err!("User not found")
            };
            user.authenticator_legacy_key = None;
            user.authenticator_legacy_key_id = None;
            user.save(&conn).await?;
            Ok(user)
        })
        .await?;

    nt.send_user_update(UpdateType::SyncVault, &user, headers.device.push_uuid.as_ref(), &conn).await;
    let entries = AuthenticatorEntry::find_by_user(&user_id, &conn).await?;
    let entries_json: Vec<Value> = entries.iter().map(AuthenticatorEntry::to_json).collect();
    Ok(Json(json!({
        "data": entries_json,
        "object": "list",
        "continuationToken": null,
    })))
}

pub(crate) fn authenticator_key_rotation_json(user: &User) -> Value {
    json!({
        "required": user.authenticator_legacy_key.is_some(),
        "wrappedOldUserKey": user.authenticator_legacy_key,
        "oldUserKeyId": user.authenticator_legacy_key_id,
        "object": "authenticatorKeyRotation",
    })
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

/// Bitwarden EncString: `{type}.{segments}` where segments are base64 pieces separated by `|`.
///
/// Type 0 is `iv|ct`. Types 1 and 2 are `iv|ct|mac`. Types 3 and 4 are one RSA blob. Types 5 and 6
/// are `data|mac`. Type 7 is one COSE blob and may be standard or URL-safe base64.
fn is_enc_string(value: &str) -> bool {
    let Some((enc_type, payload)) = value.split_once('.') else {
        return false;
    };
    if payload.is_empty() || payload.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return false;
    }
    let segments: Vec<&str> = payload.split('|').collect();
    let url_safe = enc_type == "7";
    // 0 is iv|ct, 5 and 6 are data|mac: both are two segments. 1 and 2 are iv|ct|mac.
    let expected = match enc_type {
        "1" | "2" => 3,
        "3" | "4" | "7" => 1,
        "0" | "5" | "6" => 2,
        _ => return false,
    };
    segments.len() == expected && segments.iter().all(|segment| is_base64_segment(segment, url_safe))
}

fn is_base64_segment(segment: &str, url_safe: bool) -> bool {
    if segment.is_empty() {
        return false;
    }
    if data_encoding::BASE64.decode(segment.as_bytes()).is_ok() {
        return true;
    }
    url_safe
        && (data_encoding::BASE64URL.decode(segment.as_bytes()).is_ok()
            || data_encoding::BASE64URL_NOPAD.decode(segment.as_bytes()).is_ok())
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

/// One authenticator entry inside a key-rotation `accountData.authenticatorEntries` item.
///
/// `name`, `issuer`, `secret`, and `notes` are EncStrings re-encrypted with the new user key.
/// `algorithm`, `digits`, `period`, `favorite`, and `sortOrder` are the plaintext fields and must
/// be omitted or equal to the stored entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthenticatorRotationData {
    pub id: AuthenticatorEntryId,
    pub name: String,
    pub issuer: Option<String>,
    pub secret: String,
    pub notes: Option<String>,
    pub algorithm: Option<String>,
    pub digits: Option<i32>,
    pub period: Option<i32>,
    pub favorite: Option<bool>,
    pub sort_order: Option<i32>,
}

pub(crate) struct ReencryptedAuthenticator {
    pub name: String,
    pub issuer: Option<String>,
    pub secret: String,
    pub notes: Option<String>,
}

/// Checks a rotation item against the stored entry and returns the new ciphertext.
///
/// An issuer or notes value that exists must be re-encrypted. One that does not exist cannot be
/// added here. Plaintext metadata cannot change.
pub(crate) fn reencrypted_content(
    existing: &AuthenticatorEntry,
    data: &AuthenticatorRotationData,
) -> ApiResult<ReencryptedAuthenticator> {
    unchanged_str(data.algorithm.as_deref(), &existing.algorithm, "Algorithm")?;
    unchanged_i32(data.digits, existing.digits, "Digits")?;
    unchanged_i32(data.period, existing.period, "Period")?;
    unchanged_bool(data.favorite, existing.favorite, "Favorite")?;
    unchanged_i32(data.sort_order, existing.sort_order, "SortOrder")?;

    Ok(ReencryptedAuthenticator {
        name: validate_enc_string(data.name.clone(), "Name")?,
        issuer: reencrypted_optional(existing.issuer.as_deref(), data.issuer.clone(), "Issuer")?,
        secret: validate_enc_string(data.secret.clone(), "Secret")?,
        notes: reencrypted_optional(existing.notes.as_deref(), data.notes.clone(), "Notes")?,
    })
}

fn reencrypted_optional(current: Option<&str>, provided: Option<String>, field: &str) -> ApiResult<Option<String>> {
    let provided = match provided {
        None => None,
        Some(value) if value.is_empty() => None,
        Some(value) => Some(validate_enc_string(value, field)?),
    };
    match (current.is_some(), provided.is_some()) {
        (true, false) => err!(format!("The {field} field must be re-encrypted during key rotation.")),
        (false, true) => err!(format!("The {field} field cannot be added during key rotation.")),
        _ => Ok(provided),
    }
}

fn unchanged_str(provided: Option<&str>, current: &str, field: &str) -> EmptyResult {
    if provided.is_some_and(|value| value != current) {
        err!(format!("The {field} field cannot change during key rotation."))
    }
    Ok(())
}

fn unchanged_i32(provided: Option<i32>, current: i32, field: &str) -> EmptyResult {
    if provided.is_some_and(|value| value != current) {
        err!(format!("The {field} field cannot change during key rotation."))
    }
    Ok(())
}

fn unchanged_bool(provided: Option<bool>, current: bool, field: &str) -> EmptyResult {
    if provided.is_some_and(|value| value != current) {
        err!(format!("The {field} field cannot change during key rotation."))
    }
    Ok(())
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

    const ENC: &str = "2.AAAA|AAAA|AAAA";

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
            "name": "0.AAAA|AAAA",
            "secret": "7.YWJjZA",
            "issuer": "",
            "notes": "2.AAAA|AAAA|AAAB",
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
        assert_eq!(fields.notes.as_deref(), Some("2.AAAA|AAAA|AAAB"));
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
            json!({"name": "2.AAAA|AAAA", "secret": ENC}),
            json!({"name": "0.AAAA", "secret": ENC}),
            json!({"name": "3.AAAA|AAAA", "secret": ENC}),
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

    #[test]
    fn rotation_reencrypts_ciphertext_and_keeps_plaintext_metadata() {
        let entry = AuthenticatorEntry {
            uuid: String::from("11111111-1111-1111-1111-111111111111").into(),
            user_uuid: String::from("22222222-2222-2222-2222-222222222222").into(),
            name: ENC.into(),
            issuer: Some(ENC.into()),
            secret: ENC.into(),
            algorithm: "SHA1".into(),
            digits: 6,
            period: 30,
            notes: None,
            favorite: false,
            sort_order: 0,
            revision_date: chrono::NaiveDateTime::parse_from_str("2026-11-15 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap(),
            creation_date: chrono::NaiveDateTime::parse_from_str("2026-11-15 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap(),
        };
        let rotated: AuthenticatorRotationData = serde_json::from_value(json!({
            "id": entry.uuid,
            "name": "2.AAAA|AAAA|AAAC",
            "issuer": "2.AAAA|AAAA|AAAD",
            "secret": "2.AAAA|AAAA|AAAE",
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
            "favorite": false,
            "sortOrder": 0
        }))
        .unwrap();
        let updated = reencrypted_content(&entry, &rotated).unwrap();
        assert_eq!(updated.name, "2.AAAA|AAAA|AAAC");
        assert_eq!(updated.issuer.as_deref(), Some("2.AAAA|AAAA|AAAD"));
        assert_eq!(updated.secret, "2.AAAA|AAAA|AAAE");
        assert!(updated.notes.is_none());

        for value in [
            json!({"id": entry.uuid, "name": "2.AAAA|AAAA|AAAC", "secret": "2.AAAA|AAAA|AAAE"}),
            json!({"id": entry.uuid, "name": "2.AAAA|AAAA|AAAC", "issuer": "2.AAAA|AAAA|AAAD", "secret": "2.AAAA|AAAA|AAAE", "digits": 8}),
            json!({"id": entry.uuid, "name": "2.AAAA|AAAA|AAAC", "issuer": "2.AAAA|AAAA|AAAD", "secret": "2.AAAA|AAAA|AAAE", "notes": "2.AAAA|AAAA|AAAF"}),
            json!({"id": entry.uuid, "name": "GitHub", "issuer": "2.AAAA|AAAA|AAAD", "secret": "2.AAAA|AAAA|AAAE"}),
            json!({"id": entry.uuid, "name": "2.AAAA|AAAA", "issuer": "2.AAAA|AAAA|AAAD", "secret": "2.AAAA|AAAA|AAAE"}),
        ] {
            let item = serde_json::from_value(value).unwrap();
            assert!(reencrypted_content(&entry, &item).is_err());
        }
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

    const ENC: &str = "2.AAAA|AAAA|AAAA";

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
            assert_eq!(AuthenticatorEntry::find_by_user(&owner_id, &conn).await.unwrap().len(), 0);

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
                        "name": "2.AAAA|AAAA|AAAB",
                        "secret": "2.AAAA|AAAA|AAAC",
                        "issuer": "2.AAAA|AAAA|AAAD",
                        "algorithm": "SHA256",
                        "digits": 8,
                        "period": 60,
                        "notes": "2.AAAA|AAAA|AAAE",
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
            assert_eq!(second["issuer"], "2.AAAA|AAAA|AAAD");

            let list =
                get_authenticator_entries(headers(&owner_id, &conn).await, db.conn()).await.unwrap().into_inner();
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
            assert_eq!(fetched["secret"], "2.AAAA|AAAA|AAAC");
            assert!(
                get_authenticator_entry(second_id.clone(), headers(&other_id, &conn).await, db.conn()).await.is_err()
            );
            assert_eq!(
                get_authenticator_entries(headers(&other_id, &conn).await, db.conn())
                    .await
                    .unwrap()
                    .into_inner()["data"]
                    .as_array()
                    .unwrap()
                    .len(),
                0
            );

            let unchanged =
                serde_json::from_value(json!({"name": "2.AAAA|AAAA|AAAF", "secret": "2.AAAA|AAAA|AAAF"})).unwrap();
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
                "2.AAAA|AAAA|AAAC"
            );

            let updated = put_authenticator_entry(
                second_id.clone(),
                Json(
                    serde_json::from_value(json!({"name": "2.AAAA|AAAA|AAAG", "secret": "2.AAAA|AAAA|AAAH"})).unwrap(),
                ),
                headers(&owner_id, &conn).await,
                db.conn(),
                notify,
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(updated["name"], "2.AAAA|AAAA|AAAG");
            assert_eq!(updated["secret"], "2.AAAA|AAAA|AAAH");
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
            assert_eq!(AuthenticatorEntry::find_by_user(&owner_id, &conn).await.unwrap().len(), 0);
        });
    }
}
