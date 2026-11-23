use std::{
    net::IpAddr,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use chrono::{NaiveDateTime, Utc};
use rmpv::Value;
use rocket::{Route, futures::StreamExt, serde::json::Json};
use rocket_ws::{Message, WebSocket};
use serde_json::json;
use tokio::sync::mpsc::Sender;

use crate::{
    CONFIG, Error,
    auth::{ClientIp, WsAccessTokenHeader},
    db::{
        DbConn,
        models::{
            AuthRequestId, AuthenticatorEntry, Cipher, CollectionId, Device, DeviceId, Folder, PushId, Send as DbSend,
            User, UserId,
        },
    },
};

use super::{
    push::push_auth_request, push::push_auth_response, push_authenticator_update, push_cipher_update,
    push_folder_update, push_logout, push_send_update, push_user_update,
};

pub static WS_USERS: LazyLock<Arc<WebSocketUsers>> = LazyLock::new(|| {
    Arc::new(WebSocketUsers {
        map: Arc::new(dashmap::DashMap::new()),
    })
});

pub static WS_ANONYMOUS_SUBSCRIPTIONS: LazyLock<Arc<AnonymousWebSocketSubscriptions>> = LazyLock::new(|| {
    Arc::new(AnonymousWebSocketSubscriptions {
        map: Arc::new(dashmap::DashMap::new()),
        connections: Arc::new(dashmap::DashMap::new()),
    })
});

/// The anonymous hub needs no authentication, so bound how much a single client can hold open.
/// One connection is needed per pending login request, several at once are only expected behind NAT.
const MAX_ANONYMOUS_CONNECTIONS_PER_IP: u32 = 25;

/// How often a Ping is sent to the client.
const WS_PING_INTERVAL: Duration = Duration::from_secs(15);

/// Close the connection if nothing, not even a Pong, was received from the client for this long.
/// Otherwise half-open connections (client gone without a FIN, e.g. behind a proxy or NAT) are kept forever.
/// Same as the default `ClientTimeoutInterval` of ASP.NET Core SignalR, which the official server uses.
const WS_CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

static NOTIFICATIONS_DISABLED: LazyLock<bool> = LazyLock::new(|| !CONFIG.enable_websocket() && !CONFIG.push_enabled());

pub fn routes() -> Vec<Route> {
    if CONFIG.enable_websocket() {
        routes![hub_negotiate, websockets_hub, anonymous_websockets_hub]
    } else {
        info!("WebSocket are disabled, realtime sync functionality will not work!");
        routes![]
    }
}

#[derive(FromForm)]
struct NegotiateRequest {
    #[field(name = "negotiateVersion")]
    negotiate_version: Option<i32>,
    access_token: Option<String>,
}

fn require_login(
    query_token: Option<String>,
    header_token: Option<String>,
) -> Result<crate::auth::LoginJwtClaims, Error> {
    let Some(token) = query_token.or(header_token) else {
        err_code!("Invalid claim", 401)
    };
    if let Ok(claims) = crate::auth::decode_login(&token) {
        Ok(claims)
    } else {
        err_code!("Invalid token", 401)
    }
}

/// SignalR's default client posts here before opening `/hub`. The id is opaque: the hub
/// still authenticates the socket with the access token and keeps every connection for the user.
#[post("/hub/negotiate?<data..>")]
fn hub_negotiate(data: NegotiateRequest, header_token: WsAccessTokenHeader) -> Result<Json<serde_json::Value>, Error> {
    require_login(data.access_token, header_token.access_token)?;
    let id = uuid::Uuid::new_v4().to_string();
    let transports = json!([{
        "transport": "WebSockets",
        "transferFormats": ["Text", "Binary"]
    }]);
    let body = if data.negotiate_version.unwrap_or(0) >= 1 {
        json!({
            "negotiateVersion": 1,
            "connectionId": id,
            "connectionToken": id,
            "availableTransports": transports,
        })
    } else {
        json!({
            "connectionId": id,
            "availableTransports": transports,
        })
    };
    Ok(Json(body))
}

#[derive(FromForm, Debug)]
struct WsAccessToken {
    access_token: Option<String>,
}

struct WSEntryMapGuard {
    users: Arc<WebSocketUsers>,
    user_uuid: UserId,
    entry_uuid: uuid::Uuid,
    addr: IpAddr,
}

impl WSEntryMapGuard {
    fn new(users: Arc<WebSocketUsers>, user_uuid: UserId, entry_uuid: uuid::Uuid, addr: IpAddr) -> Self {
        Self {
            users,
            user_uuid,
            entry_uuid,
            addr,
        }
    }
}

impl Drop for WSEntryMapGuard {
    fn drop(&mut self) {
        info!("Closing WS connection from {}", self.addr);
        if let Some(mut entry) = self.users.map.get_mut(self.user_uuid.as_ref()) {
            entry.retain(|(uuid, _)| uuid != &self.entry_uuid);
        }
    }
}

struct WSAnonymousEntryMapGuard {
    subscriptions: Arc<AnonymousWebSocketSubscriptions>,
    token: String,
    entry_uuid: uuid::Uuid,
    addr: IpAddr,
}

impl WSAnonymousEntryMapGuard {
    fn new(
        subscriptions: Arc<AnonymousWebSocketSubscriptions>,
        token: String,
        entry_uuid: uuid::Uuid,
        addr: IpAddr,
    ) -> Self {
        Self {
            subscriptions,
            token,
            entry_uuid,
            addr,
        }
    }
}

impl Drop for WSAnonymousEntryMapGuard {
    fn drop(&mut self) {
        info!("Closing WS connection from {}", self.addr);
        if let Some(mut entry) = self.subscriptions.map.get_mut(&self.token) {
            entry.retain(|(uuid, _)| uuid != &self.entry_uuid);
        }
        self.subscriptions.map.remove_if(&self.token, |_, senders| senders.is_empty());
        self.subscriptions.release(self.addr);
    }
}

#[expect(tail_expr_drop_order)]
#[get("/hub?<data..>")]
fn websockets_hub<'r>(
    ws: WebSocket,
    data: WsAccessToken,
    ip: ClientIp,
    header_token: WsAccessTokenHeader,
) -> Result<rocket_ws::Stream!['r], Error> {
    info!("Accepting Rocket WS connection from {}", ip.ip);

    let claims = require_login(data.access_token, header_token.access_token)?;

    let (mut rx, guard) = {
        let users = Arc::clone(&WS_USERS);

        // Add a channel to send messages to this client to the map
        let entry_uuid = uuid::Uuid::new_v4();
        let (tx, rx) = tokio::sync::mpsc::channel::<Message>(100);
        users.map.entry(claims.sub.to_string()).or_default().push((entry_uuid, tx));

        // Once the guard goes out of scope, the connection will have been closed and the entry will be deleted from the map
        (rx, WSEntryMapGuard::new(users, claims.sub, entry_uuid, ip.ip))
    };

    Ok({
        rocket_ws::Stream! { ws => {
            let mut ws = ws;
            let _guard = guard;
            let mut interval = tokio::time::interval(WS_PING_INTERVAL);
            let mut last_received = Instant::now();
            loop {
                tokio::select! {
                    res = ws.next() =>  {
                        match res {
                            Some(Ok(message)) => {
                                // Any message, including a Pong, means the client is still there
                                last_received = Instant::now();

                                match message {
                                    // Respond to any pings
                                    Message::Ping(ping) => yield Message::Pong(ping),
                                    Message::Pong(_) => {/* Ignored */},

                                    // We should receive an initial message with the protocol and version, and we will reply to it
                                    Message::Text(ref message) => {
                                        let msg = message.strip_suffix(RECORD_SEPARATOR as char).unwrap_or(message);

                                        if serde_json::from_str(msg).ok() == Some(INITIAL_MESSAGE) {
                                            yield Message::binary(INITIAL_RESPONSE);
                                        }
                                    }

                                    // Prevent sending anything back when a `Close` Message is received.
                                    // Just break the loop
                                    Message::Close(_) => break,

                                    // Just echo anything else the client sends
                                    _ => yield message,
                                }
                            }
                            _ => break,
                        }
                    }

                    res = rx.recv() => {
                        match res {
                            Some(res) => yield res,
                            None => break,
                        }
                    }

                    _ = interval.tick() => {
                        // The client stopped responding without closing the connection, drop it
                        if last_received.elapsed() > WS_CLIENT_TIMEOUT {
                            break;
                        }
                        yield Message::Ping(PING.to_vec());
                    }
                }
            }
        }}
    })
}

#[expect(tail_expr_drop_order)]
#[get("/anonymous-hub?<token..>")]
fn anonymous_websockets_hub<'r>(ws: WebSocket, token: String, ip: ClientIp) -> Result<rocket_ws::Stream!['r], Error> {
    info!("Accepting Anonymous Rocket WS connection from {}", ip.ip);

    let (mut rx, guard) = {
        let subscriptions = Arc::clone(&WS_ANONYMOUS_SUBSCRIPTIONS);

        if !subscriptions.try_reserve(ip.ip) {
            err_code!("Too many connections", 429)
        }

        // Add a channel to send messages to this client to the map.
        // Clients reconnect with the same token while a login request is still pending, so keep
        // every subscriber instead of replacing, otherwise the older one takes the newer one down.
        let (tx, rx) = tokio::sync::mpsc::channel::<Message>(100);
        let entry_uuid = uuid::Uuid::new_v4();
        subscriptions.map.entry(token.clone()).or_default().push((entry_uuid, tx));

        // Once the guard goes out of scope, the connection will have been closed and the entry will be deleted from the map
        (rx, WSAnonymousEntryMapGuard::new(subscriptions, token, entry_uuid, ip.ip))
    };

    Ok({
        rocket_ws::Stream! { ws => {
            let mut ws = ws;
            let _guard = guard;
            let mut interval = tokio::time::interval(WS_PING_INTERVAL);
            let mut last_received = Instant::now();
            loop {
                tokio::select! {
                    res = ws.next() =>  {
                        match res {
                            Some(Ok(message)) => {
                                // Any message, including a Pong, means the client is still there
                                last_received = Instant::now();

                                match message {
                                    // Respond to any pings
                                    Message::Ping(ping) => yield Message::Pong(ping),
                                    Message::Pong(_) => {/* Ignored */},

                                    // We should receive an initial message with the protocol and version, and we will reply to it
                                    Message::Text(ref message) => {
                                        let msg = message.strip_suffix(RECORD_SEPARATOR as char).unwrap_or(message);

                                        if serde_json::from_str(msg).ok() == Some(INITIAL_MESSAGE) {
                                            yield Message::binary(INITIAL_RESPONSE);
                                        }
                                    }

                                    // Prevent sending anything back when a `Close` Message is received.
                                    // Just break the loop
                                    Message::Close(_) => break,

                                    // Just echo anything else the client sends
                                    _ => yield message,
                                }
                            }
                            _ => break,
                        }
                    }

                    res = rx.recv() => {
                        match res {
                            Some(res) => yield res,
                            None => break,
                        }
                    }

                    _ = interval.tick() => {
                        // The client stopped responding without closing the connection, drop it
                        if last_received.elapsed() > WS_CLIENT_TIMEOUT {
                            break;
                        }
                        yield Message::Ping(PING.to_vec());
                    }
                }
            }
        }}
    })
}

//
// Websockets server
//

fn serialize(val: &Value) -> Vec<u8> {
    use rmpv::encode::write_value;

    let mut buf = Vec::new();
    write_value(&mut buf, val).expect("Error encoding MsgPack");

    // Add size bytes at the start
    // Extracted from BinaryMessageFormat.js
    let mut size: usize = buf.len();
    let mut len_buf: Vec<u8> = Vec::new();

    loop {
        #[expect(clippy::cast_possible_truncation, reason = "masked to 7 bits, fits u8")]
        let mut size_part = (size & 0x7f) as u8;
        size >>= 7;

        if size > 0 {
            size_part |= 0x80;
        }

        len_buf.push(size_part);

        if size == 0 {
            break;
        }
    }

    len_buf.append(&mut buf);
    len_buf
}

fn serialize_date(date: NaiveDateTime) -> Value {
    let seconds: i64 = date.and_utc().timestamp();
    let nanos: i64 = date.and_utc().timestamp_subsec_nanos().into();
    let timestamp = (nanos << 34) | seconds;

    let bs = timestamp.to_be_bytes();

    // -1 is Timestamp
    // https://github.com/msgpack/msgpack/blob/master/spec.md#timestamp-extension-type
    Value::Ext(-1, bs.to_vec())
}

fn convert_option<T: Into<Value>>(option: Option<T>) -> Value {
    match option {
        Some(a) => a.into(),
        None => Value::Nil,
    }
}

const RECORD_SEPARATOR: u8 = 0x1e;
const INITIAL_RESPONSE: [u8; 3] = [0x7b, 0x7d, RECORD_SEPARATOR]; // {, }, <RS>
const PING: [u8; 3] = [0x02, 0x91, 0x06];

#[derive(Deserialize, Copy, Clone, Eq, PartialEq)]
struct InitialMessage<'a> {
    protocol: &'a str,
    version: i32,
}

static INITIAL_MESSAGE: InitialMessage<'static> = InitialMessage {
    protocol: "messagepack",
    version: 1,
};

// We attach the UUID to the sender so we can differentiate them when we need to remove them from the Vec
type UserSenders = (uuid::Uuid, Sender<Message>);
#[derive(Clone)]
pub struct WebSocketUsers {
    map: Arc<dashmap::DashMap<String, Vec<UserSenders>>>,
}

impl WebSocketUsers {
    async fn send_update(&self, user_id: &UserId, data: &[u8]) {
        if let Some(user) = self.map.get(user_id.as_ref()).map(|v| v.clone()) {
            for (_, sender) in &user {
                if let Err(e) = sender.send(Message::binary(data)).await {
                    error!("Error sending WS update {e}");
                }
            }
        }
    }

    // NOTE: The last modified date needs to be updated before calling these methods
    pub async fn send_user_update(&self, ut: UpdateType, user: &User, push_uuid: Option<&PushId>, conn: &DbConn) {
        // Skip any processing if both WebSockets and Push are not active
        if *NOTIFICATIONS_DISABLED {
            return;
        }
        let data = create_update(
            vec![("UserId".into(), user.uuid.to_string().into()), ("Date".into(), serialize_date(user.updated_at))],
            ut,
            None,
        );

        if CONFIG.enable_websocket() {
            self.send_update(&user.uuid, &data).await;
        }

        if CONFIG.push_enabled() {
            push_user_update(ut, user, push_uuid, conn).await;
        }
    }

    pub async fn send_logout(&self, user: &User, acting_device: Option<&Device>, conn: &DbConn) {
        self.send_logout_with_reason(user, acting_device, None, conn).await;
    }

    /// A logout that clients may handle differently depending on `reason`
    pub async fn send_logout_with_reason(
        &self,
        user: &User,
        acting_device: Option<&Device>,
        reason: Option<LogOutReason>,
        conn: &DbConn,
    ) {
        // Skip any processing if both WebSockets and Push are not active
        if *NOTIFICATIONS_DISABLED {
            return;
        }
        let acting_device_id = acting_device.map(|d| d.uuid.clone());
        let mut payload =
            vec![("UserId".into(), user.uuid.to_string().into()), ("Date".into(), serialize_date(user.updated_at))];
        if let Some(reason) = reason {
            payload.push(("Reason".into(), (reason as i32).into()));
        }
        let data = create_update(payload, UpdateType::LogOut, acting_device_id);

        if CONFIG.enable_websocket() {
            self.send_update(&user.uuid, &data).await;
        }

        if CONFIG.push_enabled() {
            push_logout(user, acting_device, reason, conn).await;
        }
    }

    pub async fn send_folder_update(&self, ut: UpdateType, folder: &Folder, device: &Device, conn: &DbConn) {
        // Skip any processing if both WebSockets and Push are not active
        if *NOTIFICATIONS_DISABLED {
            return;
        }
        let data = create_update(
            vec![
                ("Id".into(), folder.uuid.to_string().into()),
                ("UserId".into(), folder.user_uuid.to_string().into()),
                ("RevisionDate".into(), serialize_date(folder.updated_at)),
            ],
            ut,
            Some(device.uuid.clone()),
        );

        if CONFIG.enable_websocket() {
            self.send_update(&folder.user_uuid, &data).await;
        }

        if CONFIG.push_enabled() {
            push_folder_update(ut, folder, device, conn).await;
        }
    }

    pub async fn send_authenticator_update(
        &self,
        ut: UpdateType,
        entry: &AuthenticatorEntry,
        device: &Device,
        conn: &DbConn,
    ) {
        // Skip any processing if both WebSockets and Push are not active
        if *NOTIFICATIONS_DISABLED {
            return;
        }
        // Every socket for this user, including the device that wrote the entry. ContextId is that
        // device id so the client can ignore its own echo. Upstream does not drop the actor either.
        let data = create_update(
            vec![
                ("Id".into(), entry.uuid.to_string().into()),
                ("UserId".into(), entry.user_uuid.to_string().into()),
                ("RevisionDate".into(), serialize_date(entry.revision_date)),
            ],
            ut,
            Some(device.uuid.clone()),
        );

        if CONFIG.enable_websocket() {
            self.send_update(&entry.user_uuid, &data).await;
        }

        if CONFIG.push_enabled() {
            push_authenticator_update(ut, entry, device, conn).await;
        }
    }

    pub async fn send_cipher_update(
        &self,
        ut: UpdateType,
        cipher: &Cipher,
        user_ids: &[UserId],
        device: &Device,
        collection_uuids: Option<Vec<CollectionId>>,
        conn: &DbConn,
    ) {
        // Skip any processing if both WebSockets and Push are not active
        if *NOTIFICATIONS_DISABLED {
            return;
        }
        let org_id = convert_option(cipher.organization_uuid.as_deref());
        // Depending if there are collections provided or not, we need to have different values for the following variables.
        // The user_uuid should be `null`, and the revision date should be set to now, else the clients won't sync the collection change.
        let (user_id, collection_uuids, revision_date) = if let Some(collection_uuids) = collection_uuids {
            (
                Value::Nil,
                Value::Array(collection_uuids.into_iter().map(|v| v.to_string().into()).collect::<Vec<Value>>()),
                serialize_date(Utc::now().naive_utc()),
            )
        } else {
            (convert_option(cipher.user_uuid.as_deref()), Value::Nil, serialize_date(cipher.updated_at))
        };

        let data = create_update(
            vec![
                ("Id".into(), cipher.uuid.to_string().into()),
                ("UserId".into(), user_id),
                ("OrganizationId".into(), org_id),
                ("CollectionIds".into(), collection_uuids),
                ("RevisionDate".into(), revision_date),
            ],
            ut,
            Some(device.uuid.clone()), // Acting device id (unique device/app uuid)
        );

        if CONFIG.enable_websocket() {
            for uuid in user_ids {
                self.send_update(uuid, &data).await;
            }
        }

        if CONFIG.push_enabled() && user_ids.len() == 1 {
            push_cipher_update(ut, cipher, device, conn).await;
        }
    }

    pub async fn send_send_update(
        &self,
        ut: UpdateType,
        send: &DbSend,
        user_ids: &[UserId],
        device: &Device,
        conn: &DbConn,
    ) {
        // Skip any processing if both WebSockets and Push are not active
        if *NOTIFICATIONS_DISABLED {
            return;
        }
        let user_id = convert_option(send.user_uuid.as_deref());

        let data = create_update(
            vec![
                ("Id".into(), send.uuid.to_string().into()),
                ("UserId".into(), user_id),
                ("RevisionDate".into(), serialize_date(send.revision_date)),
            ],
            ut,
            None,
        );

        if CONFIG.enable_websocket() {
            for uuid in user_ids {
                self.send_update(uuid, &data).await;
            }
        }
        if CONFIG.push_enabled() && user_ids.len() == 1 {
            push_send_update(ut, send, device, conn).await;
        }
    }

    pub async fn send_auth_request(&self, user_id: &UserId, auth_request_uuid: &str, device: &Device, conn: &DbConn) {
        // Skip any processing if both WebSockets and Push are not active
        if *NOTIFICATIONS_DISABLED {
            return;
        }
        let data = create_update(
            vec![("Id".into(), auth_request_uuid.to_owned().into()), ("UserId".into(), user_id.to_string().into())],
            UpdateType::AuthRequest,
            Some(device.uuid.clone()),
        );
        if CONFIG.enable_websocket() {
            self.send_update(user_id, &data).await;
        }

        if CONFIG.push_enabled() {
            push_auth_request(user_id, auth_request_uuid, device, conn).await;
        }
    }

    pub async fn send_auth_response(
        &self,
        user_id: &UserId,
        auth_request_id: &AuthRequestId,
        device: &Device,
        conn: &DbConn,
    ) {
        // Skip any processing if both WebSockets and Push are not active
        if *NOTIFICATIONS_DISABLED {
            return;
        }
        let data = create_update(
            vec![("Id".into(), auth_request_id.to_string().into()), ("UserId".into(), user_id.to_string().into())],
            UpdateType::AuthRequestResponse,
            Some(device.uuid.clone()),
        );
        if CONFIG.enable_websocket() {
            self.send_update(user_id, &data).await;
        }

        if CONFIG.push_enabled() {
            push_auth_response(user_id, auth_request_id, device, conn).await;
        }
    }
}

#[derive(Clone)]
pub struct AnonymousWebSocketSubscriptions {
    map: Arc<dashmap::DashMap<String, Vec<UserSenders>>>,
    connections: Arc<dashmap::DashMap<IpAddr, u32>>,
}

impl AnonymousWebSocketSubscriptions {
    /// Takes a connection slot for this address, returns false when it already reached the limit.
    fn try_reserve(&self, addr: IpAddr) -> bool {
        let mut count = self.connections.entry(addr).or_insert(0);
        if *count >= MAX_ANONYMOUS_CONNECTIONS_PER_IP {
            return false;
        }
        *count += 1;
        true
    }

    /// Releases a slot taken by `try_reserve`.
    fn release(&self, addr: IpAddr) {
        let empty = if let Some(mut count) = self.connections.get_mut(&addr) {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        // Only remove once the guard above is dropped, otherwise this deadlocks.
        if empty {
            self.connections.remove_if(&addr, |_, count| *count == 0);
        }
    }

    async fn send_update(&self, token: &str, data: &[u8]) {
        // Clone the senders so the map isn't kept locked while sending.
        let senders = self.map.get(token).map(|v| v.clone()).unwrap_or_default();
        for (_, sender) in senders {
            if let Err(e) = sender.send(Message::binary(data)).await {
                error!("Error sending WS update {e}");
            }
        }
    }

    pub async fn send_auth_response(&self, user_id: &UserId, auth_request_id: &AuthRequestId) {
        if !CONFIG.enable_websocket() {
            return;
        }
        let data = create_anonymous_update(
            vec![("Id".into(), auth_request_id.to_string().into()), ("UserId".into(), user_id.to_string().into())],
            UpdateType::AuthRequestResponse,
            user_id,
        );
        self.send_update(auth_request_id, &data).await;
    }
}

/* Message Structure
[
    1, // MessageType.Invocation
    {}, // Headers (map)
    null, // InvocationId
    "ReceiveMessage", // Target
    [ // Arguments
        {
            "ContextId": acting_device_id || Nil,
            "Type": ut as i32,
            "Payload": {}
        }
    ]
]
*/
fn create_update(payload: Vec<(Value, Value)>, ut: UpdateType, acting_device_id: Option<DeviceId>) -> Vec<u8> {
    use rmpv::Value as V;

    let value = V::Array(vec![
        1.into(),
        V::Map(vec![]),
        V::Nil,
        "ReceiveMessage".into(),
        V::Array(vec![V::Map(vec![
            ("ContextId".into(), acting_device_id.map_or(V::Nil, |v| v.to_string().into())),
            ("Type".into(), (ut as i32).into()),
            ("Payload".into(), payload.into()),
        ])]),
    ]);

    serialize(&value)
}

fn create_anonymous_update(payload: Vec<(Value, Value)>, ut: UpdateType, user_id: &UserId) -> Vec<u8> {
    use rmpv::Value as V;

    let value = V::Array(vec![
        1.into(),
        V::Map(vec![]),
        V::Nil,
        // This word is misspelled, but upstream has this too
        // https://github.com/bitwarden/server/blob/dff9f1cf538198819911cf2c20f8cda3307701c5/src/Notifications/HubHelpers.cs#L86
        // https://github.com/bitwarden/clients/blob/9612a4ac45063e372a6fbe87eb253c7cb3c588fb/libs/common/src/auth/services/anonymous-hub.service.ts#L45
        "AuthRequestResponseRecieved".into(),
        V::Array(vec![V::Map(vec![
            ("Type".into(), (ut as i32).into()),
            ("Payload".into(), payload.into()),
            ("UserId".into(), user_id.to_string().into()),
        ])]),
    ]);

    serialize(&value)
}

/// Why a logout was pushed, absent for a plain one. `KdfChange` isn't sent yet.
///
/// Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Core/Enums/PushNotificationLogOutReason.cs#L3-L7>
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum LogOutReason {
    KeyRotation = 1,
}

// https://github.com/bitwarden/server/blob/375af7c43b10d9da03525d41452f95de3f921541/src/Core/Enums/PushType.cs
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum UpdateType {
    SyncCipherUpdate = 0,
    SyncCipherCreate = 1,
    SyncLoginDelete = 2,
    SyncFolderDelete = 3,
    SyncCiphers = 4,

    SyncVault = 5,
    SyncOrgKeys = 6,
    SyncFolderCreate = 7,
    SyncFolderUpdate = 8,
    // SyncCipherDelete = 9, // Redirects to `SyncLoginDelete` on upstream
    SyncSettings = 10,

    LogOut = 11,

    SyncSendCreate = 12,
    SyncSendUpdate = 13,
    SyncSendDelete = 14,

    AuthRequest = 15,
    AuthRequestResponse = 16,

    // SyncOrganizations = 17, // Not supported
    // SyncOrganizationStatusChanged = 18, // Not supported
    // SyncOrganizationCollectionSettingChanged = 19, // Not supported

    // Notification = 20, // Not supported
    // NotificationStatus = 21, // Not supported

    // RefreshSecurityTasks = 22, // Not supported

    // Fork-only standalone authenticator entries. Official clients ignore unknown types.
    SyncAuthenticatorCreate = 30,
    SyncAuthenticatorUpdate = 31,
    SyncAuthenticatorDelete = 32,

    None = 100,
}

pub type Notify<'a> = &'a rocket::State<Arc<WebSocketUsers>>;
pub type AnonymousNotify<'a> = &'a rocket::State<Arc<AnonymousWebSocketSubscriptions>>;

#[cfg(all(test, sqlite))]
mod ws_tests {
    use std::{
        io::{Read, Write},
        net::TcpStream,
        time::Duration,
    };

    use serde_json::Value;

    const ENC: &str = "2.AAAA|AAAA|AAAA";
    const DEVICE_A: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const DEVICE_B: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

    /// Negotiate, then open two hub sockets for one user. Device A's create/update/delete must
    /// push types 30/31/32 to device B. The acting socket is not dropped: upstream leaves that
    /// to the client, which ignores a ContextId equal to its own device id.
    #[test]
    fn two_device_hubs_receive_authenticator_notifications() {
        if std::env::var_os("VAULTWARDEN_WS_AUTHENTICATOR_TEST").is_none() {
            let dir = std::env::temp_dir().join(format!("vw-ws-authn-{}", std::process::id()));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir_all(&dir).unwrap();
            let db = dir.join("db.sqlite3");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", std::thread::current().name().unwrap(), "--nocapture"])
                .env("VAULTWARDEN_WS_AUTHENTICATOR_TEST", "1")
                .env("DATA_FOLDER", &dir)
                .env("DATABASE_URL", format!("sqlite://{}", db.display()))
                .env("ENABLE_WEBSOCKET", "true")
                .env("DOMAIN", "http://127.0.0.1")
                .env("WEB_VAULT_ENABLED", "false")
                .output()
                .unwrap();
            std::fs::remove_dir_all(&dir).ok();
            assert!(
                output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(run());
    }

    async fn run() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        crate::auth::initialize_keys().await.unwrap();
        let pool = crate::db::DbPool::from_config().unwrap();
        let conn = pool.get().await.unwrap();
        let mut user =
            crate::db::models::User::new(&format!("ws-{}@example.com", uuid::Uuid::new_v4()), Some("WS".into()));
        user.save(&conn).await.unwrap();
        let mut device_a =
            crate::db::models::Device::new(DEVICE_A.to_owned().into(), user.uuid.clone(), "A".into(), 14);
        let mut device_b =
            crate::db::models::Device::new(DEVICE_B.to_owned().into(), user.uuid.clone(), "B".into(), 14);
        device_a.save(false, &conn).await.unwrap();
        device_b.save(false, &conn).await.unwrap();
        let token_a = crate::auth::LoginJwtClaims::default(
            &device_a,
            &user,
            &crate::auth::AuthMethod::Password,
            Some("web".into()),
        )
        .token();
        let token_b = crate::auth::LoginJwtClaims::default(
            &device_b,
            &user,
            &crate::auth::AuthMethod::Password,
            Some("web".into()),
        )
        .token();
        let user_id = user.uuid.to_string();
        drop(conn);

        let mut config = rocket::Config::from(rocket::Config::figment());
        config.address = "127.0.0.1".parse().unwrap();
        config.port = port;
        config.log_level = rocket::config::LogLevel::Critical;
        let rocket = rocket::custom(config)
            .mount("/api", crate::api::core::routes())
            .mount("/notifications", super::routes())
            .manage(pool)
            .manage(std::sync::Arc::clone(&super::WS_USERS))
            .manage(std::sync::Arc::clone(&super::WS_ANONYMOUS_SUBSCRIPTIONS))
            .ignite()
            .await
            .unwrap();
        let shutdown = rocket.shutdown();
        let launched = tokio::spawn(async move { rocket.launch().await });
        for _ in 0..50 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let (unauth, _) = http(port, "POST", "/notifications/hub/negotiate?negotiateVersion=1", None, None);
        assert_eq!(unauth, 401);

        let id_a = negotiate(port, &token_a);
        let id_b = negotiate(port, &token_b);
        let (ready_a_tx, ready_a_rx) = std::sync::mpsc::channel();
        let (ready_b_tx, ready_b_rx) = std::sync::mpsc::channel();
        let (notes_a_tx, notes_a_rx) = std::sync::mpsc::channel();
        let (notes_b_tx, notes_b_rx) = std::sync::mpsc::channel();
        let thread_a = std::thread::spawn({
            let token = token_a.clone();
            move || notes_a_tx.send(collect_notifications(port, &token, &id_a, &ready_a_tx)).unwrap()
        });
        let thread_b = std::thread::spawn({
            let token = token_b.clone();
            move || notes_b_tx.send(collect_notifications(port, &token, &id_b, &ready_b_tx)).unwrap()
        });
        ready_a_rx.recv_timeout(Duration::from_secs(8)).expect("device A hub");
        ready_b_rx.recv_timeout(Duration::from_secs(8)).expect("device B hub");

        let created = api(
            port,
            "POST",
            "/api/authenticator",
            &token_a,
            Some(&json!({
                "name": ENC, "secret": ENC
            })),
        );
        let entry_id = created["id"].as_str().unwrap().to_owned();
        api(
            port,
            "PUT",
            &format!("/api/authenticator/{entry_id}"),
            &token_a,
            Some(&json!({
                "name": ENC, "secret": "2.AAAA|AAAA|AAAB"
            })),
        );
        api(port, "DELETE", &format!("/api/authenticator/{entry_id}"), &token_a, None);

        let notes_a = notes_a_rx
            .recv_timeout(Duration::from_secs(8))
            .unwrap_or_else(|err| panic!("device A notifications: {err}, thread: {:?}", thread_a.join()));
        let notes_b = notes_b_rx
            .recv_timeout(Duration::from_secs(8))
            .unwrap_or_else(|err| panic!("device B notifications: {err}, thread: {:?}", thread_b.join()));
        assert_notifications(&notes_a, &entry_id, &user_id);
        assert_notifications(&notes_b, &entry_id, &user_id);

        shutdown.notify();
        drop(launched.await);
    }

    fn negotiate(port: u16, token: &str) -> String {
        let path = format!("/notifications/hub/negotiate?negotiateVersion=1&access_token={token}");
        let (status, text) = http(port, "POST", &path, None, None);
        assert_eq!(status, 200, "{text}");
        let body: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(body["negotiateVersion"], 1);
        assert_eq!(body["availableTransports"][0]["transport"], "WebSockets");
        assert_eq!(body["connectionId"], body["connectionToken"]);
        body["connectionToken"].as_str().unwrap().to_owned()
    }

    fn api(port: u16, method: &str, path: &str, token: &str, body: Option<&Value>) -> Value {
        let bytes = body.map(|value| serde_json::to_vec(value).unwrap());
        let (status, text) = http(port, method, path, Some(token), bytes.as_deref());
        assert!(matches!(status, 200 | 204), "{status} {text}");
        if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap()
        }
    }

    fn http(port: u16, method: &str, path: &str, token: Option<&str>, body: Option<&[u8]>) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(8))).unwrap();
        let auth = match token {
            Some(token) => format!("Authorization: Bearer {token}\r\n"),
            None => String::new(),
        };
        let content = match body {
            Some(body) => format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()),
            None => String::new(),
        };
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nAccept: application/json\r\n{auth}{content}\r\n"
        );
        stream.write_all(head.as_bytes()).unwrap();
        if let Some(body) = body {
            stream.write_all(body).unwrap();
        }
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf);
        let (head, raw) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
        let status = head.split_whitespace().nth(1).unwrap_or("0").parse().unwrap();
        let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            decode_chunked(raw)
        } else {
            raw.to_owned()
        };
        (status, body)
    }

    fn decode_chunked(input: &str) -> String {
        let mut out = String::new();
        let mut rest = input;
        while let Some((size, after)) = rest.split_once("\r\n") {
            let len = usize::from_str_radix(size.split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
            if len == 0 || after.len() < len {
                break;
            }
            out.push_str(&after[..len]);
            rest = after[len..].strip_prefix("\r\n").unwrap_or(&after[len..]);
        }
        out
    }

    fn assert_notifications(frames: &[Vec<u8>], entry_id: &str, user_id: &str) {
        assert_eq!(frames.len(), 3, "expected create, update, delete");
        for (frame, ut) in frames.iter().zip([30, 31, 32]) {
            let value = decode_frame(frame);
            let fields = value.as_array().unwrap();
            assert_eq!(fields[3].as_str(), Some("ReceiveMessage"));
            let message = &fields[4].as_array().unwrap()[0];
            assert_eq!(field(message, "ContextId").as_str(), Some(DEVICE_A));
            assert_eq!(field(message, "Type").as_i64(), Some(ut));
            let payload = field(message, "Payload");
            assert_eq!(field(payload, "Id").as_str(), Some(entry_id));
            assert_eq!(field(payload, "UserId").as_str(), Some(user_id));
            assert!(matches!(field(payload, "RevisionDate"), rmpv::Value::Ext(-1, _)));
        }
    }

    fn field<'a>(value: &'a rmpv::Value, key: &str) -> &'a rmpv::Value {
        value.as_map().unwrap().iter().find(|(k, _)| k.as_str() == Some(key)).map(|(_, v)| v).unwrap()
    }

    fn decode_frame(frame: &[u8]) -> rmpv::Value {
        let mut index = 0;
        while frame[index] & 0x80 != 0 {
            index += 1;
        }
        rmpv::decode::read_value(&mut &frame[index + 1..]).unwrap()
    }

    fn collect_notifications(
        port: u16,
        token: &str,
        connection_id: &str,
        ready: &std::sync::mpsc::Sender<()>,
    ) -> Vec<Vec<u8>> {
        let mut sock = connect_hub(port, token, connection_id).expect("hub upgrade");
        let mut handshake = br#"{"protocol":"messagepack","version":1}"#.to_vec();
        handshake.push(0x1e);
        write_frame(&mut sock, 0x1, &handshake).unwrap();
        ready.send(()).unwrap();

        let mut notes = Vec::new();
        while notes.len() < 3 {
            let (opcode, payload) = read_frame(&mut sock).expect("hub frame");
            match opcode {
                0x9 => write_frame(&mut sock, 0xA, &payload).unwrap(),
                0x2 if payload.as_slice() != b"{}\x1e" => notes.push(payload),
                0x8 => break,
                _ => {}
            }
        }
        notes
    }

    fn connect_hub(port: u16, token: &str, connection_id: &str) -> std::io::Result<TcpStream> {
        let mut stream = TcpStream::connect(("127.0.0.1", port))?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(8)))?;
        stream.set_write_timeout(Some(Duration::from_secs(8)))?;
        let request = format!(
            "GET /notifications/hub?id={connection_id}&access_token={token} HTTP/1.1\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             \r\n"
        );
        stream.write_all(request.as_bytes())?;
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte)?;
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if buf.len() > 8192 {
                return Err(std::io::Error::other(format!("handshake too long: {}", String::from_utf8_lossy(&buf))));
            }
        }
        let head = String::from_utf8_lossy(&buf);
        if !head.starts_with("HTTP/1.1 101") {
            return Err(std::io::Error::other(format!("upgrade failed: {head}")));
        }
        Ok(stream)
    }

    fn write_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
        let mask = [0x11u8, 0x22, 0x33, 0x44];
        let mut header = vec![0x80 | opcode];
        let len = payload.len();
        if len < 126 {
            header.push(0x80 | u8::try_from(len).unwrap());
        } else {
            header.push(0x80 | 0x7e);
            header.extend(u16::try_from(len).unwrap().to_be_bytes());
        }
        header.extend(mask);
        stream.write_all(&header)?;
        let masked: Vec<u8> = payload.iter().enumerate().map(|(i, byte)| byte ^ mask[i % 4]).collect();
        stream.write_all(&masked)
    }

    fn read_frame(stream: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
        let mut head = [0u8; 2];
        stream.read_exact(&mut head)?;
        let opcode = head[0] & 0x0f;
        let masked = head[1] & 0x80 != 0;
        let mut len = usize::from(head[1] & 0x7f);
        if len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext)?;
            len = usize::from(u16::from_be_bytes(ext));
        } else if len == 127 {
            return Err(std::io::Error::other("frame too large"));
        }
        let mask = if masked {
            let mut mask = [0u8; 4];
            stream.read_exact(&mut mask)?;
            Some(mask)
        } else {
            None
        };
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload)?;
        if let Some(mask) = mask {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
        }
        Ok((opcode, payload))
    }
}
