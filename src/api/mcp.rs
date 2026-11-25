//! Streamable HTTP MCP at `/mcp`. Each POST is one JSON-RPC message.
//! The server is stateless and does not issue `Mcp-Session-Id`.
//! Authentication is `Authorization: Bearer vw_mcp_...`.

use std::io::Cursor;

use rocket::{
    Request, Route,
    http::{ContentType, Status},
    request::{FromRequest, Outcome},
    response::{self, Responder, Response},
    serde::json::Json,
};
use serde_json::{Value, json};

use crate::{
    CONFIG,
    auth::ClientIp,
    db::DbConn,
    mcp::{self, OpenError, protocol},
};

pub fn routes() -> Vec<Route> {
    routes![mcp_post, mcp_get, mcp_delete]
}

struct McpHttp {
    status: Status,
    body: Option<String>,
    protocol: Option<String>,
    allow_post: bool,
}

impl<'r> Responder<'r, 'static> for McpHttp {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let mut builder = Response::build();
        builder.status(self.status);
        builder.raw_header("Cache-Control", "no-store");
        if let Some(protocol) = self.protocol {
            builder.raw_header("MCP-Protocol-Version", protocol);
        }
        if self.allow_post {
            builder.raw_header("Allow", "POST");
        }
        if let Some(body) = self.body {
            builder.header(ContentType::JSON).sized_body(Some(body.len()), Cursor::new(body));
        }
        builder.ok()
    }
}

fn disabled() -> McpHttp {
    McpHttp {
        status: Status::NotFound,
        body: Some(json!({"error": "MCP is disabled"}).to_string()),
        protocol: None,
        allow_post: false,
    }
}

#[expect(clippy::needless_pass_by_value, reason = "callers build a fresh JSON value")]
fn json_body(status: Status, value: Value, protocol: Option<String>) -> McpHttp {
    McpHttp {
        status,
        body: Some(value.to_string()),
        protocol,
        allow_post: false,
    }
}

#[get("/")]
fn mcp_get() -> McpHttp {
    if !CONFIG.mcp_enabled() {
        return disabled();
    }
    McpHttp {
        status: Status::MethodNotAllowed,
        body: Some(
            json!({"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"这个端点只接受 POST。请使用 Streamable HTTP。"}})
                .to_string(),
        ),
        protocol: None,
        allow_post: true,
    }
}

#[delete("/")]
fn mcp_delete() -> McpHttp {
    if !CONFIG.mcp_enabled() {
        return disabled();
    }
    McpHttp {
        status: Status::NoContent,
        body: None,
        protocol: None,
        allow_post: false,
    }
}

struct PresentedToken(Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for PresentedToken {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(Self(bearer(request)))
    }
}

#[post("/", format = "json", data = "<body>")]
async fn mcp_post(body: Json<Value>, presented: PresentedToken, conn: DbConn, ip: ClientIp) -> McpHttp {
    if !CONFIG.mcp_enabled() {
        return disabled();
    }
    let Some(token) = presented.0 else {
        return auth_failed(&ip, &conn, "missing", None).await;
    };
    let session = match mcp::McpSession::open(&token, &conn).await {
        Ok(session) => session,
        Err(OpenError::Revoked {
            user_uuid,
        }) => return auth_failed(&ip, &conn, "revoked", Some(user_uuid)).await,
        Err(OpenError::Invalid) => return auth_failed(&ip, &conn, "invalid", None).await,
    };
    drop(token);
    if !mcp::allow_token(&session.token_uuid) {
        return json_body(
            Status::TooManyRequests,
            json!({"jsonrpc":"2.0","id":null,"error":{"code":-32002,"message":"请求过于频繁，请稍后再试"}}),
            None,
        );
    }

    match protocol::parse(&body) {
        protocol::Parsed::Notification(method) => {
            debug!("MCP notification {method}");
            McpHttp {
                status: Status::Accepted,
                body: None,
                protocol: None,
                allow_post: false,
            }
        }
        protocol::Parsed::Error {
            id,
            code,
            message,
        } => json_body(Status::Ok, protocol::rpc_error(&id, code, message), None),
        protocol::Parsed::Request(rpc) => dispatch(rpc, &session, &ip, &conn).await,
    }
}

async fn auth_failed(ip: &ClientIp, conn: &DbConn, detail: &str, user: Option<crate::db::models::UserId>) -> McpHttp {
    if !mcp::allow_ip(&ip.ip) {
        return json_body(
            Status::TooManyRequests,
            json!({"jsonrpc":"2.0","id":null,"error":{"code":-32002,"message":"请求过于频繁，请稍后再试"}}),
            None,
        );
    }
    let ip_text = ip.ip.to_string();
    if let Some(user) = user {
        drop(mcp::audit_user(&user, "auth", false, detail, &ip_text, conn).await);
    } else {
        drop(mcp::audit_anonymous("auth", false, detail, &ip_text, conn).await);
    }
    json_body(
        Status::Unauthorized,
        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"MCP 访问令牌无效或已吊销"}}),
        None,
    )
}

async fn dispatch(rpc: protocol::RpcRequest, session: &mcp::McpSession, ip: &ClientIp, conn: &DbConn) -> McpHttp {
    let ip_text = ip.ip.to_string();
    match rpc.method.as_str() {
        "initialize" => match protocol::negotiate_version(&rpc.params) {
            Ok(version) => json_body(
                Status::Ok,
                protocol::rpc_result(&rpc.id, protocol::initialize_result(&version)),
                Some(version),
            ),
            Err(message) => json_body(Status::Ok, protocol::rpc_error(&rpc.id, -32602, message), None),
        },
        "ping" => json_body(Status::Ok, protocol::rpc_result(&rpc.id, json!({})), None),
        "tools/list" => json_body(Status::Ok, protocol::rpc_result(&rpc.id, protocol::tools()), None),
        "tools/call" => tool_call(&rpc, session, &ip_text, conn).await,
        _ => json_body(Status::Ok, protocol::rpc_error(&rpc.id, -32601, "未知的 MCP 方法"), None),
    }
}

async fn tool_call(rpc: &protocol::RpcRequest, session: &mcp::McpSession, ip: &str, conn: &DbConn) -> McpHttp {
    let name = rpc.params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = rpc.params.get("arguments").cloned().unwrap_or_else(|| json!({}));
    let outcome = match name {
        "list_totp_aliases" => mcp::list_aliases(session, ip, conn).await,
        "get_totp_code" => match protocol::string_arg(&arguments, "alias") {
            Some(alias) => mcp::get_code(session, &alias, ip, conn).await,
            None => Ok(protocol::missing_arg("alias")),
        },
        "search_totp" => match protocol::string_arg(&arguments, "query") {
            Some(query) => mcp::search(session, &query, ip, conn).await,
            None => Ok(protocol::missing_arg("query")),
        },
        _ => Ok(protocol::unknown_tool(name)),
    };
    match outcome {
        Ok(tool_result) => json_body(Status::Ok, protocol::rpc_result(&rpc.id, tool_result), None),
        Err(err) => {
            error!("MCP tool failed: {err}");
            json_body(Status::Ok, protocol::rpc_result(&rpc.id, protocol::internal_tool_error()), None)
        }
    }
}

fn bearer(request: &Request<'_>) -> Option<String> {
    let header = request.headers().get_one("Authorization")?;
    let token = header.strip_prefix("Bearer ").or_else(|| header.strip_prefix("bearer "))?.trim();
    (!token.is_empty()).then(|| token.to_owned())
}
