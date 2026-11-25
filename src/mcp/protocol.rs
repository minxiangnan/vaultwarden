//! JSON-RPC for MCP tool calls. Transport (HTTP or stdio) is elsewhere.
//! Tool failures are returned as a successful JSON-RPC result with `isError: true`,
//! which is what MCP clients show to the model.

use serde_json::{Value, json};

pub const PROTOCOL_VERSION: &str = "2025-03-26";
const SUPPORTED: &[&str] = &["2024-11-05", "2025-03-26", "2025-06-18"];

#[derive(Debug)]
pub struct RpcRequest {
    pub id: Value,
    pub method: String,
    pub params: Value,
}

#[derive(Debug)]
pub enum Parsed {
    Request(RpcRequest),
    Notification(String),
    Error {
        id: Value,
        code: i64,
        message: &'static str,
    },
}

pub fn parse(body: &Value) -> Parsed {
    let Some(object) = body.as_object() else {
        return Parsed::Error {
            id: Value::Null,
            code: -32600,
            message: "请求必须是 JSON 对象",
        };
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Parsed::Error {
            id: object.get("id").cloned().unwrap_or(Value::Null),
            code: -32600,
            message: "只接受 JSON-RPC 2.0",
        };
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Parsed::Error {
            id: object.get("id").cloned().unwrap_or(Value::Null),
            code: -32600,
            message: "缺少 method",
        };
    };
    let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
    match object.get("id") {
        None => Parsed::Notification(method.to_owned()),
        Some(id) => Parsed::Request(RpcRequest {
            id: id.clone(),
            method: method.to_owned(),
            params,
        }),
    }
}

pub fn negotiate_version(params: &Value) -> Result<String, &'static str> {
    let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or(PROTOCOL_VERSION);
    if SUPPORTED.contains(&requested) {
        Ok(requested.to_owned())
    } else {
        Err("不支持的 MCP 协议版本")
    }
}

pub fn initialize_result(version: &str) -> Value {
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "vaultwarden-mcp", "version": "1.1.0" },
        "instructions": "This server returns the current TOTP only for entries the user opted in. Call list_totp_aliases, then get_totp_code with an exact alias. A successful result has code, seconds_remaining, issuer, account, and alias. If several entries match, the tool returns candidates and no code: ask the user which alias to use, do not guess. Codes expire; read seconds_remaining. Do not ask for passwords or for entries that are not listed. 只返回用户明确放行的验证码。先 list_totp_aliases，再用精确别名调用 get_totp_code。多个候选时不要猜。"
    })
}

pub fn tools() -> Value {
    json!({
        "tools": [
            {
                "name": "list_totp_aliases",
                "description": "List opted-in TOTP aliases for this token. Each item has alias, issuer, account, and host. Does not return a code. 列出可读取的别名、发行方、账户和主机，不返回验证码。",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                }
            },
            {
                "name": "get_totp_code",
                "description": "Return the current TOTP for one alias. Success fields: code, seconds_remaining, issuer, account, host, alias, match (exact or fuzzy). Matching ignores case. If the alias is not exact, issuer, account, and host are searched. If more than one entry matches, isError is true, no code is returned, and candidates lists alias, issuer, account, and host. Ask the user which alias to use. 按别名取当前验证码。多个候选时不返回验证码，只列出候选别名。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "alias": { "type": "string", "description": "Exact short alias set by the user, such as gitlab or oxylabs. 用户设置的短别名。" }
                    },
                    "required": ["alias"],
                    "additionalProperties": false
                }
            },
            {
                "name": "search_totp",
                "description": "Search opted-in entries by issuer, account, host, or alias. One match returns the same fields as get_totp_code, including the current code. Several matches return candidates and no code. 按发行方、账户、主机或别名搜索。唯一匹配才返回验证码。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Part of an issuer, account, host, or alias. 发行方、账户、主机或别名的一部分。" }
                    },
                    "required": ["query"],
                    "additionalProperties": false
                }
            }
        ]
    })
}

#[expect(clippy::needless_pass_by_value, reason = "callers build a fresh JSON value")]
pub fn tool_ok(value: Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()) }],
        "structuredContent": value,
        "isError": false
    })
}

#[expect(clippy::needless_pass_by_value, reason = "callers build a fresh JSON value")]
pub fn tool_err(message: &str, extra: Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": message }],
        "structuredContent": extra,
        "isError": true
    })
}

#[expect(clippy::needless_pass_by_value, reason = "callers build a fresh JSON value")]
pub fn rpc_result(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

pub fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

pub fn missing_arg(name: &str) -> Value {
    tool_err(&format!("缺少参数 {name}"), json!({"error": "invalid_params", "argument": name}))
}

pub fn unknown_tool(name: &str) -> Value {
    tool_err(&format!("没有名为 {name} 的工具"), json!({"error": "unknown_tool"}))
}

pub fn internal_tool_error() -> Value {
    tool_err("读取验证码失败", json!({"error": "internal"}))
}

pub fn string_arg(params: &Value, key: &str) -> Option<String> {
    params.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requests_and_notifications() {
        let request = parse(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}));
        assert!(matches!(request, Parsed::Request(_)));
        let note = parse(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        assert!(matches!(note, Parsed::Notification(_)));
        let bad = parse(&json!([]));
        assert!(matches!(
            bad,
            Parsed::Error {
                code: -32600,
                ..
            }
        ));
    }

    #[test]
    fn negotiates_supported_versions_only() {
        assert_eq!(negotiate_version(&json!({"protocolVersion":"2025-06-18"})).unwrap(), "2025-06-18");
        assert!(negotiate_version(&json!({"protocolVersion":"1999-01-01"})).is_err());
        let result = initialize_result(PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], "vaultwarden-mcp");
        assert_eq!(tools()["tools"].as_array().unwrap().len(), 3);
    }
}
