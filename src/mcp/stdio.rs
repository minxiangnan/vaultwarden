//! stdio MCP proxy. Claude Desktop speaks stdio; this process forwards each JSON-RPC
//! message to the server's `/mcp` endpoint with the access token and writes the response
//! back using Content-Length framing. The token stays in this process. It is not logged.

use std::{io::ErrorKind, process::exit};

use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    time::{Duration, timeout},
};

pub async fn run() {
    let url = match std::env::var("MCP_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("需要环境变量 MCP_URL，例如 https://vault.example.com/mcp");
            exit(1);
        }
    };
    let token = match std::env::var("MCP_ACCESS_TOKEN") {
        Ok(token) if token.starts_with("vw_mcp_") => token,
        _ => {
            eprintln!("需要环境变量 MCP_ACCESS_TOKEN，值为扩展里显示的 vw_mcp_ 令牌");
            exit(1);
        }
    };

    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            eprintln!("无法创建 HTTP 客户端: {err}");
            exit(1);
        }
    };

    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    loop {
        let message = match read_message(&mut stdin).await {
            Ok(Some(message)) => message,
            Ok(None) => break,
            Err(err) => {
                eprintln!("读取 MCP 消息失败: {err}");
                exit(1);
            }
        };
        match forward(&client, &url, &token, &message).await {
            Ok(Some(body)) => {
                if let Err(err) = write_message(&mut stdout, &body).await {
                    eprintln!("写回 MCP 消息失败: {err}");
                    exit(1);
                }
            }
            Ok(None) => {}
            Err(err) => {
                let error = protocol_error(&err);
                if let Err(write_err) = write_message(&mut stdout, error.as_bytes()).await {
                    eprintln!("写回 MCP 错误失败: {write_err}");
                    exit(1);
                }
            }
        }
    }
}

async fn forward(client: &reqwest::Client, url: &str, token: &str, message: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let response = timeout(
        Duration::from_secs(30),
        client
            .post(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .body(message.to_vec())
            .send(),
    )
    .await
    .map_err(|_| "连接 MCP 服务超时".to_owned())?
    .map_err(|err| format!("连接 MCP 服务失败: {err}"))?;

    let status = response.status();
    if status.as_u16() == 202 || status.as_u16() == 204 {
        return Ok(None);
    }
    let bytes = response.bytes().await.map_err(|err| format!("读取 MCP 响应失败: {err}"))?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if !status.is_success() {
        return Ok(Some(bytes.to_vec()));
    }
    Ok(Some(bytes.to_vec()))
}

fn protocol_error(message: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":-32000,"message":"{}"}}}}"#, message.replace('"', "'"))
}

async fn read_message<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(None);
        }
        if !line.trim().is_empty() {
            break;
        }
    }
    if line.trim_start().starts_with('{') {
        return Ok(Some(line.trim().as_bytes().to_vec()));
    }

    let mut content_length = None;
    loop {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':')
            && name.eq_ignore_ascii_case("Content-Length")
        {
            content_length = value.trim().parse::<usize>().ok();
        }
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
    }
    let Some(len) = content_length else {
        return Err(std::io::Error::new(ErrorKind::InvalidData, "MCP frame missing Content-Length"));
    };
    if len > 1_000_000 {
        return Err(std::io::Error::new(ErrorKind::InvalidData, "MCP frame is too large"));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

async fn write_message<W: AsyncWrite + Unpin>(writer: &mut W, body: &[u8]) -> std::io::Result<()> {
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    writer.write_all(header.as_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await
}
