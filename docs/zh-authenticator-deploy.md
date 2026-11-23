# 部署带验证器同步和 MCP 的 Vaultwarden

这个分支在上游 Vaultwarden 上增加了验证器条目，以及一个可选的 MCP 端点。AI 客户端只能读取你在扩展里明确放行的验证码。请使用本仓库的镜像或二进制，不要用 Docker Hub 上的 `vaultwarden/server`。

## 最短启动

在仓库根目录执行。`ADMIN_TOKEN` 是 `/admin` 的口令，`DOMAIN` 必须和浏览器地址栏里的源一致，带 `https://`，末尾不要斜杠。

```bash
export ADMIN_TOKEN="$(openssl rand -base64 32)"
export DOMAIN="https://vault.example.com"
docker compose up -d --build
```

第一次注册账户时临时打开注册，注册完再关掉：

```bash
SIGNUPS_ALLOWED=true docker compose up -d
# 注册完成后
SIGNUPS_ALLOWED=false docker compose up -d
```

容器监听 8080，数据在 `./vw-data`。进程以 uid 1000 运行。前面放 HTTPS 反向代理，不要把 8080 直接暴露到公网。

本机试用可以把 `DOMAIN` 设成 `http://127.0.0.1:8080`。生产扩展的实时推送仍需要 HTTPS。

已经构建好的镜像：

```bash
docker pull ghcr.io/minxiangnan/vaultwarden:zh-authenticator
```

镜像同时有 amd64 和 arm64。标签 `zh-authenticator` 指向当前发布。

## 接上 MCP

1. 扩展里打开「设置 → MCP 访问」，点「创建令牌」。令牌只显示一次，点「复制令牌」。
2. 打开「验证器」，编辑一条验证码，打开「允许 MCP 读取」，别名填 `gitlab` 这样的短名，保存。
3. 把令牌配进 AI 客户端。服务地址是 `https://vault.example.com/mcp`。

Cursor 的 `mcp.json`：

```json
{
  "mcpServers": {
    "vaultwarden": {
      "url": "https://vault.example.com/mcp",
      "headers": {
        "Authorization": "Bearer vw_mcp_把这里换成令牌"
      }
    }
  }
}
```

Claude Desktop 如果只支持本地进程，用本仓库二进制的 stdio 代理：

```json
{
  "mcpServers": {
    "vaultwarden": {
      "command": "/绝对路径/vaultwarden",
      "args": ["mcp-stdio"],
      "env": {
        "MCP_URL": "https://vault.example.com/mcp",
        "MCP_ACCESS_TOKEN": "vw_mcp_把这里换成令牌"
      }
    }
  }
}
```

没有本地二进制时，可以用官方的远程桥：

```json
{
  "mcpServers": {
    "vaultwarden": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://vault.example.com/mcp",
        "--header",
        "Authorization: Bearer vw_mcp_把这里换成令牌"
      ]
    }
  }
}
```

三个工具：

| 工具 | 作用 |
| --- | --- |
| `list_totp_aliases` | 列出可读取的别名、发行方、账户、主机，不返回验证码 |
| `get_totp_code` | 参数 `alias`。成功时返回 `code`、`seconds_remaining`、`issuer`、`account`、`host`、`alias`、`match` |
| `search_totp` | 参数 `query`，按发行方、账户、主机或别名搜索 |

别名不区分大小写。没有精确别名时会按发行方、账户和主机模糊匹配。匹配到多条时不返回验证码，正文里列出候选别名，`structuredContent.candidates` 也有同样的列表。让模型改用精确别名再调一次，不要猜。

吊销：扩展「设置 → MCP 访问 → 吊销令牌」，或管理页 `/admin` 对应用户的 `Revoke MCP token`。吊销后旧令牌立即 401，已放行的密文会被删掉。

## 安全取舍

验证器条目的 `name`、`issuer`、`secret`、`notes` 仍然是用户密钥加密的 EncString，服务端读不了。

打开「允许 MCP 读取」之后，扩展会把这一条的 TOTP 密钥再用 MCP 令牌派生的密钥包一层，单独存起来。派生方式是 HKDF-SHA256，盐存在服务器上，令牌本身只存 SHA-256。取码时客户端带上令牌，服务器在内存里派生密钥、解密、算出当前验证码，然后丢掉明文。磁盘上没有令牌，也没有明文密钥。

代价是：拿着令牌的人，包括你配置的 AI 客户端，在令牌有效期间可以算出已放行条目的当前验证码。请求处理的那一瞬间，服务器进程能看到这些条目的密钥。没有放行的条目仍然是零知识，密码也不会通过 MCP 出去。别名是明文，用来查找。

令牌等同于这些账号的第二因素。只用 HTTPS，不要写进 git。不用了就吊销。

轮换会作废旧令牌。扩展会用新令牌重新包装还能解密的条目。包装失败的别名会提示你重新打开开关。

## 进阶

### 这个 compose 里的变量

| 变量 | 默认 | 作用 |
| --- | --- | --- |
| `DOMAIN` | `https://vault.example.com` | 浏览器里的源 |
| `ADMIN_TOKEN` | 必填 | `/admin` 口令 |
| `MCP_ENABLED` | `true` | 打开 `/mcp` 和扩展里的 MCP 设置 |
| `SIGNUPS_ALLOWED` | `false` | 是否允许注册 |
| `SIGNUPS_VERIFY` | `false` | 没有邮箱时保持 false |
| `ENABLE_WEBSOCKET` | `true` | 验证器多设备推送 |
| `WEB_VAULT_ENABLED` | `false` | 这个镜像不含网页保险库 |
| `HOST_PORT` | `8080` | 宿主机端口 |

限流：`MCP_RATELIMIT_BURST` 默认 30，用完之后每 `MCP_RATELIMIT_SECONDS`（默认 2）秒再允许一次。失败的令牌按 IP 限制。每次取码写入审计，不记录验证码本身。扩展的设置页不展示审计；管理接口是登录后的 `GET /api/mcp/audit`。

二进制默认 `MCP_ENABLED=false`。compose 默认打开，因为这个发布就是给 MCP 用的。

### HTTPS

Caddy 会处理 WebSocket。仓库里的 `docker/Caddyfile.example` 把 `vault.example.com` 转到容器。改域名后：

```bash
docker compose --profile https up -d
```

`DOMAIN` 仍写成 `https://vault.example.com`，不要写成容器内网地址。

Nginx：

```nginx
server {
    listen 443 ssl;
    server_name vault.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /notifications/hub {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
    }
}
```

### 不用 Docker

发布页的 `vaultwarden-linux-x86_64` 用 `cargo build --release --features sqlite` 编译。

```bash
chmod +x vaultwarden-linux-x86_64
mkdir -p /var/lib/vaultwarden
export DATA_FOLDER=/var/lib/vaultwarden
export DOMAIN=https://vault.example.com
export SIGNUPS_ALLOWED=false
export SIGNUPS_VERIFY=false
export ENABLE_WEBSOCKET=true
export MCP_ENABLED=true
export ADMIN_TOKEN='请换成你自己的口令'
export WEB_VAULT_ENABLED=false
export ROCKET_ADDRESS=127.0.0.1
export ROCKET_PORT=8080
./vaultwarden-linux-x86_64
```

从源码编译：

```bash
cargo build --release --features sqlite
```

### 和扩展配合

1. 服务通过 HTTPS 可访问。
2. 安装 clients 仓库 `release/zh-authenticator` 上带 MCP 改动的扩展。安装步骤见该仓库的 `README-zh-authenticator.md`。
3. 扩展里把服务器 URL 设成同一个 `DOMAIN`，注册并登录。
4. 「设置 → MCP 访问」创建令牌；「验证器」编辑条目，打开「允许 MCP 读取」并填写别名。

管理页面是 `https://vault.example.com/admin`。
