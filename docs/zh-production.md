# 生产部署

这是在一台有公网域名的 VPS 上运行本仓库的步骤。镜像不带网页保险库。浏览器扩展和 Android 客户端走 API。管理页在 `/admin`。

发布镜像：

- `ghcr.io/minxiangnan/vaultwarden:v-zh-authenticator-1.2.2`
- `ghcr.io/minxiangnan/vaultwarden:zh-authenticator`（浮动标签，指向当前发布）

两个标签都是 amd64 和 arm64。GitHub Actions 只有在标签 `v-zh-authenticator-1.2.2` 被推送到仓库、并且工作流跑完之后才会把镜像推到 GHCR。发布页上的标签本身不会自动触发这次构建。

## 1. 准备

- 一台 VPS，开放 80 和 443。不要把 8080 暴露到公网。
- 一个域名，例如 `vault.example.com`，A 或 AAAA 记录指向这台机器。
- Docker Engine 和 Compose v2。
- 一个能发信的 SMTP 账号。注册是关着的，新用户靠管理页发邀请邮件。

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2
sudo usermod -aG docker "$USER"
```

重新登录，使 docker 组生效。

## 2. 取代码和配置

```bash
git clone https://github.com/minxiangnan/vaultwarden.git
cd vaultwarden
git checkout v-zh-authenticator-1.2.2
cp .env.example .env
```

编辑 `.env`：

- `DOMAIN=https://vault.example.com`，带 `https://`，末尾不要斜杠。扩展和手机都填这个地址。
- `DOMAIN_HOST=vault.example.com`，只写主机名。Caddy 用它申请证书。
- `SIGNUPS_ALLOWED=false`
- `INVITATIONS_ALLOWED=true`
- `MCP_ENABLED=true`
- `LOG_LEVEL=info`
- 填上 `SMTP_HOST`、`SMTP_FROM`、`SMTP_USERNAME`、`SMTP_PASSWORD`。587 用 `SMTP_SECURITY=starttls`，465 用 `force_tls`。

`ADMIN_TOKEN` 先留空。下一步生成 Argon2 哈希。不要把登录口令原文写进 `.env`。明文令牌能登录，但管理页会一直显示警告。

`.env` 不要提交。仓库已经忽略它。

## 3. 生成管理口令

先拉镜像。镜像还没发布时，去掉后面命令里的 `--no-deps` 以外的部分，改成在仓库里 `--build`。

```bash
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml run --rm --no-deps --entrypoint /vaultwarden vaultwarden hash
```

`vaultwarden hash` 会问两次口令，然后打印一行 `$argon2id$...`。把它写进 `.env`，并用单引号包起来，否则 `$` 会被吃掉：

```bash
ADMIN_TOKEN='$argon2id$v=19$m=65540,t=3,p=4$...'
```

你登录 `/admin` 时输入的是刚才敲的口令，不是这一行哈希。

## 4. 启动

```bash
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml ps
```

Caddy 监听 80 和 443，自动申请证书，并把 `/notifications/hub` 以 WebSocket 转发给 Vaultwarden。Vaultwarden 只在内部网络的 8080 上，不映射到宿主机。

数据在命名卷 `vw-data`。容器重启策略是 `unless-stopped`。健康检查请求 `/alive`。Docker 把 json 日志限制在每个容器 5 个 10MB 文件。服务日志级别是 `info`。不要在公网机器上改成 `debug` 或打开 `EXTENDED_LOGGING`。

第一次启动后等一两分钟，再打开 `https://vault.example.com/admin`。证书失败时先看 `docker compose -f docker-compose.prod.yml logs caddy`。常见原因是 DNS 还没指向这台机器，或者 80 端口被占用。

## 5. 第一个用户

注册是关的。管理页的邀请会记下这个邮箱，只有它能创建账户。

1. 打开 `https://vault.example.com/admin`，输入第 3 步的口令。
2. 在「SMTP 邮件」里核对主机、端口和发件人，保存后发一封测试信。
3. 打开用户页，邀请你自己的邮箱。
4. 在浏览器扩展或 Android 里把服务器设为 `https://vault.example.com`，选择创建账户，邮箱必须和邀请的一样，然后设置主密码。服务器看不到这个密码。
5. 创建完成后保持 `SIGNUPS_ALLOWED=false`。

这个镜像没有网页保险库。邮件里的链接指向网页保险库的接受邀请页，在这台服务器上打不开。用扩展或 Android 的「创建账户」，不要点那封邮件里的链接。

邀请只对这一个邮箱有效，而且只用一次。发出后请马上创建。别人如果知道这个邮箱，可以抢先创建；创建成功后这个口子就关上了。

没有 SMTP 时，管理页仍然会记下邀请，扩展和 Android 可以创建账户，但你收不到邮件。不要为了创建第一个用户把注册永久打开。

`SIGNUPS_VERIFY=true` 时，客户端还会要求再点一封验证邮件。默认是 `false`，邀请过的邮箱可以一次设好主密码。

## 6. 浏览器扩展

使用本仓库配套的扩展分支 `release/zh-authenticator`，不要用官方商店里的 Bitwarden 扩展来做 MCP 放行。

1. 扩展设置里把服务器 URL 设为 `https://vault.example.com`。
2. 用刚创建的账号登录。
3. 打开「设置 → MCP 访问」，创建令牌。令牌只显示一次，复制后立刻放进密码管理器或客户端配置。
4. 在验证器里编辑一条验证码，打开「允许 MCP 读取」，别名用短名，例如 `github`，然后保存。

没有放行的条目，MCP 读不到。

## 7. Android

官方 Bitwarden Android 可以连这台服务器的密码库。它没有本分支的 MCP 开关。

1. 安装 Bitwarden。
2. 在登录前进入服务器设置，填 `https://vault.example.com`。
3. 用邀请时设置的邮箱和主密码登录。
4. 验证器条目的放行和别名仍在浏览器扩展里操作。

## 8. MCP

端点是 `https://vault.example.com/mcp`，只接受 POST，请求头：

```http
Authorization: Bearer vw_mcp_...
Content-Type: application/json
```

工具是 `list_totp_aliases`、`get_totp_code`、`search_totp`。别名不唯一时返回候选，不返回验证码。

Cursor 的 `mcp.json`：

```json
{
  "mcpServers": {
    "vaultwarden": {
      "url": "https://vault.example.com/mcp",
      "headers": {
        "Authorization": "Bearer vw_mcp_把令牌贴在这里"
      }
    }
  }
}
```

Claude Desktop 用 stdio。令牌只放在客户端环境里：

```json
{
  "mcpServers": {
    "vaultwarden": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ghcr.io/minxiangnan/vaultwarden:v-zh-authenticator-1.2.2", "mcp-stdio"],
      "env": {
        "MCP_URL": "https://vault.example.com/mcp",
        "MCP_ACCESS_TOKEN": "vw_mcp_把令牌贴在这里"
      }
    }
  }
}
```

吊销：扩展或 `/admin` 的用户页里吊销该令牌。之后同一个令牌返回 401，提示「MCP 访问令牌无效或已吊销」。吊销会立刻作废，不需要重启。

## 9. 备份和恢复

SQLite 在线备份（服务不用停）：

```bash
chmod +x scripts/vw-backup.sh scripts/vw-restore.sh
./scripts/vw-backup.sh
```

目录里有 `db.sqlite3`（`sqlite3 .backup` 的一致性快照）和 `files.tar.gz`（附件、发送文件、`rsa_key.pem`、`config.json`）。把整个目录拷走。快照能恢复密文，解不开主密码。

恢复会停一下服务：

```bash
./scripts/vw-restore.sh backups/vw-20261124T120000Z
```

不要在服务运行时直接拷贝 `/data/db.sqlite3`。那样会拷到写了一半的库。

Postgres 或 MySQL 不要用这个脚本。分别用 `pg_dump` 和 `mysqldump`，并同样保存 `rsa_key.pem`。

## 10. 升级

```bash
./scripts/vw-backup.sh
git fetch --tags
git checkout v-zh-authenticator-1.2.2
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

浮动标签 `zh-authenticator` 会跟着新发布变。生产环境把 `.env` 里的 `VW_IMAGE_TAG` 固定成 `v-zh-authenticator-1.2.2`，升级时再改。

## 11. 可选的 Postgres 或 MySQL

GHCR 上的镜像只编译了 SQLite。数据库变体要在这台机器上按功能重新构建。

Postgres：

```bash
# .env 里设置 POSTGRES_PASSWORD
VW_FEATURES=sqlite,postgresql docker compose \
  -f docker-compose.prod.yml -f docker-compose.postgres.yml up -d --build
```

MySQL：

```bash
# .env 里设置 MYSQL_PASSWORD
VW_FEATURES=sqlite,mysql docker compose \
  -f docker-compose.prod.yml -f docker-compose.mysql.yml up -d --build
```

`DATABASE_URL` 必须是 `postgresql://` 或 `mysql://`。已经有 SQLite 数据时，换数据库不会自动迁移。

## 12. 这个版本的安全边界

- `/mcp` 没有 Bearer `vw_mcp_...` 时返回 401。无效令牌和已吊销令牌用同一句话，避免告诉对方令牌曾经存在。
- 服务器只存令牌的 SHA-256 和盐。明文令牌不落库。验证码密钥用该令牌做 HKDF-SHA256，再 AES-256-GCM 密封。吊销后服务器解不开这些副本。
- 用户保险库里的原始密文仍然只用主密码的密钥，MCP 副本是额外的一份，而且只有你在扩展里放行的条目才会写入。
- 有效令牌按令牌限速，默认 30 次、每 2 秒补充。失败认证按 IP 限速，同样是 30 次突发、每 2 秒 1 次，超过返回 429。令牌是高熵随机串，这个限制挡住的是灌请求，不是可猜测的短密码。
- 审计只记动作、别名和 `missing` / `invalid` / `revoked` / `decrypt` 这种原因。不记令牌，不记六位验证码。
- CORS 只允许你的 `DOMAIN`、`file://` 和桌面客户端的源。没有 `*`。MCP 用 Authorization 头，不靠 Cookie。
- Caddy 把真实客户端地址放进 `X-Real-IP`。Vaultwarden 只信任本机和私网代理，也就是前面的 Caddy。
- 日志级别保持 `info`。Docker 按 10MB × 5 个文件轮转。

## 13. 排错

| 现象 | 处理 |
| --- | --- |
| Caddy 拿不到证书 | 确认 `DOMAIN_HOST` 的 DNS 指向本机，80 端口从公网能访问 |
| `/admin` 提示令牌是明文 | `.env` 里的 `ADMIN_TOKEN` 不是 `$argon2id$` 开头。重新 `vaultwarden hash` |
| 邀请没有邮件 | 在管理页发测试信，核对 `SMTP_SECURITY` 和端口 |
| 扩展登录失败 | `DOMAIN` 必须和扩展里的服务器 URL 完全一致 |
| 手机没有实时同步 | 确认走的是 `https://域名`，而不是 IP 或 8080 |
| MCP 401 | 令牌被吊销，或客户端还在用旧令牌。重新创建 |
| MCP 429 | 短时间请求太多。等几秒，或调大 `MCP_RATELIMIT_BURST` |
