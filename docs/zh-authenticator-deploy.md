# 部署带验证器同步的 Vaultwarden

这个分支在上游 Vaultwarden 上增加了验证器条目接口，以及多设备同步所需的 SignalR `/notifications/hub/negotiate`。请使用本仓库的镜像或本仓库编译的二进制，不要用 Docker Hub 上的 `vaultwarden/server` 原版代替，否则浏览器扩展里没有「验证器」标签，第二台设备也收不到推送。

## 用 Docker Compose

仓库根目录的 `docker-compose.yml` 会按当前源码构建镜像，数据放在 `./vw-data`。

```bash
# 生成一个管理员口令。明文也可以启动，但日志会提示它不安全。
# 构建完成后可用容器里的 ./vaultwarden hash 生成 Argon2 PHC，再写回 ADMIN_TOKEN。
export ADMIN_TOKEN="$(openssl rand -base64 32)"
export DOMAIN="https://vault.example.com"

docker compose build
docker compose up -d
```

`DOMAIN` 必须是浏览器地址栏里的源，包含 `https://`，不要以 `/` 结尾。扩展和生产网页会用它拼接 `/api`、`/identity` 和 `/notifications`。

容器监听 80，示例映射到宿主机 8080。前面放一层 TLS 反向代理，不要把 8080 直接暴露到公网。

### 必须打开的开关

| 变量 | 示例 | 作用 |
| --- | --- | --- |
| `DOMAIN` | `https://vault.example.com` | 对外地址 |
| `SIGNUPS_ALLOWED` | `true` | 允许注册。上线后建议改成 `false` |
| `SIGNUPS_VERIFY` | `false` | 没有 SMTP 时保持 false，否则注册停在待验证 |
| `ENABLE_WEBSOCKET` | `true` | 验证器和其他保险库变更的推送 |
| `ADMIN_TOKEN` | 长随机串或 Argon2 PHC | 打开 `/admin` |
| `WEB_VAULT_ENABLED` | `true` | 提供网页保险库 |

数据卷是 `/data`。删除容器不会删除 `./vw-data`，密钥和 SQLite 数据库都在里面。

## HTTPS 与 WebSocket

扩展的生产版本只在 `https://` 上连接 `/notifications/hub`。反代必须把这个路径升级为 WebSocket，读超时要够长。

### Caddy

```caddy
vault.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

### Nginx

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

只在本机试用时，可以用受信任的证书把 `https://127.0.0.1` 反代到容器。自签证书要在系统里信任，否则扩展和 Chrome 会拒绝。明文 `http://127.0.0.1` 可以打开 API，但生产扩展不会在上面建立推送。

## 不用 Docker 的 Linux x86_64 二进制

发布页附有 `vaultwarden-linux-x86_64`。它启用了 `sqlite` 特性。

```bash
chmod +x vaultwarden-linux-x86_64
mkdir -p /var/lib/vaultwarden
export DATA_FOLDER=/var/lib/vaultwarden
export DOMAIN=https://vault.example.com
export SIGNUPS_ALLOWED=true
export SIGNUPS_VERIFY=false
export ENABLE_WEBSOCKET=true
export ADMIN_TOKEN='请换成你自己的口令'
export WEB_VAULT_ENABLED=true
export ROCKET_ADDRESS=127.0.0.1
export ROCKET_PORT=8080
./vaultwarden-linux-x86_64
```

二进制不包含网页保险库。`WEB_VAULT_ENABLED=true` 时需要旁边有 `web-vault/` 目录，或者把 `WEB_VAULT_FOLDER` 指到 Bitwarden 网页构建结果。只使用浏览器扩展时，可以把 `WEB_VAULT_ENABLED` 设为 `false`。

从源码重新编译：

```bash
cargo build --release --features sqlite
# 产物：target/release/vaultwarden
```

## 和扩展配合

1. 按上面的方式让服务通过 HTTPS 可访问。
2. 安装 clients 仓库 `release/zh-authenticator` 发布页里的扩展 zip。安装步骤见该仓库的 `README-zh-authenticator.md`。
3. 扩展里把服务器 URL 设成同一个 `DOMAIN`，注册并登录。
4. 弹出窗口出现「验证器」。添加一条验证码后，另一台登录同一账户的浏览器应在不刷新的情况下看到它。

管理页面是 `https://vault.example.com/admin`。
