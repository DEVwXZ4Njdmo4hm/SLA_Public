<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         auth.md
Description:  Authentication and authorization (U-A-P) reference with role model and endpoints.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# 认证与授权 (U-A-P)

## 概述

U-A-P（User-Actor-Permission）是内置的认证与授权子系统，为 RMI 端点提供访问控制，并支持基于角色的多用户邮件接收。系统同时支持 JWT 令牌（交互式登录）和 API Key（程序化接入）两种认证方式。

核心实现位于 `src/auth/`。

## 角色模型

系统定义四个角色，权限从高到低：

| 角色 | 说明 | 数量限制 |
|------|------|---------|
| Owner | 系统所有者，拥有全部权限，包括用户管理 | 有且仅有 1 个 |
| Administrator | 运维管理员，可触发日报、查看日志流 | 不限 |
| Agent | 系统分配给 LLM 或自动化脚本的角色；运行期 Agent 用户由 `LLMHandler` 创建，实例关闭时撤销 | 不限 |
| Watcher | 只读角色，可查看统计、接收日报 | 不限 |

### 端点权限矩阵

| 端点 | Owner | Administrator | Agent | Watcher | 无需认证 |
|------|:-----:|:------------:|:-----:|:-------:|:-------:|
| `GET /health` | | | | | ✓ |
| `GET /version` | | | | | ✓ |
| `POST /login` | | | | | ✓ |
| `GET /perfcfg` / `GET /perfcfgs` | ✓ | ✓ | ✓ | ✓ | |
| `GET /stats` | ✓ | ✓ | ✓ | ✓ | |
| `POST /gen_report+{date}` | ✓ | ✓ | | | |
| `GET /log` (SSE) | ✓ | ✓ | | | |
| `GET /stats/stream` (SSE) | ✓ | ✓ | | | |
| `GET/PUT/DELETE /credentials/*` | ✓ | ✓ | | | |
| `GET /executor/capabilities` | ✓ | ✓ | ✓ | ✓ | |
| `POST /executor/execute` | ✓ | ✓ | | | |
| `GET /executor/audit` | ✓ | ✓ | | | |
| `GET/POST /finetune/*` | ✓ | ✓ | | | |
| `GET/POST /users` | ✓ | | | | |
| `GET/PATCH/DELETE /users/{id}` | ✓ | | | | |
| `*/users/{id}/apikeys` | ✓ | | | | |
| `DELETE /apikeys/{id}` | ✓ | | | | |
| `GET /me` | ✓ | ✓ | ✓ | ✓ | |
| `*/me/apikeys` | ✓ | ✓ | ✓ | ✓ | |

### 邮件接收权限

邮件接收根据事件类型和角色自动分发：

| 事件类型 | 接收角色 |
|---------|---------|
| `startup_shutdown` | Owner, Administrator |
| `daily_report` | Owner, Administrator, Watcher |
| `alert` | Owner, Administrator |
| `critical_alert` | Owner, Administrator, Watcher |

系统从 U-A-P 用户数据库中按角色查询收件人邮箱。若数据库不可用，邮件将无法发送。

## 认证方式

### JWT 令牌

适用于交互式登录场景（如 Web 管理界面、curl 调试）。

**登录流程**：

```
1. 客户端 POST /login { username, password }
       │
2. 服务端验证凭据 → 签发 JWT
       │
3. 客户端在后续请求中携带令牌
       Authorization: Bearer <token>
```

**令牌特性**：
- 签名算法：HS256（HMAC-SHA256）
- 载荷：`sub`（用户 ID）, `role`, `iat`, `exp`
- 有效期：`jwt_expire_seconds`，默认 86400 秒（24 小时）
- 无外部依赖（不使用 PyJWT，手写实现）

**示例**：

```bash
# 登录获取令牌
TOKEN=$(curl -s -X POST http://localhost:8765/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}' | jq -r '.access_token')

# 使用令牌访问受保护端点
curl -H "Authorization: Bearer $TOKEN" http://localhost:8765/stats
```

### API Key

适用于程序化接入场景（如 CI/CD、监控脚本、第三方集成）。

**特性**：
- 格式：`secrets.token_urlsafe(32)`（43 字符 URL 安全字符串）
- 存储：SHA-256 哈希存库，原文仅在创建时返回一次
- 支持标签（`label`）和过期时间（`expires_at`）
- 可随时吊销（`revoke`）

**使用方式**：

```bash
# 使用 API Key 访问
curl -H "X-API-Key: your-api-key-here" http://localhost:8765/stats
```

## 数据存储

用户、API Key 和服务凭据统一存储在 SQLite 数据库中（`credentials.db`）。

### 数据库特性

- **模式**：WAL（Write-Ahead Logging），支持并发读
- **线程安全**：每次操作创建独立连接 + 全局互斥锁
- **外键**：`ON DELETE CASCADE`，删除用户时自动清理 API Key
- **Owner 唯一约束**：数据库层面通过 `UNIQUE INDEX WHERE role = 'Owner'` 强制

### 表结构

**users 表**：

| 列 | 类型 | 说明 |
|----|------|------|
| `id` | INTEGER PK | 自增主键 |
| `username` | TEXT UNIQUE | 用户名 |
| `email` | TEXT UNIQUE | 邮箱地址 |
| `password_hash` | TEXT | bcrypt 或 PBKDF2 哈希 |
| `role` | TEXT | Owner / Administrator / Agent / Watcher |
| `created_at` | TEXT | 创建时间 |
| `updated_at` | TEXT | 更新时间 |

**api_keys 表**：

| 列 | 类型 | 说明 |
|----|------|------|
| `id` | INTEGER PK | 自增主键 |
| `user_id` | INTEGER FK | 关联用户 |
| `key_hash` | TEXT UNIQUE | SHA-256 哈希 |
| `label` | TEXT | 用途标签 |
| `created_at` | TEXT | 创建时间 |
| `expires_at` | TEXT | 过期时间（可选） |
| `revoked` | INTEGER | 是否已吊销 |

### 密码哈希

- **首选**：bcrypt（`$2b$` 前缀，自动加盐）
- **回退**：PBKDF2-HMAC-SHA256（`pbkdf2:sha256:260000$` 前缀，用于无 C 编译器的环境）
- 两种格式可共存，验证时自动识别

## 配置

在 `suricata-llm-agent.toml` 中配置：

```toml
[auth]
db_path = "auth-data/credentials.db"     # SQLite 数据库路径（相对于配置文件）
jwt_expire_seconds = 86400              # JWT 有效期（秒）
# jwt_secret 存储在 credentials.db 中，由部署脚本写入。
# Owner 凭据在部署阶段直接写入 credentials.db，不出现在此文件中。
```

### 配置参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `db_path` | string | `""` | SQLite 凭据数据库文件路径（包含子目录，便于卷挂载）；配置模板使用 `"auth-data/credentials.db"` |
| `jwt_secret` | string | — | JWT 签名密钥（存储在 credentials.db 中） |
| `jwt_expire_seconds` | int | `86400` | JWT 令牌有效期，最小 60 秒 |

### 凭据存储

所有服务凭据（ES、JWT、Git、LLM、Mail）均存储在 `credentials.db` 的 `credentials` 表中，由部署脚本写入。启动时自动加载，无需环境变量或 Podman secret。

> **注意**：Owner 凭据不通过环境变量传递。Owner 用户在部署阶段由部署脚本直接写入 `credentials.db`。

### 密钥管理

在 `secrets.toml` 中管理敏感信息：

```toml
[auth]
jwt_secret = { "value" = "your-jwt-secret" }

[auth.owner]
username = "admin"
password = "strong-production-password"
email = "admin@yourcompany.com"
```

`jwt_secret` 和其他服务凭据在部署时写入 `credentials.db`（不明文出现在服务文件或环境变量中）。`[auth.owner]` 仅被部署脚本读取，用于初始化数据库中的 Owner 用户，**不会**出现在容器环境变量或 Quadlet 服务文件中。

## Owner 引导

Owner 用户在**部署阶段**由部署脚本创建，而非应用启动时：

```
部署脚本:
1. _provision_auth_db() 读取 secrets.toml 中的 [auth.owner] 凭据
       │
2. 检查宿主机 db_host_dir 中是否已有 credentials.db
       │
       ├── [已存在] → 复制到工作目录，保留既有 Owner / 用户 / API Key
       │
       └── [不存在] → 在工作目录新建数据库
                         ├── UserDB 初始化完整 schema
                         └── 缺少 Owner 时写入 Owner + bcrypt 密码哈希
       │
3. upsert JWT、ES、Git、LLM、Mail 等服务凭据
       │
4. OAuth2 步骤可继续写入工作目录 credentials.db
       │
5. _deploy_auth_db() 将工作目录 credentials.db 写回宿主机持久目录
       │
6. Quadlet bind mount 将宿主机目录挂载到容器
       │
7. 应用启动时直接读取已有数据库，无需再次引导
```

此机制确保：
- Owner 密码**仅**在 `secrets.toml` 中出现明文，不进入容器环境变量
- 数据库在重新部署时不被覆盖（仅首次部署才创建）
- 应用本身无需持有任何 Owner 凭据

## RMI API 端点

以下端点由 U-A-P 系统引入，详细的请求/响应格式见下文。

### POST /login

用户登录，返回 JWT 令牌。

**请求**：
```json
{
  "username": "admin",
  "password": "your-password"
}
```

**响应**：
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer"
}
```

---

### GET /log (SSE)

实时日志流，通过 Server-Sent Events 推送应用日志。需要 Administrator 及以上角色。

**响应格式**：`text/event-stream`

```
data: 2026-03-22 10:00:01 [INFO] Processing batch 42...

data: 2026-03-22 10:00:03 [INFO] Batch 42 completed (15 docs)

: keepalive
```

- 每条日志以 `data: ` 前缀推送
- 空闲 30 秒后发送 `: keepalive` 心跳
- 使用 `LogBroadcaster` 异步扇出，支持多个并发订阅者
- 慢消费者的队列满时自动丢弃（不阻塞日志系统）

---

### GET /stats/stream (SSE)

实时统计快照流，每 5 秒推送一次。需要 Administrator 及以上角色。

**响应格式**：`text/event-stream`

```
data: {"processed_total":1234,"failed_total":5,"perf_index":623,"pressure_score":0.38,"quality_factor":0.62}
```

---

### GET /users

列出所有用户（Owner 专属）。

**响应**：
```json
[
  {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "Owner",
    "created_at": "2026-03-22 00:00:00",
    "updated_at": "2026-03-22 00:00:00"
  }
]
```

---

### POST /users

创建新用户（Owner 专属）。

**请求**：
```json
{
  "username": "analyst",
  "email": "analyst@example.com",
  "password": "secure-password",
  "role": "Watcher"
}
```

---

### GET /users/{user_id}

获取指定用户详情（Owner 专属）。

---

### PATCH /users/{user_id}

更新用户信息（Owner 专属）。可单独更新 `username`、`email`、`password`、`role` 中的任意字段。

**请求**：
```json
{
  "email": "new-email@example.com",
  "role": "Administrator"
}
```

---

### DELETE /users/{user_id}

删除用户（Owner 专属）。不允许删除自己。

---

### POST /users/{user_id}/apikeys

为指定用户创建 API Key（Owner 专属）。

**请求**：
```json
{
  "label": "CI pipeline",
  "expires_at": "2027-01-01T00:00:00"
}
```

**响应**：
```json
{
  "api_key": "xxxx...xxxx",
  "key_id": 3,
  "label": "CI pipeline"
}
```

> **注意**：`api_key` 仅在创建时返回一次，之后无法再次查看。

---

### GET /users/{user_id}/apikeys

列出指定用户的所有 API Key（Owner 专属）。不返回密钥原文。

---

### DELETE /apikeys/{key_id}

吊销指定 API Key（Owner 专属）。

---

### GET /me

获取当前登录用户信息（任意已认证用户）。

---

### GET /me/apikeys

列出自己的 API Key（任意已认证用户）。

---

### POST /me/apikeys

为自己创建 API Key（任意已认证用户）。

---

### GET /credentials

列出当前已设置的、可通过 API 管理的服务凭据键（Owner / Administrator）。

**响应**：
```json
[
  {"key": "llm_api_key", "has_value": true},
  {"key": "git_token", "has_value": true}
]
```

仅返回已存在且可管理的凭据键：`llm_api_key`、`git_token`、`mail_client_id`、`mail_client_secret`。尚未写入的可管理凭据不会以 `has_value=false` 占位返回；内部凭据（如 `es_user`、`jwt_secret`）不通过此端点暴露。

---

### PUT /credentials/{key}

创建或更新一条服务凭据（Owner / Administrator）。

**请求**：
```json
{
  "value": "sk-new-api-key"
}
```

**响应**：
```json
{
  "status": "updated",
  "key": "llm_api_key"
}
```

仅允许更新可管理的凭据键，其他键返回 400。`value` 不允许为空字符串。

> **热更新边界**：更新 `llm_api_key` 会同步运行中的配置，并尝试更新 RMI 持有的活动 LLM 后端；已按模型缓存的其他后端实例以重新创建或重启服务为边界。

---

### DELETE /credentials/{key}

删除一条服务凭据（Owner / Administrator）。凭据不存在时返回 404。

**响应**：
```json
{
  "status": "deleted",
  "key": "llm_api_key"
}
```

## 模块结构

```
src/auth/
├── __init__.py       # 模块导出
├── models.py         # Role、User/APIKeyRecord、CredKey、MAIL_PERMISSION_MAP
├── passwords.py      # hash_password(), verify_password()
├── tokens.py         # JWT 签发/验证，API Key 生成/哈希
├── database.py       # UserDB SQLite CRUD
├── dependencies.py   # FastAPI Depends() 注入
├── bootstrap.py      # Agent 身份引导；Owner 引导辅助函数
└── log_broadcast.py  # LogBroadcaster + BroadcastLogHandler

src/mailer/
└── recipients.py     # 基于角色的多用户收件人解析
```

## 容器部署

容器化部署时，认证数据库存储在宿主机的持久目录中，通过 Quadlet bind mount 挂载：

```
# deploy.toml
[auth]
db_host_dir = "/opt/suricata-llm-agent"

# 生成的 Quadlet 服务文件中：
Volume=/opt/suricata-llm-agent:/app/auth-data:Z
```

部署脚本会自动：
1. 创建宿主机目录（如 `/opt/suricata-llm-agent/`）
2. 在部署工作目录中生成或更新 `credentials.db`
3. 数据库缺少 Owner 时，从 `secrets.toml` 写入首个 Owner 用户
4. 将 JWT、ES、Git、LLM、Mail 等服务凭据 upsert 到数据库
5. 将生成后的 `credentials.db` 复制到宿主机持久目录

应用启动时会打开该数据库、初始化 U-A-P 子系统，并在数据库缺少 Owner 时记录警告。Owner 用户由部署脚本创建；生产部署不依赖应用启动时的 Owner 自动引导。

数据库以目录级别挂载（而非文件级别），以确保 SQLite WAL 模式的 `-wal` 和 `-shm` 伴随文件也被正确持久化。

`jwt_secret` 存储在 `credentials.db` 的 `credentials` 表中。Owner 密码只在部署阶段从 `secrets.toml` 读取，用于首次创建缺失的 Owner 用户，不应烘焙进镜像或写入 Quadlet 环境变量。

详见 [部署指南](deployment.md)。
