<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         mail-system.md
Description:  Mail subsystem documentation with OAuth2, Basic Auth, and queue architecture.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# 邮件系统

## 概述

邮件子系统负责发送通知邮件（启动/关闭通知）和日报邮件，支持 OAuth2 (Outlook) 和 Basic Auth (Gmail) 两种认证方式，并内置了持久化的指数退避重试队列。

核心实现位于 `src/mailer/`。

## 架构

```
send_email()
│
├── _send_email_raw()
│   ├── load_provider_config()
│   ├── OAuth2 / Basic Auth
│   └── SMTP 发送 HTML 邮件
│
├── 发送成功 → return True
│
└── 发送失败
    ├── MailQueue 已启动
    │   └── MailQueue.enqueue()
    │       └── 后台线程 _process_spool()
    │           ├── 检查 next_retry_at
    │           ├── _try_send() → _send_email_raw()
    │           ├── 成功 → 删除暂存文件
    │           ├── 失败 → 指数退避，更新 next_retry_at
    │           └── 超过最大重试 → 移至 dead_letter/
    │
    └── MailQueue 未启动
        └── 记录 warning，本封邮件不进入重试队列
```

## 邮件发送

### 认证方式

| 提供商 | 认证方式 | 配置 |
|--------|---------|------|
| Outlook | OAuth2 (XOAUTH2) | `client_id`, `client_secret`（存储在 `credentials.db`） |
| Gmail | Basic Auth (密码) | `sender` 作为 SMTP 用户名，`client_secret` 作为密码（存储在 `credentials.db`） |

### OAuth2 流程 (Outlook)

1. `MSOAuth2Helper` 使用 MSAL (Microsoft Authentication Library) 管理令牌
2. 首先尝试**静默获取**（从缓存中取有效令牌或刷新过期令牌）
3. 缓存未命中时需要交互式授权（仅部署时执行一次，见 [部署指南](deployment.md)）
4. 令牌缓存持久化到 `credentials.db`（`CredKey.MAIL_OAUTH2_TOKEN_CACHE`），Token 刷新后自动回写
5. SMTP 使用 `XOAUTH2` 机制认证

### 邮件格式

- **类型**：MIME multipart/alternative
- **内容**：HTML 格式
- **编码**：UTF-8
- **SMTP**：TLS (端口 587)

## 邮件队列 (MailQueue)

### 设计

当邮件发送失败且 `MailQueue` 已经启动时，`MailQueue` 提供持久化的重试机制：

1. 失败的邮件序列化为 JSON 文件，保存到 spool 目录
2. 后台线程周期扫描 spool，对到期的消息尝试重发
3. 指数退避策略避免频繁重试
4. 超过最大重试次数的消息归档到 dead_letter 目录

### 暂存消息结构 (`_SpooledMessage`)

| 字段 | 说明 |
|------|------|
| `subject` | 邮件主题 |
| `html_body` | HTML 内容 |
| `recipients` | 收件人列表 |
| `attempt` | 当前重试次数 |
| `next_retry_at` | 下次重试时间戳（ISO 8601） |
| `created_at` | 首次入队时间 |

### 指数退避

```
重试间隔 = min(base_delay × 2^attempt, max_delay)
```

每次失败后等待时间翻倍，直到达到上限。

### 生命周期

```python
# 启动
start_mail_queue()    # 创建 MailQueue 单例，启动后台线程

# 运行时
send_email(...)       # 失败时自动入队
get_mail_queue()      # 获取单例实例

# 关闭
stop_mail_queue()     # 停止后台线程，flush 暂存
```

### 死信归档

当消息超过最大重试次数后，从 spool 移动到 `dead_letter/` 目录保留。这些消息不会再被自动重试，但保留 JSON 文件以便人工检查和手动重发。

## 邮件提供商配置

预定义在 `configs/mail_providers/` 下：

### outlook.toml

```toml
[mail_provider.outlook]
provider = "Outlook"

[mail_provider.outlook.smtp]
auth_methods = ["OAuth2"]
host = "smtp.office365.com"
port = 587

[mail_provider.outlook.oauth2]
authority = "https://login.microsoftonline.com/common"
scopes = ["https://outlook.office.com/SMTP.Send"]
```

### gmail.toml

```toml
[mail_provider.gmail]
provider = "Gmail"

[mail_provider.gmail.smtp]
auth_methods = ["password"]
host = "smtp.gmail.com"
port = 587
```

## 使用场景

| 场景 | 触发方 |
|------|--------|
| 启动通知 | `main.py` — 服务启动时 |
| 关闭通知 | `main.py` — 收到 SIGINT/SIGTERM 时 |
| 日报邮件 | `daily_report.py` — 日报生成完成后 |

## 多用户收件人

当 U-A-P 子系统启用后，收件人根据事件类型和用户角色自动分发。例如，日报邮件会发送给所有 Owner、Administrator 和 Watcher 角色的用户邮箱。

当用户数据库不可用或无匹配角色时，收件人列表为空，邮件将无法发送。

详见 [认证与授权](auth.md)。

## 配置

在 `suricata-llm-agent.toml` 的 `[mail]` 部分配置：

```toml
[mail]
enable_notification = true
provider = "outlook"
# client_id 和 client_secret 已迁移至 secrets.toml → credentials.db
# OAuth2 token cache 存储在 credentials.db，无需文件配置
sender = "sender@outlook.com"
```

设置 `enable_notification = false` 会禁用启动/关闭通知和日报邮件发送；日报 HTML 生成本身仍由 `daily_report.enabled` 控制。
