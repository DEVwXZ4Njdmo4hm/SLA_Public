<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         mail-system.md
Description:  Mail subsystem documentation with OAuth2, Basic Auth, and queue architecture.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# Mail System

## Overview

The mail subsystem sends notification emails (startup/shutdown notifications)
and daily report emails. It supports OAuth2 for Outlook and Basic Auth for Gmail
and includes a persistent retry queue with exponential backoff.

The core implementation lives in `src/mailer/`.

## Architecture

```text
send_email()
|
|-- _send_email_raw()
|   |-- load_provider_config()
|   |-- OAuth2 / Basic Auth
|   `-- Send HTML mail through SMTP
|
|-- Success -> return True
|
`-- Failure
    |-- MailQueue started
    |   `-- MailQueue.enqueue()
    |       `-- Background thread _process_spool()
    |           |-- Check next_retry_at
    |           |-- _try_send() -> _send_email_raw()
    |           |-- Success -> delete spool file
    |           |-- Failure -> exponential backoff, update next_retry_at
    |           `-- Exceeded max retries -> move to dead_letter/
    |
    `-- MailQueue not started
        `-- Log warning; this email is not queued for retry
```

## Sending Mail

### Authentication Methods

| Provider | Authentication | Configuration |
|----------|----------------|---------------|
| Outlook | OAuth2 (XOAUTH2) | `client_id`, `client_secret`, stored in `credentials.db` |
| Gmail | Basic Auth (password) | `sender` as SMTP username, `client_secret` as password, stored in `credentials.db` |

### OAuth2 Flow (Outlook)

1. `MSOAuth2Helper` uses MSAL (Microsoft Authentication Library) to manage tokens.
2. It first tries **silent acquisition**, using a valid token from cache or
   refreshing an expired token.
3. When the cache misses, interactive authorization is required. This runs only
   once during deployment; see [Deployment Guide](deployment.md).
4. The token cache is persisted to `credentials.db`
   (`CredKey.MAIL_OAUTH2_TOKEN_CACHE`) and written back automatically after
   refresh.
5. SMTP authenticates with `XOAUTH2`.

### Mail Format

- **Type**: MIME multipart/alternative
- **Content**: HTML
- **Encoding**: UTF-8
- **SMTP**: TLS on port 587

## MailQueue

### Design

When mail delivery fails and `MailQueue` has already started, `MailQueue`
provides persistent retries:

1. Failed mail is serialized as a JSON file and saved in the spool directory.
2. A background thread periodically scans the spool and retries due messages.
3. Exponential backoff avoids overly frequent retries.
4. Messages that exceed the maximum retry count are archived in `dead_letter/`.

### Spooled Message Structure (`_SpooledMessage`)

| Field | Description |
|-------|-------------|
| `subject` | Mail subject |
| `html_body` | HTML body |
| `recipients` | Recipient list |
| `attempt` | Current retry count |
| `next_retry_at` | Next retry timestamp in ISO 8601 format |
| `created_at` | First enqueue time |

### Exponential Backoff

```text
retry delay = min(base_delay x 2^attempt, max_delay)
```

The wait time doubles after each failure until it reaches the maximum delay.

### Lifecycle

```python
# Startup
start_mail_queue()    # Create MailQueue singleton and start background thread

# Runtime
send_email(...)       # Automatically queues on failure
get_mail_queue()      # Return singleton instance

# Shutdown
stop_mail_queue()     # Stop background thread and flush spool
```

### Dead-Letter Archive

When a message exceeds the maximum retry count, it is moved from the spool to
`dead_letter/`. These messages are not retried automatically, but the JSON files
are preserved for manual inspection and resend.

## Mail Provider Configuration

Provider definitions live under `configs/mail_providers/`.

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

## Use Cases

| Scenario | Trigger |
|----------|---------|
| Startup notification | `main.py` when the service starts |
| Shutdown notification | `main.py` on SIGINT/SIGTERM |
| Daily report email | `daily_report.py` after daily report generation |

## Multi-User Recipients

When the U-A-P subsystem is enabled, recipients are selected automatically by
event type and user role. For example, daily report emails are sent to all users
with Owner, Administrator, and Watcher roles.

When the user database is unavailable or no matching role exists, the recipient
list is empty and mail cannot be sent.

See [Authentication and Authorization](auth.md).

## Configuration

Configure the `[mail]` section in `suricata-llm-agent.toml`:

```toml
[mail]
enable_notification = true
provider = "outlook"
# client_id and client_secret have moved to secrets.toml -> credentials.db
# OAuth2 token cache is stored in credentials.db; no file configuration required
sender = "sender@outlook.com"
```

Setting `enable_notification = false` disables startup/shutdown notifications
and daily report email delivery. Daily report HTML generation itself is still
controlled by `daily_report.enabled`.
