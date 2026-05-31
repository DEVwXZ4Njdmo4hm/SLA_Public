<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         auth.md
Description:  Authentication and authorization (U-A-P) reference with role model and endpoints.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# Authentication and Authorization (U-A-P)

## Overview

U-A-P (User-Actor-Permission) is the built-in authentication and authorization
subsystem. It provides access control for RMI endpoints and supports
role-based multi-user mail delivery. The system supports both JWT tokens for
interactive login and API Keys for programmatic access.

The core implementation lives in `src/auth/`.

## Role Model

The system defines four roles, ordered from highest to lowest privilege:

| Role | Description | Quantity limit |
|------|-------------|----------------|
| Owner | System owner with all permissions, including user management | Exactly 1 |
| Administrator | Operations administrator; can trigger daily reports and view log streams | Unlimited |
| Agent | Role assigned to the LLM or automation scripts; runtime Agent users are created by `LLMHandler` and revoked on instance shutdown | Unlimited |
| Watcher | Read-only role; can view statistics and receive daily reports | Unlimited |

### Endpoint Permission Matrix

| Endpoint | Owner | Administrator | Agent | Watcher | No auth |
|----------|:-----:|:-------------:|:-----:|:-------:|:-------:|
| `GET /health` | | | | | yes |
| `GET /version` | | | | | yes |
| `POST /login` | | | | | yes |
| `GET /perfcfg` / `GET /perfcfgs` | yes | yes | yes | yes | |
| `GET /stats` | yes | yes | yes | yes | |
| `POST /gen_report+{date}` | yes | yes | | | |
| `GET /log` (SSE) | yes | yes | | | |
| `GET /stats/stream` (SSE) | yes | yes | | | |
| `GET/PUT/DELETE /credentials/*` | yes | yes | | | |
| `GET /executor/capabilities` | yes | yes | yes | yes | |
| `POST /executor/execute` | yes | yes | | | |
| `GET /executor/audit` | yes | yes | | | |
| `GET/POST /finetune/*` | yes | yes | | | |
| `GET/POST /users` | yes | | | | |
| `GET/PATCH/DELETE /users/{id}` | yes | | | | |
| `*/users/{id}/apikeys` | yes | | | | |
| `DELETE /apikeys/{id}` | yes | | | | |
| `GET /me` | yes | yes | yes | yes | |
| `*/me/apikeys` | yes | yes | yes | yes | |

### Mail Recipient Permissions

Mail recipients are selected by event type and role:

| Event type | Recipient roles |
|------------|-----------------|
| `startup_shutdown` | Owner, Administrator |
| `daily_report` | Owner, Administrator, Watcher |
| `alert` | Owner, Administrator |
| `critical_alert` | Owner, Administrator, Watcher |

The system queries recipient email addresses from the U-A-P user database by
role. If the database is unavailable, mail cannot be sent.

## Authentication Methods

### JWT Tokens

JWT tokens are intended for interactive login scenarios, such as a web
management UI or curl-based debugging.

**Login flow**:

```text
1. Client POST /login { username, password }
       |
2. Server validates credentials -> issues JWT
       |
3. Client sends the token on later requests
       Authorization: Bearer <token>
```

**Token properties**:

- Signing algorithm: HS256 (HMAC-SHA256)
- Payload: `sub` (user ID), `role`, `iat`, `exp`
- Lifetime: `jwt_expire_seconds`, default 86400 seconds (24 hours)
- No external dependency; implementation does not use PyJWT

**Example**:

```bash
# Log in and obtain a token
TOKEN=$(curl -s -X POST http://localhost:8765/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}' | jq -r '.access_token')

# Use the token to access a protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8765/stats
```

### API Key

API Keys are intended for programmatic access, such as CI/CD, monitoring
scripts, and third-party integrations.

**Properties**:

- Format: `secrets.token_urlsafe(32)`, a 43-character URL-safe string
- Storage: SHA-256 hash in the database; the plaintext is returned only once at creation time
- Supports labels (`label`) and optional expiration (`expires_at`)
- Can be revoked at any time

**Usage**:

```bash
# Access with an API Key
curl -H "X-API-Key: your-api-key-here" http://localhost:8765/stats
```

## Data Storage

Users, API Keys, and service credentials are stored together in a SQLite
database (`credentials.db`).

### Database Properties

- **Mode**: WAL (Write-Ahead Logging), allowing concurrent reads
- **Thread safety**: every operation creates an independent connection and uses a global mutex
- **Foreign keys**: `ON DELETE CASCADE`, so deleting a user automatically removes API Keys
- **Unique Owner constraint**: enforced at the database layer with a `UNIQUE INDEX WHERE role = 'Owner'`

### Table Structures

**users table**:

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Autoincrement primary key |
| `username` | TEXT UNIQUE | Username |
| `email` | TEXT UNIQUE | Email address |
| `password_hash` | TEXT | bcrypt or PBKDF2 hash |
| `role` | TEXT | Owner / Administrator / Agent / Watcher |
| `created_at` | TEXT | Creation time |
| `updated_at` | TEXT | Last update time |

**api_keys table**:

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Autoincrement primary key |
| `user_id` | INTEGER FK | Associated user |
| `key_hash` | TEXT UNIQUE | SHA-256 hash |
| `label` | TEXT | Usage label |
| `created_at` | TEXT | Creation time |
| `expires_at` | TEXT | Optional expiration time |
| `revoked` | INTEGER | Whether the key is revoked |

### Password Hashing

- **Preferred**: bcrypt (`$2b$` prefix, automatic salt)
- **Fallback**: PBKDF2-HMAC-SHA256 (`pbkdf2:sha256:260000$` prefix), for environments without a C compiler
- Both formats can coexist and are detected automatically during verification

## Configuration

Configure authentication in `suricata-llm-agent.toml`:

```toml
[auth]
db_path = "auth-data/credentials.db"     # SQLite database path, relative to the config file
jwt_expire_seconds = 86400              # JWT lifetime in seconds
# jwt_secret is stored in credentials.db and written by the deployment script.
# Owner credentials are written directly to credentials.db during deployment and do not appear here.
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `db_path` | string | `""` | SQLite credential database path, including subdirectories for volume mounting; the template uses `"auth-data/credentials.db"` |
| `jwt_secret` | string | - | JWT signing secret, stored in `credentials.db` |
| `jwt_expire_seconds` | int | `86400` | JWT token lifetime, minimum 60 seconds |

### Credential Storage

All service credentials (ES, JWT, Git, LLM, Mail) are stored in the
`credentials` table in `credentials.db` and written by the deployment script.
They are loaded automatically at startup, with no environment variables or
Podman secrets required.

> **Note**: Owner credentials are not passed through environment variables. The
> Owner user is written directly to `credentials.db` by the deployment script.

### Secret Management

Manage sensitive values in `secrets.toml`:

```toml
[auth]
jwt_secret = { "value" = "your-jwt-secret" }

[auth.owner]
username = "admin"
password = "strong-production-password"
email = "admin@yourcompany.com"
```

`jwt_secret` and other service credentials are written to `credentials.db`
during deployment, so they do not appear in plaintext in service files or
environment variables. `[auth.owner]` is read only by the deployment script to
initialize the Owner user in the database, and **does not** appear in the
container environment or Quadlet service file.

## Owner Bootstrap

The Owner user is created during **deployment**, not during application startup:

```text
Deployment script:
1. _provision_auth_db() reads [auth.owner] credentials from secrets.toml
       |
2. Checks whether credentials.db already exists in db_host_dir on the host
       |
       |-- [exists] -> copy to the work directory and preserve existing Owner / users / API Keys
       `-- [missing] -> create a new database in the work directory
                         |-- UserDB initializes the full schema
                         `-- Write Owner + bcrypt password hash when Owner is missing
       |
3. Upsert JWT, ES, Git, LLM, Mail, and other service credentials
       |
4. OAuth2 steps may also write into the work-directory credentials.db
       |
5. _deploy_auth_db() writes the work-directory credentials.db back to the host persistent directory
       |
6. Quadlet bind mount maps the host directory into the container
       |
7. Application startup reads the existing database directly, with no additional bootstrap
```

This mechanism ensures that:

- The Owner password appears in plaintext **only** in `secrets.toml`.
- The database is not overwritten on redeployment; it is created only on first deployment.
- The application itself does not need to hold any Owner credentials.

## RMI API Endpoints

The following endpoints are introduced by the U-A-P system. Detailed request and
response formats are shown below.

### POST /login

Logs a user in and returns a JWT token.

**Request**:

```json
{
  "username": "admin",
  "password": "your-password"
}
```

**Response**:

```json
{
  "access_token": "eyJ...",
  "token_type": "bearer"
}
```

---

### GET /log (SSE)

Streams application logs in real time through Server-Sent Events. Requires
Administrator or higher.

**Response format**: `text/event-stream`

```text
data: 2026-03-22 10:00:01 [INFO] Processing batch 42...

data: 2026-03-22 10:00:03 [INFO] Batch 42 completed (15 docs)

: keepalive
```

- Each log entry is pushed with a `data: ` prefix.
- A `: keepalive` heartbeat is sent after 30 idle seconds.
- `LogBroadcaster` asynchronously fans out messages and supports multiple concurrent subscribers.
- Slow consumers are dropped when their queue is full, so logging is not blocked.

---

### GET /stats/stream (SSE)

Streams real-time statistics snapshots every 5 seconds. Requires Administrator
or higher.

**Response format**: `text/event-stream`

```text
data: {"processed_total":1234,"failed_total":5,"perf_index":623,"pressure_score":0.38,"quality_factor":0.62}
```

---

### GET /users

Lists all users. Owner only.

**Response**:

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

Creates a user. Owner only.

**Request**:

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

Gets details for a specific user. Owner only.

---

### PATCH /users/{user_id}

Updates a user. Owner only. Any subset of `username`, `email`, `password`, and
`role` may be updated.

**Request**:

```json
{
  "email": "new-email@example.com",
  "role": "Administrator"
}
```

---

### DELETE /users/{user_id}

Deletes a user. Owner only. Users cannot delete themselves.

---

### POST /users/{user_id}/apikeys

Creates an API Key for a specific user. Owner only.

**Request**:

```json
{
  "label": "CI pipeline",
  "expires_at": "2027-01-01T00:00:00"
}
```

**Response**:

```json
{
  "api_key": "xxxx...xxxx",
  "key_id": 3,
  "label": "CI pipeline"
}
```

> **Note**: `api_key` is returned only once at creation time and cannot be shown
> again later.

---

### GET /users/{user_id}/apikeys

Lists all API Keys for a specific user. Owner only. Plaintext keys are not
returned.

---

### DELETE /apikeys/{key_id}

Revokes a specific API Key. Owner only.

---

### GET /me

Returns information about the currently authenticated user.

---

### GET /me/apikeys

Lists the current user's API Keys.

---

### POST /me/apikeys

Creates an API Key for the current user.

---

### GET /credentials

Lists currently configured service credential keys that can be managed through
the API. Owner / Administrator.

**Response**:

```json
[
  {"key": "llm_api_key", "has_value": true},
  {"key": "git_token", "has_value": true}
]
```

Only existing manageable credential keys are returned:
`llm_api_key`, `git_token`, `mail_client_id`, and `mail_client_secret`.
Manageable credentials that have not yet been written are not returned as
`has_value=false` placeholders. Internal credentials such as `es_user` and
`jwt_secret` are not exposed through this endpoint.

---

### PUT /credentials/{key}

Creates or updates a service credential. Owner / Administrator.

**Request**:

```json
{
  "value": "sk-new-api-key"
}
```

**Response**:

```json
{
  "status": "updated",
  "key": "llm_api_key"
}
```

Only manageable credential keys may be updated; other keys return 400. `value`
must not be an empty string.

> **Hot-update boundary**: updating `llm_api_key` synchronizes the running
> configuration and attempts to update the active LLM backend held by RMI. Other
> cached per-model backend instances are refreshed only when recreated or after
> a service restart.

---

### DELETE /credentials/{key}

Deletes a service credential. Returns 404 if the credential does not exist.
Owner / Administrator.

**Response**:

```json
{
  "status": "deleted",
  "key": "llm_api_key"
}
```

## Module Structure

```text
src/auth/
├── __init__.py       # Module exports
├── models.py         # Role, User/APIKeyRecord, CredKey, MAIL_PERMISSION_MAP
├── passwords.py      # hash_password(), verify_password()
├── tokens.py         # JWT signing/verification, API Key generation/hashing
├── database.py       # UserDB SQLite CRUD
├── dependencies.py   # FastAPI Depends() injection
├── bootstrap.py      # Agent identity bootstrap; Owner bootstrap helpers
└── log_broadcast.py  # LogBroadcaster + BroadcastLogHandler

src/mailer/
└── recipients.py     # Role-based multi-user recipient resolution
```

## Container Deployment

In containerized deployment, the authentication database is stored in a
persistent host directory and mounted through Quadlet:

```text
# deploy.toml
[auth]
db_host_dir = "/opt/suricata-llm-agent"

# Generated Quadlet service file:
Volume=/opt/suricata-llm-agent:/app/auth-data:Z
```

The deployment script automatically:

1. Creates the host directory, such as `/opt/suricata-llm-agent/`.
2. Generates or updates `credentials.db` in the deployment work directory.
3. Writes the first Owner user from `secrets.toml` when the database lacks an Owner.
4. Upserts JWT, ES, Git, LLM, Mail, and other service credentials.
5. Copies the resulting `credentials.db` to the host persistent directory.

At startup, the application opens the database, initializes the U-A-P subsystem,
and logs a warning if the database has no Owner. The Owner user is created by
the deployment script; production deployment does not rely on application-startup
Owner bootstrap.

The database is mounted as a directory rather than a single file so SQLite WAL
sidecar files (`-wal` and `-shm`) are also persisted correctly.

`jwt_secret` is stored in the `credentials` table in `credentials.db`. The Owner
password is read from `secrets.toml` only during deployment to create a missing
Owner user for the first time. It should not be baked into the image or written
to Quadlet environment variables.

See [Deployment Guide](deployment.md).
