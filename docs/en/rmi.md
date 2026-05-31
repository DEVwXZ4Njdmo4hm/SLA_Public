<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         rmi.md
Description:  Remote Management Interface (RMI) API endpoint and protocol reference.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# Remote Management Interface (RMI)

## Overview

RMI (Remote Management Interface) is a FastAPI-based REST API that provides
runtime status queries and remote control. By default, it listens on
`0.0.0.0:8765`.

The core implementation lives in `src/rmi.py`.

Since the introduction of the U-A-P subsystem, every endpoint except `/health`,
`/version`, and `/login` requires authentication. See
[Authentication and Authorization](auth.md).

## Enable / Disable

Configure RMI in `suricata-llm-agent.toml`:

```toml
[rmi]
enabled = true
host = "0.0.0.0"
port = 8765
```

## API Endpoints

### GET /health

Health check.

**Response**:

```json
{
  "status": "ok"
}
```

---

### GET /version

Returns software version information.

**Response**:

```json
{
  "name": "Suricata Log LLM Analyzer",
  "suffix": "(Milestone 1)",
  "version": "0.2.0",
  "author": "Capri XXI (qxwzj@hotmail.com)",
  "license": "MIT License"
}
```

---

### GET /perfcfg

Returns the active performance configuration, current perf index, adaptive
tuning details, and loaded model profile names. `/perfcfgs` is a compatibility
alias.

**Response**:

```json
{
  "perf_index": 623,
  "current_config": {
    "index": 500,
    "PERF_INDEX_MIN": 0,
    "PERF_INDEX_MAX": 999,
    "OLLAMA_MODEL": "qwen3-coder-30b:q3_k_m",
    "OLLAMA_NUM_PREDICT": 320,
    "OLLAMA_TEMPERATURE": 0.2,
    "OLLAMA_TOP_P": 0.9,
    "OLLAMA_TOP_K": 40,
    "LLM_CONCURRENCY": 6,
    "BATCH_SIZE": 65,
    "POLL_INTERVAL": 17,
    "OLLAMA_CONTEXT_LENGTH": 12288
  },
  "adaptive": {
    "pressure_score": 0.38,
    "quality_factor": 0.62,
    "effective_tps": 37.2
  },
  "model_profiles": ["qwen3-coder-30b:q3_k_m"]
}
```

---

### GET /stats

Returns real-time processing statistics.

**Response**:

```json
{
  "processed_total": 12345,
  "failed_total": 12,
  "perf_index": 623,
  "pressure_score": 0.38,
  "quality_factor": 0.62,
  "effective_tps": 37.2,
  "5min_processed": 150,
  "5min_failed": 0,
  "5min_total": 150,
  "15min_processed": 420,
  "15min_failed": 1,
  "15min_total": 421,
  "60min_processed": 1580,
  "60min_failed": 3,
  "60min_total": 1583,
  "token_total": 524800,
  "token_total_prompt": 312000,
  "token_total_completion": 212800,
  "1min_prompt_tokens": 2400,
  "1min_completion_tokens": 1600,
  "1min_total_tokens": 4000,
  "5min_prompt_tokens": 12000,
  "5min_completion_tokens": 8200,
  "5min_total_tokens": 20200,
  "avg_tokens_per_log": 42.3
}
```

> For brevity, the example omits token fields for the `30min`, `1h`, `6h`, and
> `24h` windows. They are included in the real response.

**Field descriptions**:

| Field | Description |
|-------|-------------|
| `processed_total` | Total documents processed since startup |
| `failed_total` | Total failures |
| `perf_index` | Current performance index, 0 to 999 |
| `pressure_score` | Normalized system pressure, 0.0 to 1.0. Raw pressure is retained in performance-tuning logs and adaptive details |
| `quality_factor` | Current quality factor, 0.0 to 1.0 |
| `effective_tps` | Current effective token throughput in tokens/sec |
| `{N}min_processed/failed/total` | Sliding-window processing counts for 5 / 15 / 60 minutes |
| `token_total` | Total tokens since startup |
| `token_total_prompt` | Total prompt tokens since startup |
| `token_total_completion` | Total completion tokens since startup |
| `{window}_prompt_tokens` | Prompt tokens in the window: 1min / 5min / 30min / 1h / 6h / 24h |
| `{window}_completion_tokens` | Completion tokens in the corresponding window |
| `{window}_total_tokens` | Total tokens in the corresponding window |
| `avg_tokens_per_log` | Average completion tokens per log with EMA smoothing, returned when adaptive tuning data is available |

---

### POST /gen_report+{date}

Manually triggers daily report generation for the specified date. Generation
runs asynchronously in the background, and the caller receives `202 Accepted`
immediately. During generation, real-time analysis pauses automatically and
resumes after completion. If another report is already being generated, the
endpoint returns `409 Conflict`.

**Parameter**:

- `date`: date string in `YYYY-MM-DD` format

**Example**:

```bash
curl -X POST http://localhost:8765/gen_report+2026-03-20 \
  -H "Authorization: Bearer $TOKEN"
```

**Response** (202 Accepted):

```json
{
  "status": "accepted",
  "report_date": "2026-03-20",
  "detail": "Daily report generation started. Results will be delivered via email/PR."
}
```

**Response** (409 Conflict, another generation task is active):

```json
{
  "status": "busy",
  "report_date": "2026-03-20",
  "detail": "A daily report generation is already in progress."
}
```

Daily report generation runs in a background thread. Results are delivered by
email and/or PR.

## Authentication and Management Endpoints

The following endpoints are provided by the U-A-P subsystem. See
[Authentication and Authorization](auth.md) for details.

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| POST | `/login` | No auth | Username/password login; returns JWT |
| GET | `/me` | Any authenticated user | Show current user information |
| GET/POST | `/me/apikeys` | Any authenticated user | List or create the current user's API Keys |
| GET/POST | `/users` | Owner | List users and create users |
| GET/PATCH/DELETE | `/users/{id}` | Owner | User details, update, delete |
| GET/POST | `/users/{id}/apikeys` | Owner | Manage API Keys for a specific user |
| DELETE | `/apikeys/{id}` | Owner | Revoke an API Key |
| GET/PUT/DELETE | `/credentials/*` | Owner / Administrator | Manage `llm_api_key`, `git_token`, `mail_client_id`, `mail_client_secret` |

`GET /credentials` returns only manageable credential keys that are already set.
`PUT /credentials/llm_api_key` writes the new value to `credentials.db`,
synchronizes the running `config.LLM_BACKEND_AUTH_TOKEN`, and attempts to update
the active backend held by RMI. Other cached per-model backend instances are
refreshed only when recreated or after service restart.

## Streaming Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/log` | Owner / Administrator | Server-Sent Events log stream; sends keepalive after 30 idle seconds |
| GET | `/stats/stream` | Owner / Administrator | Pushes one statistics snapshot every 5 seconds |

## Executor and Fine-Tuning Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/executor/capabilities` | Any authenticated user | List registered capability names |
| POST | `/executor/execute` | Owner / Administrator | Manually submit an executor request |
| GET | `/executor/audit` | Owner / Administrator | Query recent audit records |
| GET | `/finetune/samples` | Owner / Administrator | Query fine-tuning samples, optionally filtered by `status` and `threat_level` |
| POST | `/finetune/samples/{sample_id}/label` | Owner / Administrator | Label a sample as `confirmed`, `rejected`, or `corrected` |
| POST | `/finetune/export` | Owner / Administrator | Export JSONL by label and date range |

## Architecture Design

### Background Tasks and Command Queue

`POST /gen_report+{date}` does not run daily report generation synchronously in
the FastAPI request thread. After validating the date and busy state, the
endpoint starts a daemon background thread named `gen-report-manual` that calls
`DailyReportService.generate_and_send(..., force=True)`, then immediately
returns `202 Accepted`:

```text
FastAPI / Uvicorn thread
|
|-- POST /gen_report+YYYY-MM-DD
|-- _admin_plus authentication and authorization
|-- Date parsing
|
|-- daily_report_active = true
|   `-- 409 busy
|
`-- daily_report_active = false
    |-- Start daemon thread: gen-report-manual
    |   `-- DailyReportService.generate_and_send(force=True)
    `-- 202 Accepted
```

`RemoteCommandQueue` remains as a thread-safe queue and in the main loop's
`apply_remote_commands()`, but no remote command handlers are currently
registered. Unknown commands return `unknown command`. The current manual daily
report path does not depend on this queue.

### Server Lifecycle

The RMI server runs in a daemon thread. During normal shutdown, the main thread
calls `RmiServer.stop()`. If the process exits abnormally, the daemon thread
ends with the process:

```python
main.py -> start_rmi_server() -> RmiServer
                              `-- uvicorn.Server in daemon Thread

shutdown -> rmi_server.stop()
```

## Container Port Mapping

Configure port mapping in `[networking]` in `deploy.toml`:

```toml
[networking]
port_mapping = { host_netseg = "127.0.0.1", host_port = 8765, container_port = 8765 }
```

By default, the RMI port is bound to `127.0.0.1`, allowing only local access. To
allow remote access, change it to `0.0.0.0` or a specific network segment.
