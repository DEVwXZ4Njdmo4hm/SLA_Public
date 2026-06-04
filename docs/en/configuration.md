<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         configuration.md
Description:  Configuration files reference for all TOML settings and their options.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# Configuration Reference

This document describes all configuration files used by Suricata LLM Agent. All
configuration files use TOML and are validated by the deployment system through
JSON Schema preflight checks.

---

## Configuration File Overview

| File | Purpose | Schema constraint |
|------|---------|-------------------|
| `suricata-llm-agent.toml` | Main configuration file | `agent-config.schema.json` |
| `llm_prompt.toml` | LLM prompt templates | `llm-prompt.schema.json` |
| `ModelProfiles.toml` | Model performance profiles | `model-profiles.schema.json` |
| `daily_report_llm_conf.toml` | Dedicated daily-report LLM parameters | Referenced by the main config |
| `suspicious_ja3.toml` | Suspicious JA3 fingerprint list | `ja3-list.schema.json` |
| `suspicious_ja3s.toml` | Suspicious JA3S fingerprint list | `ja3s-list.schema.json` |
| `secrets.toml` | Service credentials for deployment, including ES, Git, LLM, Mail, JWT | `secrets.schema.json` |
| `deploy.toml` | Deployment system configuration | `deploy-config.schema.json` |

---

## suricata-llm-agent.toml - Main Configuration

### [elasticsearch]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | `"http://elasticsearch:9200"` | Elasticsearch URL |
| `user` | string | - | ES username, stored in `credentials.db` or set in the config file |
| `password` | string | - | ES password, stored in `credentials.db` or set in the config file |
| `index_pattern` | string | `"suricata-eve-*"` | ES index pattern, with date wildcards supported |

> In containerized deployment, `user` and `password` are stored in
> `credentials.db`, written by the deployment script, and loaded automatically at
> startup. They do not need to be written in plaintext in the config file.

### [processing]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `batch_size` | integer | `50` | Maximum documents fetched per batch |
| `poll_interval` | integer | `5` | Poll interval in seconds |
| `max_retries` | integer | `3` | Maximum retries after processing failures |
| `retry_interval` | integer | `10` | Retry interval in seconds |
| `empty_runs_before_index_refresh` | integer | `50` | Threshold for refreshing the index after consecutive empty batches |

### [filter]

**Supported types/protocols** define the full set recognized by the system:

| Option | Description |
|--------|-------------|
| `supported_event_types` | Full set of Suricata event types, such as alert, dns, http, tls, ssh, smtp, ftp |
| `supported_l7_protocols` | Full set of application-layer protocols |
| `supported_l4_protocols` | Full set of transport-layer protocols: tcp, udp, icmp, icmpv6, sctp |
| `supported_l3_protocols` | Full set of network-layer protocols: ipv4, ipv6, arp |

**Actually processed subsets**. An empty array means the corresponding supported
set is used:

| Option | Default | Description |
|--------|---------|-------------|
| `allowed_event_types` | `["alert", "ssh", "rdp", "smb", "dns", "http", "tls"]` | Event types actually processed |
| `allowed_l7_protocols` | Most L7 protocols | Application-layer protocols actually processed |
| `allowed_l4_protocols` | `["tcp", "udp", "icmp", "icmpv6"]` | Transport-layer protocols actually processed |
| `allowed_l3_protocols` | `["ipv4", "ipv6"]` | Network-layer protocols actually processed |

**Alert filtering**:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `minimal_alert_severity` | integer | `2` | Minimum alert severity (1=high, 2=medium, 3=low) |

**DNS filtering**:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `dns_rcodes` | string[] | `["NXDOMAIN", "SERVFAIL", "REFUSED"]` | DNS response codes that trigger analysis |
| `dns_rrtypes` | string[] | `["ANY", "TXT"]` | DNS query types that trigger analysis |

**HTTP filtering**:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `http_status_min` | integer | `400` | Minimum HTTP status code that triggers analysis |
| `http_methods` | string[] | `["PUT", "DELETE", "TRACE", ...]` | Unusual HTTP methods that trigger analysis |

**TLS filtering**:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `tls_versions` | string[] | `["SSLv3", "TLSv1", "TLSv1.1"]` | Obsolete TLS versions that trigger analysis |
| `tls_require_sni` | boolean | `true` | Trigger analysis when SNI is missing |
| `ja3_hashes_file` | path | `"suspicious_ja3.toml"` | Suspicious JA3 fingerprint list |
| `ja3s_hashes_file` | path | `"suspicious_ja3s.toml"` | Suspicious JA3S fingerprint list |

### [llm]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `prompt_file` | path | `"llm_prompt.toml"` | LLM prompt template file |
| `memory_length` | integer | `50` | Global memory length; used by `global` / `global_rolling`, while communication-pair modes are mainly controlled by `memory_per_pair_length` |
| `memory_max_pairs` | integer | `50` | Maximum number of communication pairs |
| `memory_per_pair_length` | integer | `20` | Maximum entries per pair; templates usually set this to 50 |
| `memory_mode` | string | `"pair"` | Memory mode: `pair`, `global`, `none`, `pair_rolling`, `global_rolling`, `proto_pair`, `proto_pair_rolling` |
| `memory_lat_lru_evict_seconds` | number | `3600.0` | Last-active-time eviction threshold for top-level communication-pair buckets in `proto_pair` mode |
| `memory_maxpair_lru_evict` | integer | `0` | Number of oldest communication-pair buckets evicted when `proto_pair` reaches `memory_max_pairs`; `0` means auto-calculate |
| `memory_compact_threshold` | integer | `10` | Number of entries that triggers LLM merge summarization in rolling-compaction modes |
| `memory_compact_batch` | integer | `8` | Number of oldest entries merged per compaction; must be less than `memory_compact_threshold` |
| `memory_compact_cooldown` | number | `2.0` | Cooldown in seconds after successful `global_rolling` compaction |

Rolling-compaction modes call the `[memory_compact]` template in
`llm_prompt.toml` using the current real-time analysis model and merge the
oldest memory entries into one `[merged summary]`. `proto_pair` and
`proto_pair_rolling` use the communication pair as the first-level bucket, then
create Event_Z sub-buckets by `app_proto` or `event_type`. When either mode is
enabled, `memory_max_pairs` must be at least 3.

### [llm.backend]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `type` | string | `"ollama"` | Backend type: `"ollama"` for local inference, `"openai"` for generic OpenAI-compatible APIs including OpenAI, Azure OpenAI, and vLLM, or `"deepseek"` for the native DeepSeek API backend |
| `base_url` | string | - | Global remote API URL. `openai` requires this value. `deepseek` defaults to `https://api.deepseek.com` when omitted. When the global backend is `ollama`, `[ollama].base_url` is used; individual models can still override their backend URL through `backend_base_url` in `ModelProfiles.toml` |
| `auth_token` | string | - | Bearer token / API Key. Prefer `credentials.db` (`llm_api_key`) or environment variable `SURICATA_LLM_API_KEY`; this field is only a temporary development override |

> **API Key loading priority**, high to low: environment variable
> `SURICATA_LLM_API_KEY` -> `llm_api_key` in `credentials.db` -> config-file
> `auth_token`.

**[llm.backend.vllm_metrics]** (optional):

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `prometheus_url` | string | - | vLLM Prometheus `/metrics` endpoint URL. Meaningful only when `type = "openai"` and the backend is vLLM. Used for detailed performance collection such as running request count, throughput, and GPU cache usage |

> **Data egress warning**: when `type = "openai"` or `type = "deepseek"` and
> `base_url` points to a non-local address, the system logs a warning before
> the first call. Log data will be sent to an external service; ensure this
> complies with your data handling policies.

> **DeepSeek model names**: as of 2026-06-04, DeepSeek's current official chat
> model names are `deepseek-v4-flash` and `deepseek-v4-pro`. The legacy
> `deepseek-chat` and `deepseek-reasoner` aliases are scheduled for deprecation
> on 2026-07-24 15:59 UTC. The native DeepSeek backend sends requests to
> `/chat/completions` and maps the backend `think` flag to DeepSeek's
> `thinking.type`.

### [llm.escalation]

Escalation sends a log and communication-pair context to a higher-tier model for
deeper analysis when the primary model's initial threat assessment reaches or
exceeds a threshold.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Whether escalation is enabled |
| `threat_threshold` | string | `"中"` | Minimum threat level that triggers escalation. Values: `"无危"`, `"低"`, `"中"`, `"高"`, `"严重"` |
| `model` | string | - | Model name used for escalation; must be declared in `ModelProfiles.toml` |
| `max_tokens` | integer | `4096` | Maximum generated tokens for the escalation model |
| `context_length` | integer | `65536` | Context length for the escalation model |
| `temperature` | float | `0.2` | Generation temperature |
| `top_p` | float | `0.9` | Top-p sampling parameter |
| `top_k` | integer | `40` | Top-k sampling parameter |
| `include_raw_fields` | boolean | `true` | Whether to send raw log fields such as alert, TLS, DNS, and HTTP to the higher-tier model instead of only the initial summary |

> **Escalation and Agent mode**: escalation applies to both Pipeline and Agent
> modes. In Agent mode, escalation runs after the orchestrator completes tool
> calls such as issue creation. The escalation result replaces the initial
> analysis but does not affect already executed tool calls.
>
> **Hybrid backend support**: the escalation model can use a different backend
> from the primary model. For example, the primary model may use local Ollama
> for low latency while the escalation model uses a remote OpenAI-compatible API
> for higher quality. The system routes to the correct backend based on the
> escalation model's `backend_type` in `ModelProfiles.toml`.
>
> **Tool calling and U-A-P**: when a remote model is used for real-time analysis,
> Agent-mode tool calling still works with the local U-A-P chain and capability
> framework. The LLM backend only generates tool-call decisions; schema
> translation, policy checks, and actual execution are all performed locally.
>
> **ES field extension**: escalated documents additionally write
> `ai.escalated` (boolean), `ai.escalated_from` (keyword, initial threat level),
> and `ai.escalated_model` (keyword, escalation model name), which allows
> filtering and escalation hit-rate statistics in Kibana.

### [ollama]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `base_url` | string | `"http://host.containers.internal:11434"` | Ollama API URL |
| `timeout` | integer | `300` | Request timeout in seconds |
| `think` | boolean | `false` | Whether to allow model `<think>` reasoning blocks. When set to `false`, Ollama suppresses thinking output at the API layer, saving tokens and avoiding empty responses from reasoning models |
| `keep_alive` | string | `"5m"` | How long the model remains loaded in VRAM. `"0"` unloads immediately. In Pipeline mode, keeping the model resident allows Ollama KV cache reuse for system-prompt attention computation across requests |

### [finetune]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Whether fine-tuning training-data collection is enabled. When enabled, each pipeline LLM input/output pair is written to a SQLite database |
| `db_path` | string | `"./finetune_data.db"` | Training sample SQLite database path |
| `export_dir` | string | `"./finetune_export"` | JSONL export directory |

### [perf]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `model_profiles_file` | path | `"ModelProfiles.toml"` | Model performance profile file |
| `auto_select` | boolean | `true` | Whether adaptive performance tuning is enabled |

**[perf.indexes]**:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `analysis_value` | float | `0.5` | Analysis-value factor in (0, 1). Larger values favor analysis quality; smaller values favor processing speed |

**[perf.predict]**:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `alpha` | float | `0.6` | EMA smoothing factor |
| `window` | integer | `5` | Moving average window size |
| `window_weight` | float | `0.5` | Mixing weight between window average and EMA |

**[perf.stats]**:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `alpha` | float | `0.5` | EMA smoothing factor for token statistics |

### [gpu]

GPU hardware parameters used for local-hardware saturation detection in adaptive
tuning.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `total_vram_mb` | integer | `0` | Total GPU VRAM in MB. This was previously a global field in `ModelProfiles.toml`; `[gpu]` takes precedence |
| `fp16_tflops` | float | `0` | GPU FP16 compute capability in TFLOPS. For multi-GPU setups without NVLink, use single-card value x card count. `0` disables this signal |
| `mem_bandwidth_gbps` | float | `0` | GPU memory bandwidth in GB/s. For multi-GPU setups without NVLink, use single-card value x card count. `0` disables this signal |
| `saturation_threshold` | float | `0.9` | The fraction of theoretical maximum TPS at which the GPU is considered saturated |

### [cost]

Cost-aware scheduling parameters. These affect only paid models with
`cost_per_1k_completion > 0`; local models are unaffected.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `aware_select` | boolean | `false` | Whether cost-aware scheduling is enabled |
| `weight` | float | `0.5` | Cost constraint weight; 0 ignores cost, 1 applies maximum constraint |
| `budget_per_hour` | float | `0.0` | Hourly cost budget. The currency must match the model cost fields in `ModelProfiles.toml` |
| `saturation_threshold` | float | `0.9` | Cost saturation signal threshold as a fraction of the budget |

### [rmi]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Whether the Remote Management Interface is enabled |
| `host` | string | `"0.0.0.0"` | RMI listen address |
| `port` | integer | `8765` | RMI listen port |

### [logging]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `output_to_elasticsearch` | boolean | `true` | Whether logs are written to ES |
| `log_es_host` | string | - | Dedicated log ES URL; empty means use the primary ES |
| `log_es_user` | string | - | Log ES username; empty means use primary ES credentials |
| `log_es_password` | string | - | Log ES password |
| `log_index_prefix` | string | `"suricata-ai-agent-"` | Log index prefix |
| `log_index_pattern` | string | `"suricata-ai-agent-*"` | Log index pattern |
| `log_template_name` | string | `"suricata-ai-agent-logs"` | Log index template name |
| `log_field_limit` | integer | `65536` | ES mapping field limit |
| `log_flush_interval` | float | `1.0` | Log batch write interval in seconds |
| `log_batch_size` | integer | `200` | Log batch size |
| `stats_index_prefix` | string | `"suricata-ai-agent-stats-"` | Statistics index prefix |
| `stats_index_pattern` | string | `"suricata-ai-agent-stats-*"` | Statistics index pattern |
| `stats_template_name` | string | `"suricata-ai-agent-stats"` | Statistics index template name |

### [daily_report]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Whether daily report generation is enabled |
| `llm_config_file` | path | `"daily_report_llm_conf.toml"` | Dedicated daily-report LLM configuration |
| `fetch_size` | integer | `10000` | Daily report data fetch batch size |
| `session_gap` | integer | `1800` | Split into a new segment when adjacent events within one communication pair are separated by more than this many seconds |
| `max_segment_events` | integer | `200` | Maximum events included in one daily-report segment LLM call, preventing continuous high-frequency communication from creating very large prompts |
| `output_dir` | string | `"/app/daily_reports"` | Directory for saving daily report HTML |
| `subject_prefix` | string | `"[Suricata AI 每日流量日报]"` | Daily report email subject prefix |
| `analysis_mode` | string | `"hierarchical"` | Daily report analysis mode: `hierarchical` (segment -> pair -> global), `pair_only` (pair level only), or `flat` (one flat analysis) |
| `experiment_tag` | string | `""` | When non-empty, prepends `[EXP-{tag}]` to the email subject and inserts an experiment banner at the top of the HTML report |

> **Note**: daily report recipients are not configured here. With U-A-P enabled,
> they are selected automatically from the user database by role (Owner,
> Administrator, Watcher).

### [mail]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable_notification` | boolean | `true` | Whether email notifications are enabled |
| `provider` | string | `"outlook"` | Mail provider, `outlook` or `gmail` |
| `sender` | string | - | Sender address |

> **Note**: `client_id` and `client_secret` have moved to the `[mail]` section
> in `secrets.toml`. The deployment script writes them to `credentials.db`, and
> runtime loads them automatically from the database. The main configuration
> file should no longer contain these plaintext credentials. For non-container
> development environments, `client_id` and `client_secret` may be uncommented
> temporarily in the main config for development only.

### [auth]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `db_path` | path | `""` | SQLite credential database path, including subdirectories for volume mounting; the template uses `"auth-data/credentials.db"` |
| `jwt_secret` | string | - | JWT signing secret |
| `jwt_expire_seconds` | integer | `86400` | JWT token lifetime in seconds, minimum 60 |

> **Note**: Owner credentials are not configured in this file. The Owner user is
> read from `secrets.toml` during deployment and written to `credentials.db`.

See [Authentication and Authorization](auth.md).

### [executor]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Whether the executor subsystem is enabled |
| `capabilities_dir` | path | `"configs/capabilities"` | Directory containing capability declaration TOML files |
| `audit_db_path` | path | `""` | SQLite audit database path; empty disables audit persistence. The template uses `"auth-data/audit.db"` |
| `sandbox_root` | path | - | Global filesystem sandbox root; all writes must be under this path |
| `dry_run` | boolean | `true` | Dry-run mode. Policies are evaluated without executing handlers. Recommended for initial deployment |
| `disable_agent_mode` | boolean | `false` | Force Pipeline mode even if the model supports tool calling. Sends a dedicated notification email when enabled |

See [Executor](executor.md).

### [git]

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Whether Git integration is enabled |
| `remote_url` | string | `""` | Remote repository HTTPS URL |
| `default_branch` | string | `"main"` | Default branch name |
| `local_repo_path` | path | `"/app/git-workspace"` | Local clone path inside the container |
| `api_base_url` | string | `"https://api.github.com"` | GitHub API URL; change for GitHub Enterprise |
| `repo_owner` | string | `""` | Repository owner, organization or username |
| `repo_name` | string | `""` | Repository name |
| `auto_pr` | boolean | `true` | Whether to create a PR automatically after daily-report rule generation |
| `auto_issue` | boolean | `true` | Whether real-time analysis creates high-threat issues automatically |
| `issue_threat_threshold` | string | `"高"` | Minimum threat level that triggers automatic issues: `"高"` or `"严重"` |
| `rules_path` | string | `"rules/generated"` | Repository path for generated rules |
| `validate_with_suricata` | boolean | `false` | Whether to run medium validation with `suricata -T` |
| `fork_owner` | string | `""` | Fork mode: GitHub username for the fork repository. When set, the Agent clones the fork and creates cross-repository PRs |
| `reset_time` | string | `"02:00:00"` | Daily scheduled Git workspace reset time in HH:MM:SS 24-hour format. Reset discards local changes and pulls the latest remote code |

> **Note**: `token` is stored in `credentials.db` via `secrets.toml` deployment.

See [Git and GitHub Integration](git-integration.md).

---

## ModelProfiles.toml - Model Performance Profiles

Defines baseline performance characteristics for all available LLM models and is
used by the adaptive tuning algorithm.

### Global Configuration

| Option | Type | Description |
|--------|------|-------------|
| `total_vram_mb` | integer | Moved to `[gpu].total_vram_mb`; retained for backward compatibility, with `[gpu]` taking precedence |

### Model Profile [model."model-name"]

Each model is keyed by its full model name and contains:

| Option | Type | Description |
|--------|------|-------------|
| `baseline_tps` | float | Baseline generation speed in tokens/sec; corrected by runtime observations |
| `quality_score` | float | Model-quality metadata from 0.0 to 1.0. Current adaptive tuning adjusts parameters within the active real-time profile and does not use this for cross-model switching |
| `vram_calibration_context` | integer | Context length used for VRAM calibration |
| `vram_calibration_mb` | integer | VRAM usage at the calibration context length |
| `context_length` | {min, max} | Adjustable context length range |
| `num_predict` | {min, max} | Adjustable maximum generated token range |
| `concurrency` | {min, max} | Adjustable concurrent request range |
| `batch_size` | {min, max} | Adjustable batch size range |
| `poll_interval` | {min, max} | Adjustable poll interval range in seconds |
| `temperature` | float | Fixed generation temperature |
| `top_p` | float | Fixed Top-p sampling parameter |
| `top_k` | integer | Fixed Top-k sampling parameter |
| `supports_tool_use` | boolean? | Optional override for tool-use detection: `true`, `false`, or omitted for auto-detection |
| `backend_type` | string | Backend type: `"ollama"`, `"openai"`, or `"deepseek"`. If omitted, the global `[llm.backend].type` is used |
| `backend_base_url` | string | Backend URL override for this model. If omitted or empty, `ollama` uses `[ollama].base_url`, `openai` uses the global OpenAI backend URL when the global backend is also `openai`, and `deepseek` uses the global DeepSeek backend URL when the global backend is also `deepseek`, otherwise `https://api.deepseek.com` |
| `backend_auth_token` | string | Override for the global auth token / API Key. If omitted or empty, global config is used |
| `total_params_b` | float | Total parameter count in billions, used for hardware throughput estimation |
| `active_params_b` | float | Parameters active per inference step; can be lower than total for MoE models |
| `bytes_per_param` | float | Average bytes per parameter after quantization, used for rough VRAM/throughput estimation |
| `cost_per_1k_prompt` | float | Cost per 1K prompt tokens; currently retained as model metadata. `0` means free/local |
| `cost_per_1k_completion` | float | Cost per 1K completion tokens; currency must match `[cost].budget_per_hour`. `0` means free/local. Used in cost-pressure calculation |
| `max_requests_per_minute` | integer | Backend request rate limit. `0` means unlimited. Models sharing the same backend cache key use the strictest non-zero limit |

> **Hybrid backend**: by declaring different `backend_type` values for
> different models, a single instance can use local Ollama, remote
> OpenAI-compatible backends, and the native DeepSeek backend at the same time.
> For example, real-time analysis can use a local model
> (`backend_type = "ollama"`) while daily reports use `deepseek-v4-flash`
> (`backend_type = "deepseek"`). The system caches backend instances by
> `(backend_type, base_url, auth_token)` and keeps DeepSeek's default URL
> separate from OpenAI-compatible URLs.

See [Performance Tuning](performance-tuning.md).

---

## daily_report_llm_conf.toml - Daily Report LLM Configuration

| Option | Type | Description |
|--------|------|-------------|
| `MODEL` | string | Model used for daily report generation, usually larger than the real-time model |
| `MAX_TOKENS` | integer | Maximum generated tokens |
| `TEMPERATURE` | float | Generation temperature |
| `TOP_P` | float | Top-p sampling |
| `TOP_K` | integer | Top-k sampling |
| `CONTEXT_LENGTH` | integer | Context length; daily reports need a larger context window |
| `detail_level` | string | Event detail level in daily report prompts: `"minimal"` (default, timestamp + threat level + summary), `"extended"` (adds event type, protocol, ports, alert signature, security hint, TLS/DNS/HTTP context), or `"full"` (complete `_source` JSON) |

> **Backward compatibility**: old `OLLAMA_*` field names, such as
> `OLLAMA_MODEL` and `OLLAMA_NUM_PREDICT`, are still parsed correctly.

---

## llm_prompt.toml - Prompt Templates

See [LLM Prompt Configuration](llm-prompt-config.md).

---

## suspicious_ja3.toml / suspicious_ja3s.toml - JA3 Fingerprint Lists

Define known-malicious TLS client/server fingerprints used for event filtering.

**Format**:

```toml
# suspicious_ja3.toml
tls_ja3_hashes = [
  "e7d705a3286e19ea42f587b344ee6865"
]
```

```toml
# suspicious_ja3s.toml
tls_ja3s_hashes = [
  "ae4edc6faf64d08308082ad26be60767"
]
```

`suspicious_ja3.toml` contains only the `tls_ja3_hashes` array.
`suspicious_ja3s.toml` contains only the `tls_ja3s_hashes` array. Each element
must be a 32-character hexadecimal MD5 hash.

The project templates provide several client and server fingerprint hashes. You
can replace or extend them using the same array format.

---

## secrets.toml - Secrets and Authentication

`secrets.toml` is used only by the deployment script. All credentials are
written to `credentials.db` during deployment and loaded from the database at
runtime, with no Podman secret or credential-bearing environment variable
required.

```toml
[elasticsearch]
username = { "value" = "your-username" }
password = { "value" = "your-password" }

# [log_output]                            # Optional: uncomment for separate log-output ES credentials
# username = { "value" = "" }
# password = { "value" = "" }

[auth]
jwt_secret = { "value" = "your-jwt-secret" }

[auth.owner]
username = "admin"              # Written to credentials.db during deployment, not to environment variables
password = "strong-password"    # Hashed with bcrypt before being written to credentials.db
email = "admin@example.com"

[git]
token = { "value" = "your-github-token" }

# [llm]                                   # Remote LLM backend API Key
# api_key = { "value" = "sk-your-key" }

[mail]                                    # Mail credentials: Outlook OAuth2 / Gmail Basic Auth
client_id = { "value" = "your-client-id" }
client_secret = { "value" = "your-client-secret" }
```

`[auth.owner]` is used only by the deployment script to create the Owner user on
first deployment. The credentials **do not** appear in the container environment
or Quadlet files.

The `[mail]` section stores mail authentication credentials. Outlook uses
`client_id` and `client_secret` for OAuth2; Gmail Basic Auth uses `sender` as
the SMTP username and `client_secret` as the password. These credentials have
moved from the main `suricata-llm-agent.toml` file to `secrets.toml`; the
deployment script writes them to `credentials.db`, and runtime loads them
automatically from the database. If mail notification is unused, this section can
be commented out.

The `[llm]` section stores the API Key for a remote LLM backend. During
deployment it is written to `credentials.db` under the `llm_api_key` key. It can
also be set at runtime through `PUT /credentials/llm_api_key` or the
`SURICATA_LLM_API_KEY` environment variable. It is needed when using a remote
backend such as `type = "openai"` or `type = "deepseek"`.

---

## deploy.toml - Deployment Configuration

See [Deployment Guide](deployment.md).

---

## JSON Schema Constraints

All configuration files are validated during deployment with JSON Schemas under
`configs/constraints/`:

| Schema file | Target |
|-------------|--------|
| `agent-config.schema.json` | `suricata-llm-agent.toml` |
| `deploy-config.schema.json` | `deploy.toml` |
| `secrets.schema.json` | `secrets.toml` |
| `container-base.schema.json` | `configs/container_base/*.toml` |
| `pm-config.schema.json` | `configs/package_manager/*.toml` |
| `mail-provider-config.schema.json` | `configs/mail_providers/*.toml` |
| `model-profiles.schema.json` | `ModelProfiles.toml` |
| `llm-prompt.schema.json` | `llm_prompt.toml` |
| `ja3-list.schema.json` | `suspicious_ja3.toml` |
| `ja3s-list.schema.json` | `suspicious_ja3s.toml` |

Schemas use the custom extension `x-deploy-file: true` to mark options whose
values are file paths. The deployment system uses this marker to discover
implicit files that must be baked into the deployment image.

Schemas for the main runtime configuration, secrets configuration, and
capability declarations restrict additional fields at key object levels so
spelling mistakes are surfaced early. Deployment configuration and model profile
schemas rely mainly on required fields, enums, and value ranges, and do not
forbid additional fields at every object level.
