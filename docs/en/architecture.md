<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         architecture.md
Description:  System architecture with module dependency diagram and data flow overview.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# Architecture Overview

## System Role

Suricata LLM Agent is a real-time IDS log analysis engine deployed as an
analysis layer around Suricata and Elasticsearch. It uses local Ollama or an
OpenAI-compatible LLM backend to perform automated threat assessment for network
security events.

```text
+----------+   eve.json   +-----------------+
| Suricata |------------->| Elasticsearch   |
+----------+              | Suricata index  |
                          +--------^--------+
                                   | scroll query / bulk writeback to ai.*
                                   |
+----------------------------------+----------------------------------+
| Suricata LLM Agent                                                   |
| main.py main loop                                                    |
| |- processor.py: real-time batches, memory updates, escalation, Issue |
| |- daily_report.py: daily reports, rule generation, mail delivery     |
| |- rmi.py: FastAPI management API, SSE logs, manual report trigger    |
| `- executor/: U-A-P policy, PathGuard, audit, Git/rule handlers       |
+----------------------------------+----------------------------------+
                                   | chat / generate
                                   v
                    +------------------------------+
                    | LLM backends                 |
                    | Ollama / OpenAI-compatible   |
                    | per-model routing + limiter  |
                    +------------------------------+
```

The system supports hybrid backends. Different models can use different
backends, such as local Ollama or a remote OpenAI-compatible API. Routing is
based on each model's `backend_type` in `ModelProfiles.toml`.

## Module Dependencies

```text
main.py                              # Entry point, startup orchestration, main loop
├── config.py                        # Global configuration and model profiles
├── logging_utils.py                 # Logging, ES log handler, statistics snapshots
├── auth/                            # U-A-P users, roles, JWT, API keys
│   ├── database.py                  # SQLite user/credential storage
│   ├── dependencies.py              # FastAPI authentication dependencies
│   ├── bootstrap.py                 # Runtime Agent identity bootstrap/revocation
│   └── log_broadcast.py             # SSE log broadcast
├── executor/                        # Controlled side-effect execution layer
│   ├── registry.py                  # configs/capabilities/*.toml
│   ├── policy.py                    # Role, parameter, rate, identity checks
│   ├── path_guard.py                # Filesystem boundary checks
│   ├── runtime.py                   # Execution orchestration and audit
│   └── handlers/                    # GitHub, git, Suricata rule handlers
├── llm_handler.py                   # LLM calls, memory, JSON parsing, Agent identity
│   ├── llm_prompt.py                # Prompt template rendering
│   ├── global_memory.py             # Global FIFO / rolling-compaction memory
│   ├── comm_proto_pair_memory.py    # Protocol-communication-pair bucketed memory
│   ├── llm_backend.py               # Backend protocol and token metrics
│   └── backends/                    # Ollama / OpenAI-compatible / rate limiting
├── orchestrator.py                  # Agent-mode ReAct loop
│   └── tool_schema.py               # Capability -> function tool schema
├── processor.py                     # Real-time batch processing
│   ├── pre_process.py               # ES query construction and event filtering
│   └── es_client.py                 # ES reads, counts, bulk writeback
├── daily_report.py                  # Daily reports, rule generation, HTML output
│   ├── es_client.py                 # Daily report data fetches
│   ├── llm_prompt.py                # Daily report / rule prompts
│   └── mailer/                      # Daily report email delivery
├── rmi.py                           # FastAPI management plane and manual report thread
└── perf_cacl.py                     # Adaptive performance tuning
```

## Core Data Flow

### Real-Time Analysis Flow

```text
main.py main loop
|
|-- Date-boundary check: call DailyReportService.generate_and_send() when needed
|-- apply_remote_commands(): currently keeps the queue framework, with no registered handlers
`-- processor.process_batch(index)
   |
   |-- Skip this real-time cycle when daily_report_active is true
   |
   |-- es_client.get_unprocessed_docs()
   |  `-- pre_process.py builds bool query and fetches unprocessed documents
   |
   |-- ThreadPoolExecutor / single-threaded _build_update()
   |  |
   |  |-- Agent path: orchestrator exists and model supports tool calling
   |  |  |-- get_memory_snapshot() reads communication-pair / Event_Z memory
   |  |  |-- AgentOrchestrator.run(tools=create_github_issue)
   |  |  |-- tool_call executed by ExecutorRuntime
   |  |  `-- final_answer parsed into ai fields
   |  |
   |  `-- Pipeline path: llm_handler.generate_advice()
   |     |-- get_backend_for_model() routes by model
   |     `-- Parse JSON response
   |
   |-- _maybe_escalate(): optional high-tier model reanalysis and overwrite
   |-- update_summary_memory(): write into the configured memory structure
   |-- Side effects
   |  |-- Pipeline: _maybe_create_issue() calls Executor by threshold
   |  `-- Agent: Issue and other side effects already triggered by tool_call
   `-- es_client.bulk_update_ai_advice()
      `-- Write ai.advice, ai.processed, ai.processed_at, and ai.* fields
```

### Daily Report Flow

```text
main.py date boundary / RMI manual trigger
|
`-- DailyReportService.generate_and_send(report_date, force)
   |-- set_daily_report_active(): pause real-time process_batch()
   |-- fetch_daily_stats()
   |-- fetch_processed_summaries()
   |
   |-- analysis_mode
   |  |-- flat
   |  |  `-- build_daily_report_prompt() -> call_daily_report_llm()
   |  |-- pair_only
   |  |  `-- group_by_comm_pair() -> one LLM call per pair -> concatenate output
   |  `-- hierarchical
   |     `-- group_by_comm_pair()
   |        `-- split_by_time_gap()
   |           `-- _analyze_segment() -> _analyze_pair() -> final report LLM
   |
   |-- build_report_html()
   |-- _save_report_html()
   |-- send_daily_report_email(): only when enable_notification=true
   |-- _run_rule_generation(): only when pair_results exists and git is enabled
   `-- clear_daily_report_active(): resume real-time processing
```

### Performance Tuning Flow

```text
process_batch() returns llm_metrics / fetched / backlog
|
|-- token_window.record(): token rate statistics for RMI
|
`-- AUTO_PERF_SELECT=true
    |-- record_token_stats(): update throughput estimates for each model
    |-- perf_index_predict(): predict pressure from current observations and backlog
    |-- adaptive_select(): calculate target ModelProfile
    `-- Switch CURRENT_PERF_CONFIG when the config changes
        `-- If model name changed, stop_ollama_model(current_model) first
```

## Thread Model

```text
+-------------------------------------------------+
|                Main Thread                       |
|  main() main loop                                |
|  |-- process_batch()                             |
|  |-- Automatic daily report checks and generation |
|  |-- apply_remote_commands()                     |
|  |-- adaptive_select() performance tuning        |
|  `-- emit_stats_snapshot() statistics reporting  |
+-------------------------------------------------+

+------------------------+  +------------------------+
| ThreadPoolExecutor     |  | RMI Server Thread      |
| Created in process_batch|  | FastAPI + Uvicorn      |
| Concurrent LLM/Agent calls| REST API / SSE logs     |
+------------------------+  +------------------------+

+------------------------+  +------------------------+
| Manual Report Thread   |  | MailQueue Thread       |
| POST /gen_report+date  |  | Background retry when  |
| daemon daily report job|  | mail is enabled        |
+------------------------+  +------------------------+

+------------------------+
| ES Log Handler Thread  |
| Async bulk log writes  |
| to Elasticsearch       |
+------------------------+
```

**Thread-safety mechanisms**:

| Resource | Protection |
|----------|------------|
| `CURRENT_PERF_CONFIG` | `threading.Lock` (`_perf_config_lock`) |
| `CommPairMemory` | Internal `Lock` |
| `GlobalMemory` | Internal `Lock` |
| `CommProtoPairMemory` | Internal `Lock` |
| `RemoteCommandQueue` | Internal `Lock` |
| `MailQueue` | Internal `Lock` |
| `LLMMetrics` batch accumulation | `threading.Lock` |
| `StatsWindow` | `threading.Lock` |
| `TokenStatsWindow` | `threading.Lock` |
| ES log handler | `queue.Queue` lock-free producer-consumer pattern |

## Lifecycle

```text
Startup
 |-- Load configuration, prompt templates, and model profiles (config.py / llm_prompt.py)
 |-- Initialize logging (logging_utils.py)
 |-- Open U-A-P credential database and load service credentials
 |-- Initialize Executor and Agent identity when enabled
 |-- Create LLM backend and Agent Orchestrator when enabled
 |-- Initialize fine-tuning sample store when enabled
 |-- Initialize Git workspace when enabled
 |-- Send startup notification email
 |-- Initialize mail queue (mail_queue.py)
 |-- Initialize SSE log broadcast
 |-- Start RMI server (rmi.py)
 |-- Connect to ES and run health check (es_client.py)
 |-- Ensure AI field mappings (es_client.py)
 `-- Enter main loop
       |-- Poll and process batches
       |-- Check date boundary -> trigger daily report
       |-- Apply remote commands
       |-- Tune performance
       `-- Emit statistics snapshots

Shutdown (SIGINT/SIGTERM)
 |-- Set GracefulShutdown flag
 |-- Stop RMI server
 |-- Revoke runtime Agent identity
 |-- Close U-A-P / Executor databases
 |-- Stop mail queue and flush spool
 |-- Send shutdown notification email
 |-- Flush ES log handler
 `-- Exit
```

## Event Filtering System

The Elasticsearch bool query built by `pre_process.py` applies several layers
of event filtering:

| Filter dimension | Description |
|------------------|-------------|
| **event_type** | Process only event types listed in `allowed_event_types`, such as alert, dns, http, tls, flow |
| **L3 protocol** | IPv4 / IPv6 filtering |
| **L4 protocol** | TCP / UDP / ICMP filtering |
| **L7 protocol** | Application-layer protocol filtering |
| **Alert severity** | Filter by `minimal_alert_severity` (1=high, 2=medium, 3=low) |
| **DNS** | Filter by rcode (NXDOMAIN, SERVFAIL, REFUSED) and rrtype (ANY, TXT) |
| **HTTP** | Filter by status code (>=400) and unusual methods (PUT, DELETE, TRACE, CONNECT) |
| **TLS** | Filter by version (SSLv3, TLSv1, TLSv1.1), missing SNI, and malicious JA3/JA3S fingerprints |

## Communication Pair Mechanism

Communication pairs are the system's core grouping concept and are used in both
real-time analysis and daily report generation.

**Grouping rules**:

1. Use both parties' **hostnames** as the primary key, for example `hostA <-> hostB`.
2. If one side has no hostname, fall back to its **IP address**.
3. Bidirectional equivalence: `A->B` and `B->A` belong to the same communication pair.
4. Sort both endpoint identifiers to produce a canonical pair key.

**Real-time memory**:

- `pair` / `pair_rolling`: store memory by bidirectional communication pair;
  rolling mode calls the LLM to merge old entries after reaching the threshold.
- `global` / `global_rolling`: share memory across all events, useful as an
  ablation or global-context baseline.
- `proto_pair` / `proto_pair_rolling`: first bucket by communication pair, then
  create Event_Z sub-buckets by `app_proto` or `event_type`.
- `none`: fully disables real-time memory.
- Memory capacity is controlled by `llm.memory_max_pairs`,
  `llm.memory_per_pair_length`, `llm.memory_length`, and rolling-compaction
  parameters.

**Daily report grouping**:

- After grouping by communication pair, events are split into time segments by
  time gap (default 1800 seconds).
- `hierarchical` mode implements layered analysis: time segment ->
  communication pair -> global daily report.
- `pair_only` keeps communication-pair grouping but skips time segments and
  global synthesis; `flat` performs one overall analysis on all processed events
  from the day that have summaries.
