<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         daily-report.md
Description:  Daily report generation process with multi-level LLM analysis flow.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# Daily Report System

## Overview

The daily report system automatically generates an HTML security analysis report
at the end of each day. By default, it uses a **multi-level LLM analysis**
architecture: group by communication pair -> split by time segment -> analyze
level by level -> synthesize the final report, then save the report to disk and
send it by email. For experiments and ablation comparisons, the system also
supports the simplified `pair_only` and `flat` modes.

The core implementation lives in `src/daily_report.py`.

## Trigger Conditions

1. **Automatic trigger**: the main loop detects a date boundary (crossing 00:00)
   and generates a report for the previous day.
2. **Manual trigger**: the RMI endpoint `POST /gen_report+YYYY-MM-DD` can
   generate a report for any specified date.

> **Real-time analysis pause**: during daily report generation, real-time
> analysis (`process_batch`) is paused automatically to avoid competing with
> daily-report LLM calls for model and backend resources. It resumes
> automatically after generation completes. The pause state is implemented by
> the thread-safe `config.daily_report_active` flag.

## Generation Flow

```text
DailyReportService.generate_and_send(report_date, force)
|
|-- Not force and daily_report.enabled=false -> skip
|
|-- set_daily_report_active()
|   `-- real-time process_batch() returns an empty batch when it sees the flag
|
`-- _generate_and_send_inner()
    |-- fetch_daily_stats()
    |-- fetch_processed_summaries()
    |   `-- Fetch documents for the day where ai.processed=true and ai.summary exists
    |-- stop_ollama_model() when the current real-time model is loaded
    |
    |-- No items
    |   `-- build_daily_report_prompt() -> call_daily_report_llm()
    |
    |-- analysis_mode = "flat"
    |   `-- All summaries for the day -> one LLM call -> global report
    |
    |-- analysis_mode = "pair_only"
    |   `-- group_by_comm_pair()
    |       `-- One LLM call per communication pair -> concatenate analyses
    |
    `-- analysis_mode = "hierarchical"
        `-- group_by_comm_pair()
            `-- split_by_time_gap()
                `-- _analyze_segment()
                    `-- _analyze_pair()
                        `-- build_final_report_prompt()
                            `-- call_daily_report_llm()

Output phase
|-- build_report_html()
|-- Insert experiment_tag banner when configured
|-- _save_report_html()
|-- send_daily_report_email() only when enable_notification=true
|-- _run_rule_generation() only when pair_results exists and git is enabled
`-- clear_daily_report_active()
```

## Why Multi-Level Analysis

Feeding all communication logs from an entire day directly into one LLM call has
several problems:

1. **Noise interference**: logs from unrelated communication parties are mixed
   together, making correlation analysis difficult.
2. **Context limits**: even large-context models may not fit a full day's logs.
3. **Analysis depth**: analysis quality drops when the LLM faces a large amount
   of unrelated data.

The multi-level design addresses these issues through **classification ->
segmentation -> layered summarization**:

- **Level 1** (time segment): focuses on short-term behavior patterns within one
  communication pair.
- **Level 2** (communication pair): summarizes a full-day communication profile
  between two hosts.
- **Level 3** (global): performs correlation analysis across all communication
  pair analyses.

## HTML Report Contents

Generated HTML reports contain:

| Section | Content |
|---------|---------|
| **Statistics overview** | Total events, AI-processed count, time range |
| **Event type distribution** | Count table by `event_type` |
| **Threat level distribution** | Count table for N0 through N3 |
| **High/critical event details** | List of higher-severity events |
| **Communication pair analysis** | LLM analysis result for each communication pair |
| **Global correlation analysis** | Final Level 3 daily report content |
| **Experiment banner** | Inserted at the top when `daily_report.experiment_tag` is non-empty |
| **Metadata** | Report date and generation time |

## Configuration

### [daily_report] in suricata-llm-agent.toml

```toml
[daily_report]
enabled = true
llm_config_file = "daily_report_llm_conf.toml"
fetch_size = 10000
session_gap = 1800
max_segment_events = 200
output_dir = "/app/daily_reports"
subject_prefix = "[Suricata AI 每日流量日报]"
analysis_mode = "hierarchical"
# experiment_tag = ""
# Recipients are not configured here. With U-A-P enabled, they are selected
# automatically from the user database by role.
```

| Option | Description |
|--------|-------------|
| `enabled` | Whether daily reports are enabled |
| `llm_config_file` | Dedicated daily-report LLM configuration file |
| `fetch_size` | ES scroll batch size |
| `session_gap` | Idle gap in seconds for splitting segments within one communication pair; segments are split only when adjacent events exceed this gap |
| `max_segment_events` | Maximum events included in one segment-level LLM call |
| `output_dir` | Directory for saving HTML reports |
| `subject_prefix` | Mail subject prefix |
| `analysis_mode` | `hierarchical`, `pair_only`, or `flat` |
| `experiment_tag` | Experiment label; when non-empty, modifies the mail subject and inserts a report banner |

> With U-A-P enabled, daily report recipients are selected automatically from
> users with Owner, Administrator, and Watcher roles. They do not need to be
> configured here.

### analysis_mode

| Mode | Flow | Use case |
|------|------|----------|
| `hierarchical` | Communication-pair grouping -> time segmentation -> segment analysis -> pair analysis -> global synthesis | Default production path with full correlation analysis |
| `pair_only` | Communication-pair grouping -> one analysis per pair -> concatenate output | Ablation experiment that keeps pair grouping without time segmentation or global synthesis |
| `flat` | One overall analysis over all processed events with summaries for the day | Flat baseline with lower cost and weakest correlation structure |

### daily_report_llm_conf.toml

Daily reports use an independent LLM configuration, typically with a larger
model and longer context window:

```toml
[DailyReportLLMConfig]
MODEL = "qwen3-coder-next:q4_K_M"
MAX_TOKENS = 4096
TEMPERATURE = 0.2
TOP_P = 0.9
TOP_K = 40
CONTEXT_LENGTH = 65536
detail_level = "minimal"
```

> **Backward compatibility**: legacy `OLLAMA_*` fields such as `OLLAMA_MODEL`
> and `OLLAMA_NUM_PREDICT` are still parsed correctly.

### detail_level

`detail_level` controls how much information each event contributes to the daily
report prompt:

| Level | Description | Per-event prompt content | ES fetch scope |
|-------|-------------|--------------------------|----------------|
| `"minimal"` | Default | `[threat level] timestamp \| summary` | `ai.summary`, `ai.threat_level`, `@timestamp`, `event_type` |
| `"extended"` | Extended | Adds event_type, proto, ports, alert signature, security_hint, TLS/DNS/HTTP context | Also fetches `alert.signature`, `src_port`, `dest_port`, `proto`, `ai.security_hint`, `tls.sni`, `dns.rrname`, `http.url`, and related fields |
| `"full"` | Full | Raw JSON for the entire event | Full `_source` |

> **Token cost note**: `extended` and `full` significantly increase token use
> for each LLM call, which extends report generation time. Use them when the
> model has enough context and deeper analysis is required.

When a remote OpenAI-compatible service returns provider-specific `422` because
of content-safety policy, segment-level analysis falls back to a structured
count summary so the entire daily report is not interrupted by one failed
communication segment.

Daily report analysis processes more text than real-time analysis, so:

- `CONTEXT_LENGTH` is usually much larger than real-time analysis (65536 vs. about 16384).
- `MAX_TOKENS` is larger to allow more detailed output (4096 vs. about 512).
- The model can be larger or stronger, since it is less constrained by real-time latency.

## Statistics Fetching

`fetch_daily_stats()` uses ES aggregations to collect full-day statistics:

- **Total events**: number of documents in the day's index
- **AI processed count**: number of documents with `ai.processed=true`
- **Event type distribution**: terms aggregation by `event_type`
- **Threat level distribution**: terms aggregation by `ai.threat_level`
- **Time range**: earliest and latest `@timestamp`

Detailed report data is fetched by `fetch_processed_summaries()` from the
`suricata-eve-YYYY.MM.DD` date index via scrolling. It includes only documents
where `ai.processed=true` (or `"true"` under historical string mappings) and
`ai.summary` exists.

## Rule Generation After Reporting

If `[git].enabled = true` and the executor is available, daily report generation
filters communication pairs whose `max_threat` is high or critical, then enters
the rule-generation flow:

1. In Agent mode, `AgentOrchestrator` decides whether to call tools based on the
   `daily_report_agent` prompt.
2. In Pipeline mode, the rule-generation prompt is called and JSON rule
   suggestions returned by the LLM are parsed.
3. Each rule is lightly validated by `suricata_rule_suggest`; optional medium
   validation can run `suricata -T`.
4. Validated rules are committed through `git_commit_and_push`, and a PR is
   created according to configuration.
5. After PR creation, `git_local_checkout_default` cleans the local worktree;
   remote synchronization and fork force-push are handled only by scheduled
   `git_repo_reset`.
