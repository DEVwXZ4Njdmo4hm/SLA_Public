<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         llm-prompt-config.md
Description:  LLM prompt template configuration with variable syntax reference.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# LLM Prompt Configuration

## Overview

All LLM prompt templates are externalized in `llm_prompt.toml`, so they can be
changed without editing source code. Templates use Python `str.format_map()`
syntax for variable substitution, and unknown placeholders are preserved safely.

The core implementation lives in `src/llm_prompt.py`.

## Template File Structure

```toml
# llm_prompt.toml

[shared]
shared_prompt = """..."""       # Shared context, such as network environment and N0-N3 rules; optional

[realtime]
template = """..."""            # Real-time analysis prompt
                                # {system_prompt_end} can split system and user content

[realtime_agent]
system_template = """..."""     # Agent-mode real-time analysis system prompt
user_template = """..."""       # Agent-mode real-time analysis user prompt

[memory_compact]
template = """..."""            # Rolling memory compaction prompt

[daily_report_agent]
system_template = """..."""     # Daily report rule-generation Agent system prompt
user_template = """..."""       # Daily report rule-generation Agent user prompt

[rule_generation]
template = """..."""            # Daily report rule-generation pipeline prompt

[daily_report.segment]
template = """..."""            # Daily report: segment-level analysis

[daily_report.pair]
template = """..."""            # Daily report: communication-pair-level analysis

[daily_report.final]
template = """..."""            # Daily report: final report

[daily_report.legacy]
template = """..."""            # Daily report: traditional one-shot analysis fallback

[escalation]
template = """..."""            # Escalation: deep secondary threat analysis
```

## Shared Prompt Fragment ([shared])

`[shared].shared_prompt` stores context shared by all analysis templates. It is
injected through the `{shared_prompt}` placeholder into `realtime`,
`realtime_agent`, `escalation`, `daily_report_agent`, and all `daily_report.*`
templates.

Typical contents include:

- **Network environment**: internal subnets, domain suffixes, key device topology
  such as proxies or VPNs.
- **Threat level definitions**: harmless, low, medium, high, critical.
- **N0-N3 noise classification rules**: prioritized threat-decision rules.

This field is **optional**. The entire `[shared]` section may be omitted, or
`shared_prompt` may be an empty string. When omitted, `{shared_prompt}` in all
templates is replaced with an empty string.

## Template Variable Syntax

Use `{variable_name}` placeholders:

```text
Event type: {event_type}
Source: {src_hostname}({src_ip}):{src_port}
```

**Safe substitution**: `_SafeDict` preserves unmatched placeholders instead of
raising `KeyError`. This allows templates to contain variables that may be added
in the future without breaking current functionality.

**JSON literals**: JSON examples in templates need doubled braces:

```text
Return the following JSON:
{{
  "summary": "...",
  "threat_level": "..."
}}
```

## Real-Time Analysis Prompt ([realtime])

### Available Variables

| Variable | Source | Description |
|----------|--------|-------------|
| `{event_type}` | ES document | Event type, such as alert, dns, http, tls |
| `{timestamp}` | ES document | Event timestamp |
| `{src_ip}` | ES document | Source IP |
| `{src_port}` | ES document | Source port |
| `{src_hostname}` | ES document | Source hostname, possibly empty |
| `{src_city}` | GeoIP | Source city |
| `{src_country}` | GeoIP | Source country |
| `{src_asn}` | GeoIP | Source ASN |
| `{dest_ip}` | ES document | Destination IP |
| `{dest_port}` | ES document | Destination port |
| `{dest_hostname}` | ES document | Destination hostname |
| `{dest_city}` | GeoIP | Destination city |
| `{dest_country}` | GeoIP | Destination country |
| `{dest_asn}` | GeoIP | Destination ASN |
| `{proto}` | ES document | Protocol |
| `{alert}` | ES document | Alert rule signature |
| `{severity}` | ES document | Alert severity |
| `{is_noise}` | Preprocessing | Whether the event is classified as noise |
| `{memory_block}` | Current memory mode | Historical memory entries visible to the current event; source changes with `llm.memory_mode` between pair, global, protocol-pair sub-bucket, or empty memory |

### Prompt Structure

The real-time analysis prompt contains these main areas:

1. **Role definition**: network security expert.
2. **Shared context**: injects network environment, threat level definitions, and
   N0-N3 rules through `{shared_prompt}`.
3. **Current log**: event details injected through variables.
4. **Historical memory**: recent analysis summaries for the same communication
   pair.
5. **Output format**: JSON output requirements.

Pipeline mode calls the chat API through `build_pipeline_messages()` and returns
one `system` message and one `user` message. `{system_prompt_end}` is the
recommended split marker in the template: content before the marker becomes the
system prompt, and content after it becomes the current-log and memory context.
If the marker is missing, the code falls back to the first event-field position.

Agent mode uses `system_template` and `user_template` from `[realtime_agent]`
and passes function tool descriptions built by `src/tool_schema.py` to a backend
that supports tool calling.

### Threat-Level Rule System

Rules are prioritized into four levels (N0 highest -> N3 lowest):

| Level | Priority | Typical rule |
|-------|----------|--------------|
| **N0** | Highest | Noise -> harmless |
| **N1** | High | Known behavior for a specific host pair, direct external SSH to internal network -> critical |
| **N2** | Medium | Normal proxy backhaul traffic, monitoring traffic, well-known cloud services -> harmless |
| **N3** | Lowest | Default mapping based on alert severity |

Higher-priority rules override lower-priority rules.

## Daily Report Prompts

Daily reports have three analysis modes controlled by
`suricata-llm-agent.toml` `[daily_report].analysis_mode`:

| Mode | Templates used |
|------|----------------|
| `hierarchical` | `[daily_report.segment]` -> `[daily_report.pair]` -> `[daily_report.final]` |
| `pair_only` | `[daily_report.legacy]` once per communication pair |
| `flat` | `[daily_report.legacy]` |

### Segment Analysis ([daily_report.segment])

| Variable | Description |
|----------|-------------|
| `{host_a}` | One side of the communication pair |
| `{host_b}` | The other side of the communication pair |
| `{time_start}` | Segment start time |
| `{time_end}` | Segment end time |
| `{event_count}` | Number of events in the segment |
| `{event_summaries}` | Event summary list |

Output requirement: plain-text analysis within 200 words.

### Communication Pair Analysis ([daily_report.pair])

| Variable | Description |
|----------|-------------|
| `{host_a}` | One side of the communication pair |
| `{host_b}` | The other side of the communication pair |
| `{segment_count}` | Number of time segments |
| `{segment_analyses}` | Summary of all segment analyses |

Output requirement: plain-text analysis within 400 words, covering
communication patterns, behavior characteristics, and security risk.

### Final Report ([daily_report.final])

| Variable | Description |
|----------|-------------|
| `{report_date}` | Report date |
| `{total_events}` | Total raw event count |
| `{ai_processed_count}` | AI-processed count |
| `{ai_has_summary_count}` | Events with summaries |
| `{time_min}` / `{time_max}` | Data time range |
| `{pair_count}` | Total communication pair count |
| `{event_type_breakdown}` | Event type distribution table |
| `{threat_level_breakdown}` | Threat level distribution table |
| `{pair_analyses}` | Analyses for all communication pairs |

Output requirement: HTML fragment without `<html>`, `<head>`, or `<body>` tags.
It should include an overall overview, risk trends, key communication pair
analysis, correlation analysis, and recommendations.

### Legacy Mode ([daily_report.legacy])

Fallback template for one-shot analysis over processed summaries. `flat` mode
calls it once for all processed events with summaries from the day; `pair_only`
groups by communication pair and calls it once per group. Variables are similar
to final mode, but it receives `{summary_list}` (event summary list) and
`{high_event_count}` instead of `{pair_analyses}`.

## Daily Report Rule-Generation Prompt

After daily report generation, if `[git].enabled = true` and the executor is
initialized, the system tries to generate Suricata rules for high-risk
communication pairs.

### Agent Mode ([daily_report_agent])

When the selected model supports tool calling and Agent mode is not disabled,
rule generation uses `[daily_report_agent]`:

| Variable | Description |
|----------|-------------|
| `{report_date}` | Report date |
| `{high_pairs_text}` | Analysis text for high/critical communication pairs |
| `{existing_sids_text}` | List of SIDs already present in the repository |

The LLM is responsible only for deciding whether to call tools. Actual
`suricata_rule_suggest`, `git_commit_and_push`, `create_github_pr`, and related
actions are validated by the local executor for permissions, parameter schema,
and audit policy before execution.

### Pipeline Mode ([rule_generation])

When Agent mode is unavailable, the system uses `[rule_generation]` to generate
JSON rule suggestions, then local code calls `suricata_rule_suggest` to write
rule files.

| Variable | Description |
|----------|-------------|
| `{analysis_summary}` | Daily report analysis summary |
| `{high_threat_pairs}` | High/critical communication pair list |
| `{existing_sids}` | Existing SID list |

The subsequent Git workflow is fixed in code: commit, push, create PR, then call
`git_local_checkout_default` to clean the local worktree. Remote branch
synchronization is handled by scheduled `git_repo_reset`.

## Memory Compaction Prompt ([memory_compact])

When `[llm].memory_mode` uses `pair_rolling`, `global_rolling`, or
`proto_pair_rolling`, the system calls the `[memory_compact]` template to
compress the oldest entries once the memory bucket exceeds its threshold.

| Variable | Description |
|----------|-------------|
| `{entry_count}` | Number of entries compressed in this run |
| `{pair_key}` | Memory bucket identifier; in global mode this is the global bucket identifier, and in proto-pair mode it includes the communication pair and Event_Z sub-bucket |
| `{entries_text}` | Historical entries to compress |

Compaction uses the current real-time analysis model and current LLM backend
configuration. Keep the template output short so compaction itself does not
become a major token-cost source.

## Escalation Prompt ([escalation])

When the initial real-time analysis reaches or exceeds
`[llm.escalation].threat_threshold`, the system performs secondary deep analysis
with the escalation model. The prompt is built by `build_escalation_prompt()`.

### Available Variables

| Variable | Source | Description |
|----------|--------|-------------|
| `{raw_event_block}` | ES document | Raw event information. Controlled by `include_raw_fields`: when enabled, includes full fields such as alert, TLS, DNS, HTTP; when disabled, includes only communication-pair identifiers and event type |
| `{initial_analysis}` | Initial analysis | Raw output text from the primary model before parsed JSON processing |
| `{memory_block}` | Current memory mode | Historical records visible to the event, in the same format as real-time `memory_block` |

### Prompt Structure

1. **Role definition**: senior network security analyst.
2. **Raw event information**: `{raw_event_block}`.
3. **Initial analysis result**: `{initial_analysis}`.
4. **Communication-pair history**: `{memory_block}`.
5. **Output format**: the same JSON structure as real-time analysis: `summary`,
   `threat_level`, `security_hint`, `recommendation`.
6. **Analysis guidance**: correct initial judgments, correlate historical
   records, and identify attack patterns.

---

## Effect of detail_level on Daily Report Prompts

The `detail_level` option in `daily_report_llm_conf.toml` controls how
`{event_summaries}` is formatted in `build_segment_prompt()`:

| Level | Per-event format | Use case |
|-------|------------------|----------|
| `"minimal"` | `- [threat level] timestamp \| summary` | Default, lowest token cost |
| `"extended"` | `- [threat level] timestamp \| event type \| protocol \| ports \| summary [alert: signature] [hint: ...] [sni: ...] [dns: ...] [url: ...]` | When more network context is needed |
| `"full"` | Indented JSON of the complete `_source` | When the most complete information is needed; token cost is much higher |

> **Note**: `detail_level` also affects ES fetch scope. `extended` requests
> alert, port, protocol, TLS/DNS/HTTP fields; `full` requests the entire
> `_source`. Higher detail levels significantly increase token use and latency
> for daily report generation.

---

## Customization Guide

### Changing the Network Environment

Edit the "network environment" section in `[shared].shared_prompt` and replace
it with your actual topology. It is injected automatically through
`{shared_prompt}` into all real-time, escalation, and daily report prompts:

```toml
[shared]
shared_prompt = """
# Network environment
- Internal subnet: 10.0.0.0/8
- Internal domain suffix: .corp.example.com
- ...
"""
```

### Changing Threat Decision Rules

Edit the N0 through N3 rule table in `[shared].shared_prompt`. The rules use
Markdown table format, which LLMs can interpret accurately:

```text
| Condition | Instruction |
|-----------|-------------|
| your-condition | -> threat_level |
```

### Adjusting Output Format

Modify the "output requirements" section. Real-time analysis currently uses
these JSON fields:

- `summary`: event overview, <=150 Chinese characters in the Chinese prompt
- `threat_level`: threat level
- `security_hint`: security meaning, <=80 Chinese characters in the Chinese prompt
- `recommendation`: recommended action, <=100 Chinese characters in the Chinese prompt

> **Note**: if JSON field names are changed, update the parsing logic in
> `llm_handler.py` `parse_json_sections()` at the same time.

## Configuration Reference

Specify the prompt file path in `suricata-llm-agent.toml`:

```toml
[llm]
prompt_file = "llm_prompt.toml"
```

The deployment preflight mechanism discovers this path automatically through the
`x-deploy-file: true` schema extension, so it does not need to be added manually
to `deploy.toml` `extra_files`.
