<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         agent-mode.md
Description:  Agent mode architecture with ReAct loop, tool calling, and mode detection.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# Agent Mode Architecture

## Overview

The system adds **Agent mode** (autonomous decision-making) on top of the
traditional **Pipeline mode** (pipeline decisions). In Agent mode, the LLM
drives operations directly through tool calling instead of relying on hard-coded
threshold logic.

## Runtime Mode Comparison

| Dimension | Pipeline mode | Agent mode |
|-----------|---------------|------------|
| Decision model | Hard-coded thresholds, such as threat level >= high -> create issue | LLM decides whether to call tools |
| LLM API | Chat messages without tools, compatible with Ollama/OpenAI backends | Chat messages + tool calling |
| Operation trigger | `_maybe_create_issue()` in code | LLM returns `tool_calls` -> Orchestrator dispatches |
| Applicable models | All models | Only models that support tool calling |
| Fallback | N/A | Conditional fallback to Pipeline mode |

## Mode Detection

At startup, `LLMHandler.supports_tool_use` checks whether the current real-time
analysis model supports tool calling. The detection logic lives in the backend
layer:

1. If `supports_tool_use` is set in `ModelProfiles.toml`, that explicit
   override takes precedence.
2. The Ollama backend calls `/api/show`, checks whether the `capabilities` list
   contains `"tools"`, and inspects tool-related markers in
   `model_info.tokenizer.chat_template` and the top-level `template` field.
3. The OpenAI-compatible backend reports tool-calling support by default; actual
   availability depends on the upstream model and server.

Backend instances for the same model are cached by `(backend_type, base_url,
auth_token)`. Explicit overrides are useful when the model capability is known
but backend metadata is incomplete.

### Manual Override

Set `supports_tool_use` for a model in `ModelProfiles.toml`:

```toml
[model."qwen2.5:7b"]
supports_tool_use = true   # Force enable
# supports_tool_use = false  # Force disable
# Omit the field for automatic detection
```

## ReAct Loop

The core of Agent mode is the ReAct loop implemented by `AgentOrchestrator`:

```text
System prompt + user/log message + tool schemas
|
`-- LLM chat API
    |
    |-- No tool_calls
    |   `-- final_answer -> returned to Processor / DailyReport
    |
    `-- Has tool_calls
        |-- Parse function name / arguments
        |-- Inject agent_identity
        |   `-- ActionRequest(actor_role, actor_id, api_key)
        |-- requires_approval?
        |   |-- Yes -> downgrade to approval issue
        |   `-- No -> ExecutorRuntime.execute()
        |-- Append ExecutionResult as tool observation
        `-- Continue until final_answer / max_rounds / timeout / token_budget
```

### Termination Conditions

The loop stops when any of the following conditions is met:

- **final_answer**: the LLM returns a response without `tool_calls`
- **max_rounds**: the maximum number of loop rounds is reached (default 2)
- **timeout**: the total time budget is exceeded (default 60s)
- **token_budget**: accumulated completion tokens exceed the limit (default 16384)

## Security Model

### Credential Isolation

The LLM **never receives** API keys or authentication data. The Orchestrator
holds an `agent_identity` reference and injects credentials while constructing
each `ActionRequest`:

```text
LLM -> tool_call(name, params)
                |
Orchestrator -> ActionRequest(name, params, actor_role, actor_id, api_key)
                |
Executor -> PolicyEngine -> Handler
```

### requires_approval

Capabilities marked with `requires_approval = true`, such as
`create_github_pr`, are not executed directly by the Orchestrator in Agent mode.
The Orchestrator automatically downgrades them to GitHub issues that notify an
administrator for approval.

### Prompt Injection Resistance

The system prompt contains safety instructions that tell the LLM not to treat
log content as executable instructions.

## Dual-Mode Integration

### Real-Time Processing (Processor)

`LogProcessor._build_update()` automatically routes based on whether an
orchestrator exists and whether the model supports tool use:

- Orchestrator present + tool use supported -> `_build_update_agent()`
- Otherwise -> `_build_update_pipeline()`

Agent mode falls back to Pipeline mode if the orchestrator raises an exception
or produces neither analysis text nor tool calls. If the LLM has already
executed tool calls but does not return analysis text, the system skips Pipeline
fallback for that event to avoid duplicate side effects such as repeated issue
creation.

### Daily Report (DailyReport)

- **Multi-level analysis** (segment -> communication pair -> final report):
  always uses text mode and does not require tool calling.
- **Rule generation** supports both modes:
  - Agent mode: the Orchestrator drives the full "analyze -> generate rules ->
    commit -> PR" workflow.
  - Pipeline mode: traditional LLM JSON generation -> parsing -> step-by-step
    execution.

### Startup Notification

If the detected model does not support tool calling, the system sends an email
to notify administrators that it is running in Pipeline mode.

## File List

| File | Description |
|------|-------------|
| `src/backends/ollama.py` | Ollama `/api/show` tool-use detection |
| `src/backends/openai_compat.py` | OpenAI-compatible backend and tool-calling support declaration |
| `src/tool_schema.py` | Capability -> function tool schema translator |
| `src/orchestrator.py` | ReAct loop Orchestrator |
| `src/llm_handler.py` | `call_llm_chat()`, `supports_tool_use` property |
| `src/llm_prompt.py` | Agent-mode prompt builder |
| `llm_prompt.toml` | `[realtime_agent]`, `[daily_report_agent]` templates |
| `src/processor.py` | Dual-mode routing |
| `src/daily_report.py` | Dual-mode rule generation |
| `src/main.py` | Startup detection, Orchestrator creation, fallback notification |
