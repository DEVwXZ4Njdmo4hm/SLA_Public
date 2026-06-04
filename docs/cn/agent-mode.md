<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         agent-mode.md
Description:  Agent mode architecture with ReAct loop, tool calling, and mode detection.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# Agent 模式架构

## 概述

系统在传统的 **Pipeline 模式**（管线决策）之上新增了 **Agent 模式**（自主决策）。Agent 模式中，LLM 通过 tool calling 直接驱动操作执行，而非依赖硬编码阈值判断。

## 运行模式对比

| 维度 | Pipeline 模式 | Agent 模式 |
|------|-------------|-----------|
| 决策方式 | 硬编码阈值（如威胁等级≥高 → 创建 issue） | LLM 自主决定是否调用工具 |
| LLM API | Chat 消息（不传 tools，兼容 Ollama/OpenAI/DeepSeek 后端） | Chat 消息 + tool calling |
| 操作触发 | 代码中的 `_maybe_create_issue()` | LLM 返回 `tool_calls` → Orchestrator 分发 |
| 适用模型 | 所有模型 | 仅支持 tool calling 的模型 |
| 回退 | N/A | 有条件回退到 Pipeline 模式 |

## 模式检测

启动时通过 `LLMHandler.supports_tool_use` 检测当前实时分析模型是否支持 tool calling。检测逻辑位于后端层：

1. 若 `ModelProfiles.toml` 中设置了 `supports_tool_use`，优先使用该显式覆盖。
2. Ollama 后端调用 `/api/show`，检查 `capabilities` 列表是否包含 `"tools"`，并检查 `model_info.tokenizer.chat_template` 与顶层 `template` 字段中的 tool 相关标记。
3. OpenAI 兼容后端默认返回支持 tool calling，由具体上游模型和服务端决定实际可用性。
4. 原生 DeepSeek 后端默认返回支持 tool calling，由所选 DeepSeek 模型和 API 行为决定实际可用性。

同一模型的后端实例按 `(backend_type, base_url, auth_token)` 缓存；显式覆盖适合已知模型能力但后端元数据不完整的情况。

### 手动覆盖

在 `ModelProfiles.toml` 中为模型设置 `supports_tool_use`：

```toml
[model."qwen2.5:7b"]
supports_tool_use = true   # 强制启用
# supports_tool_use = false  # 强制禁用
# 省略 = 自动检测
```

## ReAct 循环

Agent 模式的核心是 `AgentOrchestrator` 实现的 ReAct 循环：

```
System prompt + user/log message + tool schemas
│
└── LLM chat API
    │
    ├── 无 tool_calls
    │   └── final_answer → 返回给 Processor / DailyReport
    │
    └── 有 tool_calls
        ├── 解析 function name / arguments
        ├── 注入 agent_identity
        │   └── ActionRequest(actor_role, actor_id, api_key)
        ├── requires_approval?
        │   ├── 是 → 降级为审批 Issue
        │   └── 否 → ExecutorRuntime.execute()
        ├── 将 ExecutionResult 作为 tool observation 写回对话
        └── 进入下一轮，直到 final_answer / max_rounds / timeout / token_budget
```

### 终止条件

循环在以下任一条件满足时终止：

- **final_answer**: LLM 返回无 `tool_calls` 的响应
- **max_rounds**: 达到最大循环次数（默认 2）
- **timeout**: 超过总时间预算（默认 60s）
- **token_budget**: 累计 completion token 超过上限（默认 16384）

## 安全模型

### 凭据隔离

LLM **从不接触** API 密钥或认证信息。Orchestrator 持有 `agent_identity` 引用，在构造每个 `ActionRequest` 时注入凭据：

```
LLM → tool_call(name, params)
                ↓
Orchestrator → ActionRequest(name, params, actor_role, actor_id, api_key)
                ↓
Executor → PolicyEngine → Handler
```

### requires_approval

在 Agent 模式中，标记了 `requires_approval = true` 的能力（如 `create_github_pr`）不会由 Orchestrator 直接执行。Orchestrator 会自动将其降级为 GitHub issue 通知管理员审批。

### 反提示注入

系统提示中包含安全指令，要求 LLM 不将日志内容当作指令执行。

## 双模式集成

### 实时处理 (Processor)

`LogProcessor._build_update()` 根据 orchestrator 是否存在和模型是否支持 tool use 自动路由：

- 有 orchestrator + 支持 tool use → `_build_update_agent()`
- 其他情况 → `_build_update_pipeline()`

Agent 模式在 orchestrator 异常或未产生分析文本且未执行工具调用时回退到 Pipeline 模式。若 LLM 已经执行过工具调用但没有返回分析文本，系统会跳过该事件的 Pipeline 回退，避免重复创建 Issue 等副作用。

### 每日报告 (DailyReport)

- **多级分析**（段→通信对→最终报告）：始终使用文本模式，不需要 tool calling
- **规则生成**：支持双模式
  - Agent 模式：Orchestrator 驱动 "分析 → 生成规则 → 提交 → PR" 全流程
  - Pipeline 模式：传统 LLM 生成 JSON → 解析 → 逐步执行

### 启动通知

如果检测到模型不支持 tool calling，系统会发送一封邮件通知管理员当前运行在 Pipeline 模式下。

## 文件清单

| 文件 | 说明 |
|------|------|
| `src/backends/ollama.py` | Ollama `/api/show` tool-use 检测 |
| `src/backends/openai_compat.py` | OpenAI 兼容后端与 tool calling 支持声明 |
| `src/backends/deepseek.py` | 原生 DeepSeek `/chat/completions` 后端与 tool calling 支持声明 |
| `src/tool_schema.py` | Capability → function tool schema 翻译器 |
| `src/orchestrator.py` | ReAct 循环 Orchestrator |
| `src/llm_handler.py` | `call_llm_chat()`, `supports_tool_use` 属性 |
| `src/llm_prompt.py` | Agent 模式提示词构建器 |
| `llm_prompt.toml` | `[realtime_agent]`, `[daily_report_agent]` 模板 |
| `src/processor.py` | 双模式路由 |
| `src/daily_report.py` | 双模式规则生成 |
| `src/main.py` | 启动时检测、Orchestrator 创建、回退通知 |
