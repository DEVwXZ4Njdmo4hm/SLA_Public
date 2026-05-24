<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         llm-prompt-config.md
Description:  LLM prompt template configuration with variable syntax reference.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# LLM Prompt 配置

## 概述

所有 LLM 提示词模板外置于 `llm_prompt.toml`，支持独立修改而无需接触源代码。模板使用 Python `str.format_map()` 语法进行变量替换，未识别的占位符会被安全保留。

核心实现位于 `src/llm_prompt.py`。

## 模板文件结构

```toml
# llm_prompt.toml

[shared]
shared_prompt = """..."""       # 共享上下文（网络环境 + N0-N3 规则），可选

[realtime]
template = """..."""            # 实时分析 prompt
                                # 可用 {system_prompt_end} 将 system 与 user 内容分割

[realtime_agent]
system_template = """..."""     # Agent 模式实时分析系统 prompt
user_template = """..."""       # Agent 模式实时分析用户 prompt

[memory_compact]
template = """..."""            # 滚动记忆压缩 prompt

[daily_report_agent]
system_template = """..."""     # 日报规则生成 Agent 系统 prompt
user_template = """..."""       # 日报规则生成 Agent 用户 prompt

[rule_generation]
template = """..."""            # 日报规则生成 pipeline prompt

[daily_report.segment]
template = """..."""            # 日报：时间段级分析

[daily_report.pair]
template = """..."""            # 日报：通信对级分析

[daily_report.final]
template = """..."""            # 日报：最终报告

[daily_report.legacy]
template = """..."""            # 日报：传统单次分析（后备）

[escalation]
template = """..."""            # 升级处理：深度威胁二次分析
```

## 共享 Prompt 片段 ([shared])

`[shared].shared_prompt` 存放所有分析模板共用的上下文信息，通过 `{shared_prompt}` 占位符注入到 `realtime`、`realtime_agent`、`escalation`、`daily_report_agent` 及所有 `daily_report.*` 模板中。

典型内容包括：
- **网络环境**：内网网段、域名后缀、关键设备拓扑（代理、VPN 等）
- **威胁等级定义**：无危、低、中、高、严重
- **N0-N3 噪音分类规则**：优先级递减的威胁判断规则表

此字段为**可选**：`[shared]` 整个 section 可省略，或 `shared_prompt` 可为空字符串。省略时所有模板中的 `{shared_prompt}` 会被替换为空。

## 模板变量语法

使用 `{variable_name}` 作为占位符：

```
事件类型: {event_type}
源: {src_hostname}({src_ip}):{src_port}
```

**安全替换**：通过 `_SafeDict`，未匹配的占位符保持原样而非抛出 KeyError。这允许在模板中包含未来可能扩展的变量而不影响当前功能。

**JSON 字面量**：模板中的 JSON 样例需要双花括号转义：

```
返回以下JSON：
{{
  "summary": "...",
  "threat_level": "..."
}}
```

## 实时分析 Prompt ([realtime])

### 可用变量

| 变量 | 来源 | 说明 |
|------|------|------|
| `{event_type}` | ES 文档 | 事件类型（alert, dns, http, tls 等） |
| `{timestamp}` | ES 文档 | 事件时间戳 |
| `{src_ip}` | ES 文档 | 源 IP |
| `{src_port}` | ES 文档 | 源端口 |
| `{src_hostname}` | ES 文档 | 源主机名（可能为空） |
| `{src_city}` | GeoIP | 源城市 |
| `{src_country}` | GeoIP | 源国家 |
| `{src_asn}` | GeoIP | 源 ASN |
| `{dest_ip}` | ES 文档 | 目标 IP |
| `{dest_port}` | ES 文档 | 目标端口 |
| `{dest_hostname}` | ES 文档 | 目标主机名 |
| `{dest_city}` | GeoIP | 目标城市 |
| `{dest_country}` | GeoIP | 目标国家 |
| `{dest_asn}` | GeoIP | 目标 ASN |
| `{proto}` | ES 文档 | 协议 |
| `{alert}` | ES 文档 | 告警规则签名 |
| `{severity}` | ES 文档 | 告警严重度 |
| `{is_noise}` | 预处理 | 是否判定为噪音 |
| `{memory_block}` | 当前记忆模式 | 当前事件可见的历史记忆条目；来源随 `llm.memory_mode` 在通信对、全局、协议-通信对子桶或空记忆之间切换 |

### Prompt 结构

实时分析 prompt 包含以下主要区域：

1. **角色定义** — 网络安全专家
2. **共享上下文** — 通过 `{shared_prompt}` 注入网络环境、威胁等级定义和 N0-N3 规则
3. **当前日志** — 使用变量注入的事件详情
4. **历史记忆** — 同一通信对的近期分析摘要
5. **输出格式** — JSON 格式要求

Pipeline 模式通过 `build_pipeline_messages()` 调用 chat 接口，返回 `system` / `user` 两条消息。模板中的 `{system_prompt_end}` 是推荐分割点：标记之前作为 system prompt，标记之后作为当前日志与记忆上下文。缺少该标记时，代码会用第一个事件字段位置做后备分割。

Agent 模式使用 `[realtime_agent]` 的 `system_template` 和 `user_template`，并把 `src/tool_schema.py` 构造出的函数工具描述传给支持 tool calling 的后端。

### 威胁等级规则体系

规则按优先级分为 4 级（N0 最高 → N3 最低）：

| 级别 | 优先级 | 典型规则 |
|------|--------|---------|
| **N0** | 最高 | 噪音 → 无危 |
| **N1** | 次高 | 特定主机对的已知行为模式、外部 SSH 直连内网 → 严重 |
| **N2** | 中等 | 代理回源正常流量、监控流量、知名云服务 → 无危 |
| **N3** | 最低 | 基于 alert severity 的默认映射 |

高优先级规则覆盖低优先级规则。

## 日报 Prompt

日报有三种分析模式，由主配置 `suricata-llm-agent.toml` 的 `[daily_report].analysis_mode` 控制：

| 模式 | 使用模板 |
|------|----------|
| `hierarchical` | `[daily_report.segment]` → `[daily_report.pair]` → `[daily_report.final]` |
| `pair_only` | `[daily_report.legacy]`（每个通信对一次） |
| `flat` | `[daily_report.legacy]` |

### 时间段分析 ([daily_report.segment])

| 变量 | 说明 |
|------|------|
| `{host_a}` | 通信对一方 |
| `{host_b}` | 通信对另一方 |
| `{time_start}` | 时间段起始 |
| `{time_end}` | 时间段结束 |
| `{event_count}` | 该段内事件数 |
| `{event_summaries}` | 事件摘要列表 |

输出要求：200 字以内的纯文本分析。

### 通信对分析 ([daily_report.pair])

| 变量 | 说明 |
|------|------|
| `{host_a}` | 通信对一方 |
| `{host_b}` | 通信对另一方 |
| `{segment_count}` | 时间段数量 |
| `{segment_analyses}` | 各时间段分析结果的汇总 |

输出要求：400 字以内的纯文本分析，包含通信模式、行为特征、安全风险。

### 最终报告 ([daily_report.final])

| 变量 | 说明 |
|------|------|
| `{report_date}` | 报告日期 |
| `{total_events}` | 原始事件总数 |
| `{ai_processed_count}` | AI 已处理数 |
| `{ai_has_summary_count}` | 有摘要的事件数 |
| `{time_min}` / `{time_max}` | 数据时间范围 |
| `{pair_count}` | 通信对总数 |
| `{event_type_breakdown}` | 事件类型分布表 |
| `{threat_level_breakdown}` | 威胁等级分布表 |
| `{pair_analyses}` | 所有通信对分析结果 |

输出要求：HTML 片段（不含 `<html>/<head>/<body>` 标签），包含总体概览、风险趋势、重点通信对分析、关联分析、建议措施。

### 传统模式 ([daily_report.legacy])

单次分析已处理摘要列表的后备模板。`flat` 模式对当天全部已处理且有摘要的事件调用一次；`pair_only` 模式按通信对分组后对每组调用一次。变量与 final 类似，但接收 `{summary_list}`（事件摘要列表）和 `{high_event_count}` 而非 `{pair_analyses}`。

## 日报规则生成 Prompt

日报生成完成后，若 `[git].enabled = true` 且执行器已初始化，系统会基于高危通信对尝试生成 Suricata 规则。

### Agent 模式 ([daily_report_agent])

当所选模型支持 tool calling 且未禁用 Agent 模式时，规则生成使用 `[daily_report_agent]`：

| 变量 | 说明 |
|------|------|
| `{report_date}` | 报告日期 |
| `{high_pairs_text}` | 高危/严重通信对分析文本 |
| `{existing_sids_text}` | 仓库中已存在的 SID 列表 |

LLM 只负责决定是否调用工具；实际的 `suricata_rule_suggest`、`git_commit_and_push`、`create_github_pr` 等动作由本地 executor 校验权限、参数 schema 和审计策略后执行。

### Pipeline 模式 ([rule_generation])

当 Agent 模式不可用时，系统使用 `[rule_generation]` 生成 JSON 规则建议，再由本地代码调用 `suricata_rule_suggest` 写入规则文件。

| 变量 | 说明 |
|------|------|
| `{analysis_summary}` | 日报分析摘要 |
| `{high_threat_pairs}` | 高危/严重通信对列表 |
| `{existing_sids}` | 已存在 SID 列表 |

后续 Git 流程由代码固定编排：提交、推送、创建 PR，然后调用 `git_local_checkout_default` 清理本地工作树。远程分支同步由定时 `git_repo_reset` 负责。

## 记忆压缩 Prompt ([memory_compact])

当 `[llm].memory_mode` 使用 `pair_rolling`、`global_rolling` 或 `proto_pair_rolling` 时，系统会在记忆条目超过阈值后调用 `[memory_compact]` 模板压缩最旧的若干条记录。

| 变量 | 说明 |
|------|------|
| `{entry_count}` | 本次压缩的条目数量 |
| `{pair_key}` | 记忆桶标识；global 模式下为全局桶标识，proto-pair 模式下包含通信对与 Event_Z 子桶 |
| `{entries_text}` | 待压缩的历史记录列表 |

压缩调用使用当前实时分析模型和当前 LLM 后端配置，因此模板应保持短输出，避免压缩本身成为主要 token 消耗来源。

## 升级处理 Prompt ([escalation])

当实时分析的初步威胁等级达到或超过 `[llm.escalation].threat_threshold` 时，系统使用升级模型进行二次深度分析。升级 prompt 由 `build_escalation_prompt()` 构建。

### 可用变量

| 变量 | 来源 | 说明 |
|------|------|------|
| `{raw_event_block}` | ES 文档 | 原始事件信息。受 `include_raw_fields` 配置控制：启用时包含完整字段（alert、TLS、DNS、HTTP 等），禁用时仅包含通信对标识和事件类型 |
| `{initial_analysis}` | 初步分析 | 主模型的原始输出文本（未解析的 JSON 字符串） |
| `{memory_block}` | 当前记忆模式 | 该事件可见的历史记录（格式同实时分析 memory_block） |

### Prompt 结构

1. **角色定义** — 高级网络安全分析师
2. **原始事件信息** — `{raw_event_block}`
3. **初步分析结果** — `{initial_analysis}`
4. **通信对历史** — `{memory_block}`
5. **输出格式** — 与实时分析相同的 JSON 结构（summary, threat_level, security_hint, recommendation）
6. **分析指导** — 纠正初步判断、关联历史记录、识别攻击模式

---

## detail_level 对日报 Prompt 的影响

`daily_report_llm_conf.toml` 中的 `detail_level` 选项控制 `build_segment_prompt()` 中 `{event_summaries}` 变量的格式化方式：

| 级别 | 每条事件格式 | 适用场景 |
|------|------------|----------|
| `"minimal"` | `- [威胁等级] 时间戳 \| 摘要` | 默认，token 消耗最低 |
| `"extended"` | `- [威胁等级] 时间戳 \| 事件类型 \| 协议 \| 端口 \| 摘要 [alert: 签名] [hint: 提示] [sni: ...] [dns: ...] [url: ...]` | 需要更多网络上下文时 |
| `"full"` | 完整 `_source` 的缩进 JSON | 需要最完整信息时，token 消耗显著增加 |

> **注意**：`detail_level` 同时影响 ES 数据拉取范围——`extended` 会额外请求 alert、端口、协议、TLS/DNS/HTTP 字段，`full` 请求整个 `_source`。更高的 detail_level 会显著增加日报生成的 token 消耗和延迟。

---

## 自定义指南

### 修改网络环境

编辑 `[shared].shared_prompt` 中的"网络环境"部分，替换为你的实际网络拓扑。此内容会通过 `{shared_prompt}` 自动注入到实时分析、升级分析和日报分析的所有 prompt 中：

```toml
[shared]
shared_prompt = """
# 网络环境
- 内网网段：10.0.0.0/8
- 内网域名后缀：.corp.example.com
- ...
"""
```

### 修改威胁判断规则

编辑 `[shared].shared_prompt` 中的 N0 ~ N3 规则表。规则使用 Markdown 表格格式，LLM 能准确理解：

```
| 条件 | 指令 |
|------|------|
| your-condition | → threat_level |
```

### 调整输出格式

修改"输出要求"部分。实时分析的 JSON 字段目前为：

- `summary` — 事件概述（≤150 字）
- `threat_level` — 威胁等级
- `security_hint` — 安全含义（≤80 字）
- `recommendation` — 建议措施（≤100 字）

> **注意**：如果更改 JSON 字段名，需同步修改 `llm_handler.py` 中 `parse_json_sections()` 的解析逻辑。

## 配置引用

在 `suricata-llm-agent.toml` 中指定 prompt 文件路径：

```toml
[llm]
prompt_file = "llm_prompt.toml"
```

该路径会被部署系统的预检机制自动发现（通过 `x-deploy-file: true` schema 扩展），无需手动添加到 `deploy.toml` 的 `extra_files` 中。
