<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         daily-report.md
Description:  Daily report generation process with multi-level LLM analysis flow.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# 日报系统

## 概述

日报系统在每天结束时自动生成 HTML 格式的安全分析报告，默认采用**多级 LLM 分析**架构：按通信对分组 → 按时间段分割 → 逐级分析 → 汇总成最终报告，然后保存到磁盘并通过邮件发送。为实验和消融对比，系统也支持 `pair_only` 和 `flat` 两种简化分析模式。

核心实现位于 `src/daily_report.py`。

## 触发条件

1. **自动触发**：主循环检测到日期边界（跨天 00:00），自动为前一天生成日报
2. **手动触发**：通过 RMI 端点 `POST /gen_report+YYYY-MM-DD` 指定任意日期

> **实时分析暂停**：日报生成期间，实时分析（`process_batch`）自动暂停，避免与日报 LLM 调用竞争模型和后端资源。生成完成后自动恢复。暂停状态通过线程安全的 `config.daily_report_active` 标志实现。

## 生成流程

```
DailyReportService.generate_and_send(report_date, force)
│
├── 非 force 且 daily_report.enabled=false → 跳过
│
├── set_daily_report_active()
│   └── 实时 process_batch() 看到该标志后返回空批次
│
└── _generate_and_send_inner()
    ├── fetch_daily_stats()
    ├── fetch_processed_summaries()
    │   └── 拉取当日 ai.processed=true 且包含 ai.summary 的文档
    ├── stop_ollama_model()（如当前实时模型已加载）
    │
    ├── 无 items
    │   └── build_daily_report_prompt() → call_daily_report_llm()
    │
    ├── analysis_mode = "flat"
    │   └── 当日全部摘要 → 单次 LLM → 全局报告
    │
    ├── analysis_mode = "pair_only"
    │   └── group_by_comm_pair()
    │       └── 每个通信对单次 LLM → 拼接各通信对分析
    │
    └── analysis_mode = "hierarchical"
        └── group_by_comm_pair()
            └── split_by_time_gap()
                └── _analyze_segment()
                    └── _analyze_pair()
                        └── build_final_report_prompt()
                            └── call_daily_report_llm()

输出阶段
├── build_report_html()
├── 插入 experiment_tag 横幅（如配置）
├── _save_report_html()
├── send_daily_report_email()（仅 enable_notification=true）
├── _run_rule_generation()（仅有 pair_results 且 git 启用）
└── clear_daily_report_active()
```

## 多级分析的设计理由

直接将一天的所有通信日志一次性喂给 LLM 存在以下问题：

1. **噪音干扰**：一天内不同通信方的日志相互无关，混在一起会导致 LLM 难以形成关联分析
2. **上下文限制**：即使使用大上下文模型，一天的日志量也可能超出窗口
3. **分析深度**：LLM 面对海量无关数据时，分析质量显著下降

多级方案通过**分类 → 分段 → 逐级汇总**解决了这些问题：

- **Level 1**（时间段）：关注短时间内同一通信对的行为模式
- **Level 2**（通信对）：综合看一对主机之间一整天的通信画像
- **Level 3**（全局）：在所有通信对的分析基础上做关联分析

## HTML 报告内容

生成的 HTML 报告包含：

| 区域 | 内容 |
|------|------|
| **统计概览** | 总事件数、AI 已处理数、时间范围 |
| **事件类型分布** | 各 event_type 的数量统计表 |
| **威胁等级分布** | N0 ~ N3 各级别的数量统计表 |
| **高/危事件详情** | 严重度较高的事件列表 |
| **通信对分析** | 每个通信对的 LLM 分析结果 |
| **全局关联分析** | Level 3 的最终日报内容 |
| **实验横幅** | 当 `daily_report.experiment_tag` 非空时，在报告顶部插入实验运行标记 |
| **元数据** | 报告日期、生成时间 |

## 配置

### suricata-llm-agent.toml 中的 [daily_report]

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
# 收件人不在此处配置，启用 U-A-P 后自动从用户数据库按角色查询。
```

| 选项 | 说明 |
|------|------|
| `enabled` | 是否启用日报 |
| `llm_config_file` | 日报专用 LLM 配置文件 |
| `fetch_size` | ES scroll 批次大小 |
| `session_gap` | 同一通信对内切分 segment 的空闲间隔（秒）。只有相邻事件间隔超过该值时才按时间切段 |
| `max_segment_events` | 单次 segment LLM 调用最多包含的事件数 |
| `output_dir` | HTML 报告保存目录 |
| `subject_prefix` | 邮件主题前缀 |
| `analysis_mode` | `hierarchical`、`pair_only` 或 `flat` |
| `experiment_tag` | 实验标签；非空时修改邮件主题并插入报告横幅 |

> 日报收件人启用 U-A-P 后自动从用户数据库按角色（Owner、Administrator、Watcher）查询，无需在此配置。

### analysis_mode — 分析模式

| 模式 | 流程 | 适用场景 |
|------|------|----------|
| `hierarchical` | 通信对分组 → 时间段分割 → segment 分析 → pair 分析 → 全局综合 | 默认生产路径，保留完整关联分析 |
| `pair_only` | 通信对分组 → 每个通信对单次分析 → 拼接输出 | 消融实验，保留通信对归类但不做时间段和全局综合 |
| `flat` | 对当天全部已处理且有摘要的事件做单次整体分析 | 扁平基线，成本低但关联结构最弱 |

### daily_report_llm_conf.toml

日报使用独立的 LLM 配置，通常选用更大的模型和更长的上下文：

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

> **向后兼容**：旧版 `OLLAMA_*` 前缀字段名仍可正常解析。

### detail_level — 事件详细程度

`detail_level` 控制日报 prompt 中每条事件包含多少信息：

| 级别 | 描述 | 每事件 prompt 内容 | ES 拉取范围 |
|------|------|-------------------|------------|
| `"minimal"` | 默认 | `[威胁等级] 时间戳 \| 摘要` | `ai.summary`, `ai.threat_level`, `@timestamp`, `event_type` |
| `"extended"` | 扩展 | 增加 event_type, proto, 端口, alert 签名, security_hint, TLS/DNS/HTTP 上下文 | 额外拉取 `alert.signature`, `src_port`, `dest_port`, `proto`, `ai.security_hint`, `tls.sni`, `dns.rrname`, `http.url` 等 |
| `"full"` | 完整 | 整个事件的原始 JSON | 完整 `_source` |

> **Token 消耗提示**：`extended` 和 `full` 模式会显著增加每次 LLM 调用的 token 消耗，从而延长日报生成时间。建议在模型上下文窗口充足且对分析深度有更高要求时使用。

当远程 OpenAI 兼容服务因内容安全策略返回 provider-specific `422` 时，segment 级分析会回退为结构化计数摘要，避免整份日报因单个通信段失败而中断。

日报分析相比实时分析需要处理更多文本，所以：
- `CONTEXT_LENGTH` 通常远大于实时分析（65536 vs ~16384）
- `MAX_TOKENS` 更大以允许更详细的分析输出（4096 vs ~512）
- 模型可以选择更大/更强的版本，不受实时性压力约束

## 统计数据拉取

`fetch_daily_stats()` 通过 ES 聚合查询获取全天统计：

- **总事件数** — 当日索引中的文档总数
- **AI 已处理数** — `ai.processed=true` 的文档数
- **事件类型分布** — 按 `event_type` 的 terms 聚合
- **威胁等级分布** — 按 `ai.threat_level` 的 terms 聚合
- **时间范围** — 最早和最晚的 `@timestamp`

日报明细数据由 `fetch_processed_summaries()` 从 `suricata-eve-YYYY.MM.DD` 日期索引滚动拉取，仅包含 `ai.processed=true`（或历史字符串映射下的 `"true"`）且存在 `ai.summary` 的文档。

## 报告后规则生成

若 `[git].enabled = true` 且执行器可用，日报生成完成后会筛选 `max_threat` 为「高」或「严重」的通信对，进入规则生成流程：

1. Agent 模式下由 `AgentOrchestrator` 基于 `daily_report_agent` prompt 决定是否调用工具。
2. Pipeline 模式下调用规则生成 prompt，解析 LLM 返回的 JSON 规则列表。
3. 每条规则通过 `suricata_rule_suggest` 进行轻量语法验证，可选使用 `suricata -T` 做中量验证。
4. 通过验证的规则由 `git_commit_and_push` 提交，并按配置创建 PR。
5. PR 创建后调用 `git_local_checkout_default` 清理本地工作树；远程同步和 fork force-push 只由定时 `git_repo_reset` 负责。
