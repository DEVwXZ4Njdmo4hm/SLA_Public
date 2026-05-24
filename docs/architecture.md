<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         architecture.md
Description:  System architecture with module dependency diagram and data flow overview.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# 架构概览

## 系统定位

Suricata LLM Agent 是一个实时 IDS 日志分析引擎，部署于 Suricata 和 Elasticsearch 之间的分析层，利用本地 Ollama 或 OpenAI 兼容 LLM 后端对网络安全事件进行自动化威胁评估。

```
┌──────────┐   eve.json   ┌─────────────────┐
│ Suricata │─────────────▶│ Elasticsearch   │
└──────────┘              │ Suricata index  │
                          └────────▲────────┘
                                   │ scroll 查询 / bulk 回写 ai.*
                                   │
┌──────────────────────────────────┴──────────────────────────────────┐
│ Suricata LLM Agent                                                   │
│ main.py 主循环                                                        │
│ ├─ processor.py: 实时批处理、记忆更新、升级分析、自动 Issue               │
│ ├─ daily_report.py: 日报、规则生成、邮件发送                            │
│ ├─ rmi.py: FastAPI 管理接口、SSE 日志、手动日报触发                      │
│ └─ executor/: U-A-P 策略、PathGuard、审计、Git/规则 handler            │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │ chat / generate
                                   ▼
                    ┌──────────────────────────────┐
                    │ LLM backends                 │
                    │ Ollama / OpenAI-compatible   │
                    │ per-model routing + limiter  │
                    └──────────────────────────────┘
```

系统支持混合后端：不同模型可使用不同后端（本地 Ollama / 远程 OpenAI 兼容 API），通过 `ModelProfiles.toml` 中的 `backend_type` 按模型路由。

## 模块依赖关系

```
main.py                              # 入口、启动编排、主循环
├── config.py                        # 全局配置与模型档案
├── logging_utils.py                 # 日志、ES 日志 handler、统计快照
├── auth/                            # U-A-P 用户、角色、JWT、API Key
│   ├── database.py                  # SQLite 用户/凭据存储
│   ├── dependencies.py              # FastAPI 认证依赖
│   ├── bootstrap.py                 # 运行期 Agent 身份引导/撤销
│   └── log_broadcast.py             # SSE 日志广播
├── executor/                        # 受控副作用执行层
│   ├── registry.py                  # configs/capabilities/*.toml
│   ├── policy.py                    # 角色、参数、速率、身份校验
│   ├── path_guard.py                # 文件系统边界
│   ├── runtime.py                   # 执行编排与审计
│   └── handlers/                    # GitHub、git、Suricata 规则 handler
├── llm_handler.py                   # LLM 调用、记忆、JSON 解析、Agent identity
│   ├── llm_prompt.py                # Prompt 模板渲染
│   ├── global_memory.py             # 全局 FIFO / 滚动压缩记忆
│   ├── comm_proto_pair_memory.py    # 协议-通信对分桶记忆
│   ├── llm_backend.py               # 后端协议与 token 指标
│   └── backends/                    # Ollama / OpenAI 兼容 / 限速
├── orchestrator.py                  # Agent 模式 ReAct 循环
│   └── tool_schema.py               # Capability → function tool schema
├── processor.py                     # 实时批处理
│   ├── pre_process.py               # ES 查询构建与事件过滤
│   └── es_client.py                 # ES 读取、计数、bulk 回写
├── daily_report.py                  # 日报、规则生成、HTML 输出
│   ├── es_client.py                 # 日报数据拉取
│   ├── llm_prompt.py                # 日报/规则 prompt
│   └── mailer/                      # 日报邮件发送
├── rmi.py                           # FastAPI 管理面与手动日报后台线程
└── perf_cacl.py                     # 自适应性能调优
```

## 核心数据流

### 实时分析流

```
main.py 主循环
│
├─ 日期边界检查：必要时调用 DailyReportService.generate_and_send()
├─ apply_remote_commands()：当前仅保留队列框架，未注册远程命令处理器
└─ processor.process_batch(index)
   │
   ├─ daily_report_active 为 true 时直接跳过本轮实时处理
   │
   ├─ es_client.get_unprocessed_docs()
   │  └─ pre_process.py 构建 bool 查询，拉取未处理文档
   │
   ├─ ThreadPoolExecutor / 单线程调用 _build_update()
   │  │
   │  ├─ Agent 路径：orchestrator 存在且模型支持 tool calling
   │  │  ├─ get_memory_snapshot() 读取通信对 / Event_Z 记忆
   │  │  ├─ AgentOrchestrator.run(tools=create_github_issue)
   │  │  ├─ tool_call 由 ExecutorRuntime 执行
   │  │  └─ final_answer 解析为 ai 字段
   │  │
   │  └─ Pipeline 路径：llm_handler.generate_advice()
   │     ├─ get_backend_for_model() 按模型路由到后端
   │     └─ 解析 JSON 响应
   │
   ├─ _maybe_escalate()：可选升级模型重分析并覆盖初步结论
   ├─ update_summary_memory()：写入配置指定的记忆结构
   ├─ 副作用处理
   │  ├─ Pipeline：_maybe_create_issue() 按阈值调用 Executor
   │  └─ Agent：Issue 等副作用已由 tool_call 触发
   └─ es_client.bulk_update_ai_advice()
      └─ 回写 ai.advice、ai.processed、ai.processed_at 与 ai.* 字段
```

### 日报生成流

```
main.py 日期边界 / RMI 手动触发
│
└─ DailyReportService.generate_and_send(report_date, force)
   ├─ set_daily_report_active()：暂停实时 process_batch()
   ├─ fetch_daily_stats()
   ├─ fetch_processed_summaries()
   │
   ├─ analysis_mode
   │  ├─ flat
   │  │  └─ build_daily_report_prompt() → call_daily_report_llm()
   │  ├─ pair_only
   │  │  └─ group_by_comm_pair() → 每个通信对单次 LLM → 拼接输出
   │  └─ hierarchical
   │     └─ group_by_comm_pair()
   │        └─ split_by_time_gap()
   │           └─ _analyze_segment() → _analyze_pair() → final report LLM
   │
   ├─ build_report_html()
   ├─ _save_report_html()
   ├─ send_daily_report_email()：仅在 enable_notification=true 时执行
   ├─ _run_rule_generation()：仅当存在 pair_results 且启用 git 时执行
   └─ clear_daily_report_active()：恢复实时处理
```

### 性能调优流

```
process_batch() 返回 llm_metrics / fetched / backlog
│
├── token_window.record()：统计 RMI 展示用 token 速率
│
└── AUTO_PERF_SELECT=true
    ├── record_token_stats()：更新各模型吞吐估计
    ├── perf_index_predict()：按本轮观测和 backlog 预测压力
    ├── adaptive_select()：计算目标 ModelProfile
    └── 配置变化时切换 CURRENT_PERF_CONFIG
        └── 如模型名改变，先 stop_ollama_model(current_model)
```

## 线程模型

```
┌─────────────────────────────────────────────────┐
│                Main Thread                       │
│  main() 主循环                                   │
│  ├── process_batch()                             │
│  ├── 自动日报检查 & 生成                          │
│  ├── apply_remote_commands()                     │
│  ├── adaptive_select() 性能调优                   │
│  └── emit_stats_snapshot() 统计上报               │
└─────────────────────────────────────────────────┘

┌────────────────────────┐  ┌────────────────────────┐
│ ThreadPoolExecutor     │  │ RMI Server Thread      │
│ process_batch 内创建    │  │ FastAPI + Uvicorn      │
│ 并发 LLM / Agent 调用   │  │ REST API / SSE 日志     │
└────────────────────────┘  └────────────────────────┘

┌────────────────────────┐  ┌────────────────────────┐
│ Manual Report Thread   │  │ MailQueue Thread       │
│ POST /gen_report+date  │  │ 启用邮件时后台重试失败邮件│
│ daemon 后台生成日报     │  │                        │
└────────────────────────┘  └────────────────────────┘

┌────────────────────────┐
│ ES Log Handler Thread  │
│ 异步批量写入日志到 ES    │
└────────────────────────┘
```

**线程安全机制**：

| 资源 | 保护方式 |
|------|---------|
| `CURRENT_PERF_CONFIG` | `threading.Lock` (`_perf_config_lock`) |
| `CommPairMemory` | 内部 `Lock` |
| `GlobalMemory` | 内部 `Lock` |
| `CommProtoPairMemory` | 内部 `Lock` |
| `RemoteCommandQueue` | 内部 `Lock` |
| `MailQueue` | 内部 `Lock` |
| `LLMMetrics` 批次累积 | `threading.Lock` |
| `StatsWindow` | `threading.Lock` |
| `TokenStatsWindow` | `threading.Lock` |
| ES 日志 Handler | `queue.Queue`（无锁生产者-消费者） |

## 生命周期

```
启动
 ├── 加载配置、Prompt 模板和模型档案 (config.py / llm_prompt.py)
 ├── 初始化日志系统 (logging_utils.py)
 ├── 打开 U-A-P 凭据数据库并加载服务凭据
 ├── 初始化 Executor 与 Agent identity（如启用）
 ├── 创建 LLM 后端与 Agent Orchestrator（如启用）
 ├── 初始化微调样本库（如启用）
 ├── 初始化 Git 工作区（如启用）
 ├── 发送启动通知邮件
 ├── 初始化邮件队列 (mail_queue.py)
 ├── 初始化 SSE 日志广播
 ├── 启动 RMI 服务器 (rmi.py)
 ├── 连接 ES & 健康检查 (es_client.py)
 ├── 确保 AI 字段映射 (es_client.py)
 └── 进入主循环
       ├── 轮询处理 batch
       ├── 检查日期边界 → 触发日报
       ├── 执行远程命令
       ├── 性能调优
       └── 统计快照
 
关闭 (SIGINT/SIGTERM)
 ├── GracefulShutdown 标志置位
 ├── 停止 RMI server
 ├── 撤销运行期 Agent 身份
 ├── 关闭 U-A-P / Executor 数据库
 ├── 停止邮件队列（flush 暂存）
 ├── 发送关闭通知邮件
 ├── flush ES 日志 Handler
 └── 退出
```

## 事件过滤体系

`pre_process.py` 构建的 Elasticsearch bool 查询实现了多层事件过滤：

| 过滤维度 | 说明 |
|----------|------|
| **event_type** | 仅处理 `allowed_event_types` 中列出的事件类型（alert, dns, http, tls, flow 等） |
| **L3 协议** | IPv4 / IPv6 过滤 |
| **L4 协议** | TCP / UDP / ICMP 等过滤 |
| **L7 协议** | 应用层协议过滤 |
| **Alert 严重度** | 按 `minimal_alert_severity` 过滤（1=高, 2=中, 3=低） |
| **DNS** | 按 rcode (NXDOMAIN, SERVFAIL, REFUSED) 和 rrtype (ANY, TXT) 过滤 |
| **HTTP** | 按 status code (≥400) 和异常方法 (PUT, DELETE, TRACE, CONNECT 等) 过滤 |
| **TLS** | 按版本 (SSLv3, TLSv1, TLSv1.1)、SNI 缺失、JA3/JA3S 恶意指纹过滤 |

## 通信对 (Communication Pair) 机制

通信对是本系统的核心归类概念，贯穿实时分析和日报生成两个流程。

**归类规则**：
1. 以双方的 **hostname** 为主键（如 `hostA ↔ hostB`）
2. 若某方 hostname 为空，降级使用 **IP 地址**
3. 双向等价：`A→B` 和 `B→A` 属于同一通信对
4. 通过对双方标识排序生成规范化的 pair key

**实时记忆**：
- `pair` / `pair_rolling`：按双向通信对保存记忆，滚动模式在达到阈值后调用 LLM 合并旧条目
- `global` / `global_rolling`：所有事件共享全局记忆，适合作为消融或全局上下文基线
- `proto_pair` / `proto_pair_rolling`：先按通信对分桶，再按 `app_proto` 或 `event_type` 形成 Event_Z 子桶
- `none`：完全禁用实时记忆
- 记忆容量由 `llm.memory_max_pairs`、`llm.memory_per_pair_length`、`llm.memory_length` 和滚动压缩参数控制

**日报分组**：
- 按通信对归类后，进一步按时间间隔（默认 1800 秒）分割为时间段
- `hierarchical` 模式实现逐级分析：时间段 → 通信对 → 全局日报
- `pair_only` 保留通信对分组但跳过时间段和全局综合；`flat` 直接对当天全部已处理且有摘要的事件做单次整体分析
