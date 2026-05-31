<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         rmi.md
Description:  Remote Management Interface (RMI) API endpoint and protocol reference.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# 远程管理接口 (RMI)

## 概述

RMI（Remote Management Interface）是基于 FastAPI 的 REST API，提供运行时状态查询和远程控制功能。默认监听 `0.0.0.0:8765`。

核心实现位于 `src/rmi.py`。

从 U-A-P 子系统引入后，除 `/health`、`/version`、`/login` 外的所有端点均需认证。详见 [认证与授权](auth.md)。

## 启用/禁用

在 `suricata-llm-agent.toml` 中配置：

```toml
[rmi]
enabled = true
host = "0.0.0.0"
port = 8765
```

## API 端点

### GET /health

健康检查。

**响应**：
```json
{
  "status": "ok"
}
```

---

### GET /version

返回软件版本信息。

**响应**：
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

返回当前生效的性能配置、当前 perf index、自适应调优细节和已加载的模型档案名称。`/perfcfgs` 是兼容别名。

**响应**：
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

返回实时处理统计。

**响应**：
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

> 为简洁起见，响应示例省略了 `30min`、`1h`、`6h`、`24h` 窗口的 token 字段，实际响应中均包含。

**字段说明**：

| 字段 | 说明 |
|------|------|
| `processed_total` | 启动以来累计处理的文档数 |
| `failed_total` | 累计失败数 |
| `perf_index` | 当前性能指数（0 ~ 999） |
| `pressure_score` | 归一化系统压力（0.0 ~ 1.0，原始 pressure 在性能调优日志和 adaptive 细节中保留） |
| `quality_factor` | 当前质量因子（0.0 ~ 1.0） |
| `effective_tps` | 当前有效 token 吞吐量（tokens/sec） |
| `{N}min_processed/failed/total` | 5 / 15 / 60 分钟滑窗处理量统计 |
| `token_total` | 启动以来累计 token 总量 |
| `token_total_prompt` | 启动以来累计 prompt token 总量 |
| `token_total_completion` | 启动以来累计 completion token 总量 |
| `{window}_prompt_tokens` | 对应窗口内的 prompt token 消耗（窗口：1min / 5min / 30min / 1h / 6h / 24h） |
| `{window}_completion_tokens` | 对应窗口内的 completion token 消耗 |
| `{window}_total_tokens` | 对应窗口内的 token 总消耗 |
| `avg_tokens_per_log` | 每条日志的平均 completion token 消耗（EMA 平滑，仅当自适应调优数据可用时返回） |

---

### POST /gen_report+{date}

手动触发指定日期的日报生成。生成在后台异步执行，调用方立即收到 `202 Accepted` 响应。
生成期间，实时分析自动暂停，完成后自动恢复。若已有日报正在生成，返回 `409 Conflict`。

**参数**：
- `date` — 日期字符串，格式 `YYYY-MM-DD`

**示例**：
```bash
curl -X POST http://localhost:8765/gen_report+2026-03-20 \
  -H "Authorization: Bearer $TOKEN"
```

**响应**（202 Accepted）：
```json
{
  "status": "accepted",
  "report_date": "2026-03-20",
  "detail": "Daily report generation started. Results will be delivered via email/PR."
}
```

**响应**（409 Conflict — 已有生成任务）：
```json
{
  "status": "busy",
  "report_date": "2026-03-20",
  "detail": "A daily report generation is already in progress."
}
```

日报生成在后台线程中执行，结果通过邮件和/或 PR 交付。

## 认证与管理端点

以下端点由 U-A-P 子系统提供，详细语义见 [认证与授权](auth.md)。

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| POST | `/login` | 无需认证 | 用户名/密码登录，返回 JWT |
| GET | `/me` | 任意已认证用户 | 查看当前用户信息 |
| GET/POST | `/me/apikeys` | 任意已认证用户 | 查看或创建自己的 API Key |
| GET/POST | `/users` | Owner | 用户列表与用户创建 |
| GET/PATCH/DELETE | `/users/{id}` | Owner | 用户详情、更新、删除 |
| GET/POST | `/users/{id}/apikeys` | Owner | 管理指定用户的 API Key |
| DELETE | `/apikeys/{id}` | Owner | 吊销 API Key |
| GET/PUT/DELETE | `/credentials/*` | Owner / Administrator | 管理 `llm_api_key`、`git_token`、`mail_client_id`、`mail_client_secret` |

`GET /credentials` 只返回当前已设置的可管理凭据键。`PUT /credentials/llm_api_key` 会把新值写入 `credentials.db`，同步更新运行中的 `config.LLM_BACKEND_AUTH_TOKEN`，并尝试更新 RMI 持有的活动后端；已按模型缓存的其他后端实例以重新创建或重启服务为边界。

## 流式端点

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| GET | `/log` | Owner / Administrator | Server-Sent Events 日志流，空闲 30 秒发送 keepalive |
| GET | `/stats/stream` | Owner / Administrator | 每 5 秒推送一次统计快照 |

## Executor 与微调端点

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| GET | `/executor/capabilities` | 任意已认证用户 | 列出已注册能力名称 |
| POST | `/executor/execute` | Owner / Administrator | 手动提交执行器请求 |
| GET | `/executor/audit` | Owner / Administrator | 查询最近审计记录 |
| GET | `/finetune/samples` | Owner / Administrator | 查询微调样本，可按 `status`、`threat_level` 过滤 |
| POST | `/finetune/samples/{sample_id}/label` | Owner / Administrator | 标注样本为 `confirmed`、`rejected` 或 `corrected` |
| POST | `/finetune/export` | Owner / Administrator | 按标签和日期范围导出 JSONL |

## 架构设计

### 后台任务与命令队列

`POST /gen_report+{date}` 不在 FastAPI 请求线程中同步执行日报生成。端点校验日期和忙碌状态后，启动名为 `gen-report-manual` 的 daemon 后台线程调用 `DailyReportService.generate_and_send(..., force=True)`，并立即返回 `202 Accepted`：

```
FastAPI / Uvicorn thread
│
├── POST /gen_report+YYYY-MM-DD
├── _admin_plus 认证授权
├── 日期解析
│
├── daily_report_active = true
│   └── 409 busy
│
└── daily_report_active = false
    ├── 启动 daemon thread: gen-report-manual
    │   └── DailyReportService.generate_and_send(force=True)
    └── 202 Accepted
```

`RemoteCommandQueue` 仍保留在线程安全队列和主循环 `apply_remote_commands()` 中，但当前没有已注册的远程命令处理器；未知命令会返回 `unknown command`。因此现有手动日报路径不依赖该队列。

### 服务器生命周期

RMI 服务器以 daemon 线程运行；正常关闭时由主线程调用 `RmiServer.stop()`，进程异常退出时 daemon 线程随进程结束：

```python
main.py → start_rmi_server() → RmiServer
                              └── uvicorn.Server in daemon Thread

shutdown → rmi_server.stop()
```

## 容器端口映射

在 `deploy.toml` 的 `[networking]` 中配置端口映射：

```toml
[networking]
port_mapping = { host_netseg = "127.0.0.1", host_port = 8765, container_port = 8765 }
```

默认将 RMI 端口绑定到 `127.0.0.1`，仅允许本机访问。如需远程访问，改为 `0.0.0.0` 或特定网段。
