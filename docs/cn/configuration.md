<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         configuration.md
Description:  Configuration files reference for all TOML settings and their options.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# 配置参考

本文档详细说明 Suricata LLM Agent 涉及的所有配置文件。所有配置均使用 TOML 格式，由部署系统通过 JSON Schema 进行预检验证。

---

## 配置文件总览

| 文件 | 用途 | Schema 约束 |
|------|------|-------------|
| `suricata-llm-agent.toml` | 主配置文件 | `agent-config.schema.json` |
| `llm_prompt.toml` | LLM 提示词模板 | `llm-prompt.schema.json` |
| `ModelProfiles.toml` | 模型性能基准档案 | `model-profiles.schema.json` |
| `daily_report_llm_conf.toml` | 日报专用 LLM 参数 | 由主配置引用 |
| `suspicious_ja3.toml` | 可疑 JA3 指纹列表 | `ja3-list.schema.json` |
| `suspicious_ja3s.toml` | 可疑 JA3S 指纹列表 | `ja3s-list.schema.json` |
| `secrets.toml` | 服务凭据（ES、Git、LLM、Mail、JWT 等，部署用） | `secrets.schema.json` |
| `deploy.toml` | 部署系统配置 | `deploy-config.schema.json` |

---

## suricata-llm-agent.toml — 主配置

### [elasticsearch]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `host` | string | `"http://elasticsearch:9200"` | Elasticsearch 地址 |
| `user` | string | — | ES 用户名（存储在 `credentials.db` 中，或在配置文件中设置） |
| `password` | string | — | ES 密码（存储在 `credentials.db` 中，或在配置文件中设置） |
| `index_pattern` | string | `"suricata-eve-*"` | ES 索引模式，支持日期通配 |

> 在容器化部署中，`user` 和 `password` 存储在 `credentials.db` 中，由部署脚本写入，启动时自动加载，无需在配置文件中明文写入。

### [processing]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `batch_size` | integer | `50` | 每次批处理拉取的最大文档数 |
| `poll_interval` | integer | `5` | 轮询间隔（秒） |
| `max_retries` | integer | `3` | 处理失败时的最大重试次数 |
| `retry_interval` | integer | `10` | 重试间隔（秒） |
| `empty_runs_before_index_refresh` | integer | `50` | 连续空批次后刷新索引的阈值 |

### [filter]

**支持的类型/协议**（定义了系统可识别的完整集合）：

| 选项 | 说明 |
|------|------|
| `supported_event_types` | Suricata 事件类型全集（alert, dns, http, tls, ssh, smtp, ftp 等） |
| `supported_l7_protocols` | 应用层协议全集 |
| `supported_l4_protocols` | 传输层协议全集（tcp, udp, icmp, icmpv6, sctp） |
| `supported_l3_protocols` | 网络层协议全集（ipv4, ipv6, arp） |

**实际处理的子集**（空数组 = 使用对应的 supported 全集）：

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `allowed_event_types` | `["alert", "ssh", "rdp", "smb", "dns", "http", "tls"]` | 实际处理的事件类型 |
| `allowed_l7_protocols` | （多数 L7 协议） | 实际处理的应用层协议 |
| `allowed_l4_protocols` | `["tcp", "udp", "icmp", "icmpv6"]` | 实际处理的传输层协议 |
| `allowed_l3_protocols` | `["ipv4", "ipv6"]` | 实际处理的网络层协议 |

**Alert 过滤**：

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `minimal_alert_severity` | integer | `2` | 最低告警严重度（1=高, 2=中, 3=低） |

**DNS 过滤**：

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `dns_rcodes` | string[] | `["NXDOMAIN", "SERVFAIL", "REFUSED"]` | 触发分析的 DNS 响应码 |
| `dns_rrtypes` | string[] | `["ANY", "TXT"]` | 触发分析的 DNS 查询类型 |

**HTTP 过滤**：

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `http_status_min` | integer | `400` | 触发分析的最低 HTTP 状态码 |
| `http_methods` | string[] | `["PUT", "DELETE", "TRACE", ...]` | 触发分析的异常 HTTP 方法 |

**TLS 过滤**：

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `tls_versions` | string[] | `["SSLv3", "TLSv1", "TLSv1.1"]` | 触发分析的过时 TLS 版本 |
| `tls_require_sni` | boolean | `true` | 缺少 SNI 时触发分析 |
| `ja3_hashes_file` | path | `"suspicious_ja3.toml"` | 可疑 JA3 指纹列表文件 |
| `ja3s_hashes_file` | path | `"suspicious_ja3s.toml"` | 可疑 JA3S 指纹列表文件 |

### [llm]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `prompt_file` | path | `"llm_prompt.toml"` | LLM 提示词模板文件 |
| `memory_length` | integer | `50` | 全局记忆长度；`global` / `global_rolling` 模式使用，通信对模式主要由 `memory_per_pair_length` 控制 |
| `memory_max_pairs` | integer | `50` | 最大通信对数量 |
| `memory_per_pair_length` | integer | `20` | 每对最大记忆条数（模板示例通常设为 50） |
| `memory_mode` | string | `"pair"` | 记忆模式：`pair`、`global`、`none`、`pair_rolling`、`global_rolling`、`proto_pair`、`proto_pair_rolling` |
| `memory_lat_lru_evict_seconds` | number | `3600.0` | `proto_pair` 模式下按最后活跃时间淘汰一级通信对桶的阈值 |
| `memory_maxpair_lru_evict` | integer | `0` | `proto_pair` 达到 `memory_max_pairs` 时淘汰的最旧通信对桶数量，`0` 表示自动计算 |
| `memory_compact_threshold` | integer | `10` | 滚动压缩模式触发 LLM 合并摘要的条数阈值 |
| `memory_compact_batch` | integer | `8` | 每次合并最旧的条目数量，必须小于 `memory_compact_threshold` |
| `memory_compact_cooldown` | number | `2.0` | `global_rolling` 成功压缩后的冷却时间（秒） |

滚动压缩模式使用 `llm_prompt.toml [memory_compact]` 模板调用当前实时分析模型，把最旧的若干记忆条目合并为一条 `[合并摘要]`。`proto_pair` / `proto_pair_rolling` 以通信对为一级桶，再以 `app_proto` 或 `event_type` 形成 Event_Z 子桶；当启用这两个模式时，`memory_max_pairs` 必须不小于 3。

### [llm.backend]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `type` | string | `"ollama"` | 后端类型：`"ollama"`（本地推理）或 `"openai"`（OpenAI 兼容 API，涵盖 OpenAI、Azure OpenAI、vLLM） |
| `base_url` | string | — | 全局 OpenAI 兼容 API 地址。全局后端为 `ollama` 时使用 `[ollama].base_url`；单个模型仍可通过 `ModelProfiles.toml` 的 `backend_base_url` 覆盖自身后端地址 |
| `auth_token` | string | — | Bearer 令牌 / API Key。建议通过 `credentials.db`（`llm_api_key` 键）或环境变量 `SURICATA_LLM_API_KEY` 管理，此处仅作开发阶段的临时覆盖 |

> **API Key 加载优先级**（高→低）：环境变量 `SURICATA_LLM_API_KEY` → `credentials.db` 中的 `llm_api_key` → 配置文件 `auth_token`。

**[llm.backend.vllm_metrics]**（可选）：

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `prometheus_url` | string | — | vLLM Prometheus `/metrics` 端点 URL。仅当 `type = "openai"` 且后端为 vLLM 时有意义。用于精细化性能采集（并发请求数、吞吐量、GPU 缓存利用率） |

> **数据出境警告**：当 `type = "openai"` 且 `base_url` 指向非本地地址时，系统将在首次调用时记录警告日志。日志数据将发送至外部服务，请确保符合数据处理政策。

### [llm.escalation]

升级处理：当主模型的初步威胁评估达到或超过阈值时，将该日志连同通信对历史上下文"升级"到更高级的模型进行二次深度分析。

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | `false` | 是否启用升级处理 |
| `threat_threshold` | string | `"中"` | 触发升级的最低威胁等级。可选值：`"无危"`、`"低"`、`"中"`、`"高"`、`"严重"` |
| `model` | string | — | 升级处理用的模型名（必须在 `ModelProfiles.toml` 中声明） |
| `max_tokens` | integer | `4096` | 升级模型的最大生成 token 数 |
| `context_length` | integer | `65536` | 升级模型的上下文长度 |
| `temperature` | float | `0.2` | 生成温度 |
| `top_p` | float | `0.9` | Top-p 采样参数 |
| `top_k` | integer | `40` | Top-k 采样参数 |
| `include_raw_fields` | boolean | `true` | 升级时是否向高级模型传送原始日志字段（alert、TLS、DNS、HTTP 等），而非仅初步分析摘要 |

> **升级处理与 Agent 模式的交互**：升级处理同时适用于 Pipeline 模式和 Agent 模式。在 Agent 模式中，升级处理在 orchestrator 完成工具调用（如创建 Issue）后执行——升级模型的分析结果替换初步分析，但不影响已执行的工具调用。
>
> **混合后端支持**：升级模型可以使用与主模型不同的后端。例如主模型使用本地 Ollama（低延迟），升级模型使用远程 OpenAI 兼容 API（高质量）。系统通过升级模型在 `ModelProfiles.toml` 中的 `backend_type` 自动路由到正确的后端。
>
> **工具调用与 U-A-P**：使用远程模型进行实时分析时，Agent 模式（tool calling）仍能正常匹配本地 U-A-P 链和能力框架。LLM 后端仅负责生成工具调用决策，工具的 schema 转换、策略校验和实际执行均在本地完成，与后端类型无关。
>
> **ES 字段扩展**：经升级处理的文档会在 ES 中额外写入 `ai.escalated`（boolean）、`ai.escalated_from`（keyword，初步威胁等级）、`ai.escalated_model`（keyword，升级模型名），便于在 Kibana 中筛选和统计升级命中率。

### [ollama]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `base_url` | string | `"http://host.containers.internal:11434"` | Ollama API 地址 |
| `timeout` | integer | `300` | 请求超时（秒） |
| `think` | boolean | `false` | 是否允许模型输出 `<think>` 推理块。设为 `false` 时 Ollama 会在 API 层面抑制思考输出，节省 token 并避免思考模型产生空响应 |
| `keep_alive` | string | `"5m"` | 模型在 VRAM 中的驻留时间。设为 `"0"` 立即卸载。Pipeline 模式下保持模型驻留可使 Ollama KV 缓存跨请求复用 system prompt 的注意力计算 |

### [finetune]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | `false` | 是否启用微调训练数据采集。启用后每次 pipeline LLM 请求的输入/输出对将自动写入 SQLite 数据库 |
| `db_path` | string | `"./finetune_data.db"` | 训练样本 SQLite 数据库路径 |
| `export_dir` | string | `"./finetune_export"` | JSONL 导出文件目录 |

### [perf]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `model_profiles_file` | path | `"ModelProfiles.toml"` | 模型性能档案文件 |
| `auto_select` | boolean | `true` | 是否启用自适应性能调优 |

**[perf.indexes]**：

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `analysis_value` | float | `0.5` | 分析价值因数，范围 (0, 1)。越大越偏向分析质量，越小越偏向处理速度 |

**[perf.predict]**：

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `alpha` | float | `0.6` | EMA 平滑系数 |
| `window` | integer | `5` | 移动平均窗口大小 |
| `window_weight` | float | `0.5` | 窗口平均与 EMA 的混合权重 |

**[perf.stats]**：

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `alpha` | float | `0.5` | token 统计的 EMA 平滑系数 |

### [gpu]

GPU 硬件参数，用于自适应调优的硬件饱和检测。

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `total_vram_mb` | integer | `0` | 总 GPU 显存（MB）。原位于 `ModelProfiles.toml` 的全局字段，现迁移至此 |
| `fp16_tflops` | float | `0` | GPU FP16 计算能力（TFLOPS）。多卡无 NVLink 时取单卡值 × 卡数。`0` = 禁用 |
| `mem_bandwidth_gbps` | float | `0` | GPU 显存带宽（GB/s）。多卡无 NVLink 时取单卡值 × 卡数。`0` = 禁用 |
| `saturation_threshold` | float | `0.9` | 当实际 TPS 达到理论上限的该比例时，判定 GPU 已饱和 |

### [cost]

成本感知调度参数。仅对配置了 `cost_per_1k_completion > 0` 的付费模型生效，本地模型不受影响。

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `aware_select` | boolean | `false` | 是否启用成本感知调度 |
| `weight` | float | `0.5` | 成本约束权重（0 = 忽略，1 = 最大约束） |
| `budget_per_hour` | float | `0.0` | 每小时成本预算，币种需与 `ModelProfiles.toml` 的模型成本字段保持一致 |
| `saturation_threshold` | float | `0.9` | 成本消耗达到预算的该比例时触发饱和信号 |

### [rmi]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | `true` | 是否启用远程管理接口 |
| `host` | string | `"0.0.0.0"` | RMI 监听地址 |
| `port` | integer | `8765` | RMI 监听端口 |

### [logging]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `output_to_elasticsearch` | boolean | `true` | 是否将日志输出到 ES |
| `log_es_host` | string | — | 日志专用 ES 地址（空则使用主 ES） |
| `log_es_user` | string | — | 日志 ES 用户名（空则使用主 ES 凭据） |
| `log_es_password` | string | — | 日志 ES 密码 |
| `log_index_prefix` | string | `"suricata-ai-agent-"` | 日志索引前缀 |
| `log_index_pattern` | string | `"suricata-ai-agent-*"` | 日志索引模式 |
| `log_template_name` | string | `"suricata-ai-agent-logs"` | 日志索引模板名称 |
| `log_field_limit` | integer | `65536` | ES 映射字段数量限制 |
| `log_flush_interval` | float | `1.0` | 日志批量写入间隔（秒） |
| `log_batch_size` | integer | `200` | 日志批量写入大小 |
| `stats_index_prefix` | string | `"suricata-ai-agent-stats-"` | 统计索引前缀 |
| `stats_index_pattern` | string | `"suricata-ai-agent-stats-*"` | 统计索引模式 |
| `stats_template_name` | string | `"suricata-ai-agent-stats"` | 统计索引模板名称 |

### [daily_report]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | `true` | 是否启用日报生成 |
| `llm_config_file` | path | `"daily_report_llm_conf.toml"` | 日报专用 LLM 配置 |
| `fetch_size` | integer | `10000` | 日报数据拉取批次大小 |
| `session_gap` | integer | `1800` | 同一通信对内相邻事件间隔超过该秒数时切分为新 segment |
| `max_segment_events` | integer | `200` | 单次日报 segment LLM 调用最多包含的事件数，防止连续高频通信形成超大 prompt |
| `output_dir` | string | `"/app/daily_reports"` | 日报 HTML 保存目录 |
| `subject_prefix` | string | `"[Suricata AI 每日流量日报]"` | 日报邮件主题前缀 |
| `analysis_mode` | string | `"hierarchical"` | 日报分析模式：`hierarchical`（分段→通信对→全局）、`pair_only`（仅通信对级）、`flat`（单次扁平分析） |
| `experiment_tag` | string | `""` | 非空时在邮件主题前加 `[EXP-{tag}]`，并在 HTML 报告顶部插入实验横幅 |

> **注意**：日报收件人不在此处配置，启用 U-A-P 后自动从用户数据库按角色（Owner、Administrator、Watcher）查询。

### [mail]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enable_notification` | boolean | `true` | 是否启用邮件通知 |
| `provider` | string | `"outlook"` | 邮件提供商（`outlook` 或 `gmail`） |
| `sender` | string | — | 发件人地址 |

> **注意**：`client_id` 和 `client_secret` 已迁移至 `secrets.toml` 的 `[mail]` 节，由部署脚本写入 `credentials.db`，运行时自动从数据库加载。主配置文件中不应再包含这些明文凭据。对于非容器化开发环境，可在主配置文件中取消注释 `client_id` / `client_secret` 进行临时使用（仅限开发）。

### [auth]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `db_path` | path | `""` | SQLite 凭据数据库路径（含子目录，便于卷挂载）；配置模板使用 `"auth-data/credentials.db"` |
| `jwt_secret` | string | — | JWT 签名密钥 |
| `jwt_expire_seconds` | integer | `86400` | JWT 令牌有效期（秒，最小 60） |

> **注意**：Owner 凭据不在此文件中配置。Owner 用户在部署阶段由部署脚本从 `secrets.toml` 读取并写入 `credentials.db`。

详见 [认证与授权](auth.md)。

### [executor]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | `false` | 是否启用执行器子系统（LLM 驱动的动作执行） |
| `capabilities_dir` | path | `"configs/capabilities"` | 能力声明 TOML 文件所在目录 |
| `audit_db_path` | path | `""` | SQLite 审计数据库路径（空则禁用审计）；配置模板使用 `"auth-data/audit.db"` |
| `sandbox_root` | path | — | 全局文件系统沙箱根目录，所有写操作必须位于其下 |
| `dry_run` | boolean | `true` | 试运行模式：评估策略但不实际执行。建议初始部署时开启 |
| `disable_agent_mode` | boolean | `false` | 强制使用 Pipeline 模式，即使模型支持 tool calling 也不启用 Agent 模式。启用时发送专属通知邮件 |

详见 [执行器](executor.md)。

### [git]

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | `false` | 是否启用 Git 集成 |
| `remote_url` | string | `""` | 远程仓库 HTTPS 地址 |
| `default_branch` | string | `"main"` | 默认分支名 |
| `local_repo_path` | path | `"/app/git-workspace"` | 容器内本地克隆路径 |
| `api_base_url` | string | `"https://api.github.com"` | GitHub API 地址（GitHub Enterprise 需修改） |
| `repo_owner` | string | `""` | 仓库所有者（组织名或用户名） |
| `repo_name` | string | `""` | 仓库名 |
| `auto_pr` | boolean | `true` | 日报规则生成后是否自动创建 PR |
| `auto_issue` | boolean | `true` | 实时分析是否自动创建高威胁 Issue |
| `issue_threat_threshold` | string | `"高"` | 触发自动 Issue 的最低威胁等级（`"高"` 或 `"严重"`） |
| `rules_path` | string | `"rules/generated"` | 仓库内生成规则的存放路径 |
| `validate_with_suricata` | boolean | `false` | 是否使用 `suricata -T` 进行中量验证 |
| `fork_owner` | string | `""` | Fork 模式：fork 仓库的 GitHub 用户名。设置后 Agent 克隆 fork 并创建跨仓库 PR |
| `reset_time` | string | `"02:00:00"` | 每日定时 Git 工作区重置时间（HH:MM:SS，24 小时制）。重置将丢弃本地修改并拉取最新远程代码 |

> **注意**：`token` 存储在 `credentials.db` 中，通过 `secrets.toml` 部署。

详见 [Git 与 GitHub 集成](git-integration.md)。

---

## ModelProfiles.toml — 模型性能档案

定义所有可用 LLM 模型的基准性能特征，供自适应调优算法使用。

### 全局配置

| 选项 | 类型 | 说明 |
|------|------|------|
| `total_vram_mb` | integer | （已迁移至 `[gpu].total_vram_mb`）保留用于向后兼容，`[gpu]` 优先 |

### 模型档案 [model."model-name"]

每个模型以完整的模型名作为键，包含以下配置：

| 选项 | 类型 | 说明 |
|------|------|------|
| `baseline_tps` | float | 基准 token 生成速度（tokens/sec），运行时会被实际观测值修正 |
| `quality_score` | float | 模型质量元数据（0.0 - 1.0）。当前自适应调优围绕当前实时模型档案调参，尚不据此自动切换不同模型 |
| `vram_calibration_context` | integer | VRAM 标定时的上下文长度 |
| `vram_calibration_mb` | integer | 该上下文长度下的 VRAM 占用（MB） |
| `context_length` | {min, max} | 可调上下文长度范围 |
| `num_predict` | {min, max} | 可调最大生成 token 数范围 |
| `concurrency` | {min, max} | 可调并发请求数范围 |
| `batch_size` | {min, max} | 可调批处理大小范围 |
| `poll_interval` | {min, max} | 可调轮询间隔范围（秒） |
| `temperature` | float | 生成温度（固定值） |
| `top_p` | float | Top-p 采样参数（固定值） |
| `top_k` | integer | Top-k 采样参数（固定值） |
| `supports_tool_use` | boolean? | 可选覆盖 tool-use 能力检测（`true` / `false` / 省略自动检测） |
| `backend_type` | string | 后端类型：`"ollama"` 或 `"openai"`。省略则使用全局 `[llm.backend].type` |
| `backend_base_url` | string | 覆盖全局后端 URL。省略或为空则使用全局配置 |
| `backend_auth_token` | string | 覆盖全局 auth token / API Key。省略或为空则使用全局配置 |
| `total_params_b` | float | 模型总参数量（十亿参数），用于硬件吞吐估算 |
| `active_params_b` | float | 单次推理激活参数量（MoE 模型可小于总参数量） |
| `bytes_per_param` | float | 量化后平均每参数字节数，用于显存/吞吐粗估 |
| `cost_per_1k_prompt` | float | 每 1K prompt token 成本；当前保留为模型档案元数据，`0` 表示免费/本地 |
| `cost_per_1k_completion` | float | 每 1K completion token 成本；币种需与 `[cost].budget_per_hour` 一致，`0` 表示免费/本地；成本压力计算使用该字段 |
| `max_requests_per_minute` | integer | 后端请求限速，`0` 表示不限速；同一后端缓存键共享最严格限速 |

> **混合后端**：通过为不同模型声明不同的 `backend_type`，可在同一实例中同时使用本地 Ollama 和远程 OpenAI 兼容后端。例如实时分析使用本地模型（`backend_type = "ollama"`），日报生成使用远程模型（`backend_type = "openai"`）。系统按 `(backend_type, base_url, auth_token)` 三元组自动缓存后端实例，避免重复创建。

详见 [性能调优](performance-tuning.md)。

---

## daily_report_llm_conf.toml — 日报 LLM 配置

| 选项 | 类型 | 说明 |
|------|------|------|
| `MODEL` | string | 日报生成使用的模型（通常比实时分析用更大的模型） |
| `MAX_TOKENS` | integer | 最大生成 token 数 |
| `TEMPERATURE` | float | 生成温度 |
| `TOP_P` | float | Top-p 采样 |
| `TOP_K` | integer | Top-k 采样 |
| `CONTEXT_LENGTH` | integer | 上下文长度（日报需要更大的上下文窗口） |
| `detail_level` | string | 日报 prompt 中每条事件的详细程度：`"minimal"`（默认，时间戳+威胁等级+摘要）、`"extended"`（增加事件类型、协议、端口、告警签名、安全提示、TLS/DNS/HTTP 上下文）、`"full"`（完整 `_source` JSON） |

> **向后兼容**：旧版 `OLLAMA_*` 前缀字段名（如 `OLLAMA_MODEL`、`OLLAMA_NUM_PREDICT`）仍可正常解析。

---

## llm_prompt.toml — Prompt 模板

详见 [LLM Prompt 配置](llm-prompt-config.md)。

---

## suspicious_ja3.toml / suspicious_ja3s.toml — JA3 指纹列表

定义已知恶意的 TLS 客户端/服务端指纹，用于事件过滤。

**格式**：
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

`suspicious_ja3.toml` 只包含 `tls_ja3_hashes` 数组；`suspicious_ja3s.toml` 只包含 `tls_ja3s_hashes` 数组。数组元素必须是 32 位十六进制 MD5 哈希。

项目模板提供若干客户端和服务端指纹哈希，可按同样数组格式替换或扩展。

---

## secrets.toml — 密钥与认证

`secrets.toml` 仅供部署脚本使用。所有凭据在部署时写入 `credentials.db`，运行时从数据库加载，无需 Podman secret 或凭据环境变量。

```toml
[elasticsearch]
username = { "value" = "your-username" }
password = { "value" = "your-password" }

# [log_output]                            # 可选：日志ES使用独立凭据时取消注释
# username = { "value" = "" }
# password = { "value" = "" }

[auth]
jwt_secret = { "value" = "your-jwt-secret" }

[auth.owner]
username = "admin"              # 部署时写入 credentials.db，不进入环境变量
password = "strong-password"    # 部署时经 bcrypt 哈希后写入 credentials.db
email = "admin@example.com"

[git]
token = { "value" = "your-github-token" }

# [llm]                                   # 远程 LLM 后端 API Key
# api_key = { "value" = "sk-your-key" }

[mail]                                    # Mail 凭据（Outlook OAuth2 / Gmail Basic Auth）
client_id = { "value" = "your-client-id" }
client_secret = { "value" = "your-client-secret" }
```

`[auth.owner]` 仅供部署脚本在首次部署时创建 Owner 用户，凭据**不会**出现在容器环境变量或 Quadlet 文件中。

`[mail]` 节存放邮件认证凭据。Outlook 使用 `client_id` 和 `client_secret` 完成 OAuth2；Gmail Basic Auth 使用 `sender` 作为 SMTP 用户名、`client_secret` 作为密码。凭据已从主配置文件 `suricata-llm-agent.toml` 迁移至此处，部署时写入 `credentials.db`，运行时自动从数据库加载。若不使用邮件通知，可注释掉此节。

`[llm]` 节存放远程 LLM 后端的 API Key。部署时写入 `credentials.db`（`llm_api_key` 键），也可以在运行时通过 `PUT /credentials/llm_api_key` 端点或环境变量 `SURICATA_LLM_API_KEY` 设置。仅在使用 `type = "openai"` 后端时需要。

---

## deploy.toml — 部署配置

详见 [部署指南](deployment.md)。

---

## JSON Schema 约束

所有配置文件在部署时通过 `configs/constraints/` 下的 JSON Schema 进行预检验证：

| Schema 文件 | 约束对象 |
|-------------|---------|
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

Schema 中使用自定义扩展字段 `x-deploy-file: true` 标记值类型为文件路径的选项，部署系统据此自动发现隐含的需额外烘焙的文件。

主运行配置、密钥配置和能力声明等 schema 会在关键对象层级限制额外字段，尽早暴露拼写错误；部署配置和模型档案 schema 主要依赖必填项、枚举和值域约束，未在每个对象层级都禁止额外字段。
