<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         performance-tuning.md
Description:  Adaptive performance tuning algorithm based on pressure-quality model.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# 性能调优

## 概述

Suricata LLM Agent 内置了基于 EMA（指数移动平均）的自适应性能调优系统，根据 LLM 运行时吞吐量、处理压力、本地 GPU 约束和可选成本预算实时调整调用参数，在分析质量和处理速度之间寻找最优平衡。该系统同时适用于本地 Ollama 后端、OpenAI 兼容后端和原生 DeepSeek 后端；远程后端没有硬件信息时，会自动退化为 token 吞吐量与成本信号驱动。

核心实现位于 `src/perf_cacl.py`。

## 核心概念

### 压力模型 (Pressure Model)

压力衡量的是 **"当前工作负载是否超出系统处理能力"**：

$$
\text{pressure} = \frac{\text{predicted\_eval\_tokens}}{\text{effective\_throughput} \times \text{poll\_interval}}
$$

其中：

- **predicted_eval_tokens** = 预测的下批次总生成 token 量 = `predicted_count × tokens_per_log`
- **effective_throughput** = 有效吞吐量 = `model_tps × concurrency × efficiency_factor`
- **poll_interval** = 当前轮询间隔

压力值的含义：
- `pressure < 1.0` → 系统有余量（headroom），可以提高质量参数
- `pressure ≈ 1.0` → 系统满负荷
- `pressure > 1.0` → 系统过载，需要降低质量参数换取速度

### 质量因子 (Quality Factor)

从归一化压力映射到 0.0 ~ 1.0 的质量因子，受分析价值因数（`analysis_value`）偏移。实现中先把原始 `pressure` 压缩为 `pressure_score = clamp(min(2.0, pressure) / 2.0, 0.0, 1.0)`，再计算质量因子：

$$
\text{headroom} = 1 - \text{pressure\_score}
$$

$$
\text{under\_pressure\_quality} = 0.2 + (1 - 0.2) \times \text{quality\_bias}
$$

$$
\text{quality\_factor} = \text{clamp}\left(\text{headroom} + \text{pressure\_score} \times \text{under\_pressure\_quality}, 0.2, 1.0\right)
$$

启用成本感知调度时，成本压力会抬高 `0.2` 这个质量下限。

- `quality_bias` 来自配置项 `perf.indexes.analysis_value`
- `quality_bias = 0.0` → 纯速度优先，压力略高即大幅降低质量
- `quality_bias = 1.0` → 纯质量优先，只有极端过载时才降低质量
- `quality_bias = 0.5` → 平衡模式（默认）

### 性能指数 (Perf Index)

质量因子的整数化表示（0 ~ 999），用于监控和日志：

$$
\text{perf\_index} = \text{round}(\text{quality\_factor} \times 999)
$$

## 参数插值

算法根据质量因子在 `ModelProfiles.toml` 定义的 min/max 范围内插值各参数：

### 质量驱动参数（quality_factor 越高，值越大）

| 参数 | 低质量 (0.0) | 高质量 (1.0) | 作用 |
|------|-------------|-------------|------|
| `context_length` | min | max | LLM 上下文窗口，更长 → 更多历史信息 |
| `num_predict` | min | max | 最大生成 token 数，更多 → 更详细的分析 |

### 压力驱动参数（pressure_score 越高，吞吐相关参数越激进）

| 参数 | 低压力 | 高压力 | 作用 |
|------|-------------|-------------|------|
| `concurrency` | 较低 | max | 并发 LLM 请求数 |
| `batch_size` | 较低 | max | 批处理大小 |
| `poll_interval` | min | max | 轮询间隔（压力大时增大间隔，提高批处理效率） |

## 批次预测

`perf_index_predict()` 预测下一个 batch 的处理量，用于压力计算：

1. **EMA 速率计算**：`rate = α × observed_rate + (1-α) × last_rate`
2. **移动平均混合**：维护一个滑窗（大小 `window`），将 EMA 与滑窗均值按 `window_weight` 混合
3. **积压补偿**：`predicted = blended_rate × poll_interval + backlog_factor`

## Token 统计

每个 batch 处理完成后，`record_token_stats()` 记录后端统一返回的 `LLMMetrics` 指标：

- **completion_tokens_per_sec**：实际 completion token 生成速度（EMA 平滑）。Ollama 会使用后端返回的生成阶段耗时；OpenAI 兼容 API 与 DeepSeek 等远程后端通常使用请求 wall-clock 耗时作为回退。
- **tokens_per_log**：每条日志的平均 completion token 消耗（EMA 平滑）
- **prompt_tokens / completion_tokens**：进入 `TokenStatsWindow`，用于 `/stats` 和 ES 统计索引中的滑动窗口聚合。

这些值会替换 `ModelProfiles.toml` 中的 `baseline_tps` 初始值，使系统随运行时间越来越精确。

如果模型档案配置了 `cost_per_1k_completion`，completion token 还会进入小时级 `CostTracker`，用于成本压力计算；成本字段的币种需要与 `[cost].budget_per_hour` 保持一致。

## 变更阈值

为防止微调抖动，参数变更需达到显著性阈值才会生效（`_perf_config_changed()`）：

| 参数 | 最小变更幅度 |
|------|-------------|
| 模型 | 任何变更 |
| `context_length` | ≥ 1024 |
| `num_predict` | ≥ 64 |
| `concurrency` | 任何变更 |
| `batch_size` | ≥ 5 |
| `poll_interval` | ≥ 2 |

## ModelProfiles.toml 配置

模型档案定义了每个模型的基准能力和可调范围。示例：

```toml
[model."qooba/qwen3-coder-30b-a3b-instruct:q3_k_m"]
baseline_tps = 40.0
quality_score = 0.7

vram_calibration_context = 16384
vram_calibration_mb = 22000

context_length = { min = 8192, max = 16384 }
num_predict = { min = 128, max = 512 }
concurrency = { min = 4, max = 8 }
batch_size = { min = 50, max = 80 }
poll_interval = { min = 5, max = 30 }

temperature = 0.2
top_p = 0.9
top_k = 40
total_params_b = 30.0
active_params_b = 3.0
bytes_per_param = 0.75
cost_per_1k_prompt = 0.0
cost_per_1k_completion = 0.0
max_requests_per_minute = 0
# backend_type = "ollama"        # 省略则使用全局 [llm.backend].type
# backend_base_url = ""          # 省略则使用全局后端 URL
# backend_auth_token = ""        # 省略则使用全局 auth token
```

### 混合后端

不同模型可以声明不同的 `backend_type`，使同一实例同时使用本地 Ollama、远程 OpenAI 兼容后端和原生 DeepSeek 后端：

```toml
# 本地 Ollama 模型——实时分析
[model."local-model:tag"]
backend_type = "ollama"
baseline_tps = 40.0
# ...

# 远程 OpenAI 兼容模型——日报 / 升级处理
[model."gpt-4.1-mini"]
backend_type = "openai"
backend_base_url = "https://api.openai.com"
# backend_auth_token 留空则使用全局 API Key
baseline_tps = 80.0
# ...

# 原生 DeepSeek 模型——日报 / 升级处理
[model."deepseek-v4-flash"]
backend_type = "deepseek"
# backend_base_url 留空则使用 https://api.deepseek.com
baseline_tps = 80.0
# ...
```

系统按 `(backend_type, base_url, auth_token)` 三元组缓存按模型路由的后端实例。实时分析模型由当前 `CURRENT_PERF_CONFIG.OLLAMA_MODEL` 决定，`adaptive_select()` 在当前模型档案的参数范围内调节上下文、生成长度、并发、批量和轮询间隔；日报模型由 `daily_report_llm_conf.toml` 的 `MODEL` 字段决定。两者可使用不同后端。

### 升级处理与混合后端

当 `[llm.escalation].enabled = true` 时，初步分析触发的升级处理也参与混合后端路由。升级模型通过 `[llm.escalation].model` 指定，系统查找其在 `ModelProfiles.toml` 中的 `backend_type` 来决定使用哪个后端实例。

典型的三后端混合场景：

```
实时分析  →  本地 Ollama（低延迟、低成本）
升级处理  →  远程 OpenAI API（高精度）
日报生成  →  原生 DeepSeek API（大上下文）
```

升级模型的参数（`max_tokens`、`context_length`、`temperature` 等）由 `[llm.escalation]` 配置节独立控制，不受自适应调优算法影响——因为升级调用是低频且高优先级的，不适合做动态参数压缩。

> **Agent 模式兼容性**：当实时分析使用远程模型并启用 Agent 模式时，工具调用（tool calling）、U-A-P 策略校验、能力框架匹配全部在本地完成，与 LLM 后端类型无关。远程后端仅负责生成工具调用决策，本地 executor 负责策略执行和动作分发。

### 字段说明

- **baseline_tps**：初始估计的 token 生成速度，运行后会被实际观测的 EMA 值逐步覆盖
- **quality_score**：模型质量元数据（0.0 ~ 1.0）。当前实现尚不使用它做跨模型自动切换
- **total_params_b / active_params_b / bytes_per_param**：模型规模与量化精度，用于硬件饱和判断；对 MoE 模型应把每 token 实际激活参数填入 `active_params_b`
- **vram_calibration_***：VRAM 占用的参考标定点，用于估算不同上下文长度下的显存需求
- **cost_per_1k_prompt / cost_per_1k_completion**：远程模型的价格字段；币种需与 `[cost].budget_per_hour` 一致。当前成本压力计算使用 completion 单价，prompt 单价保留为模型档案元数据
- **max_requests_per_minute**：后端共享限速器的请求上限。多个模型共用同一 `(backend_type, base_url, auth_token)` 后端时，系统采用最严格的非零 RPM 值
- **min/max 范围**：自适应调优时参数的调整边界，算法绝不会超出这些限制

### VRAM 估算

系统用标定点估算不同 `context_length` 下的 VRAM 占用：

$$
\text{estimated\_vram} \approx \text{vram\_calibration\_mb} \times \frac{\text{context\_length}}{\text{vram\_calibration\_context}}
$$

确保调优后的配置不会导致 GPU 显存溢出。

### 硬件与成本约束

`[gpu]` 节用于描述本地推理硬件：

| 选项 | 说明 |
|------|------|
| `mem_bandwidth_gbps` | 显存带宽，用于估算 decode 阶段理论上限 |
| `fp16_tflops` | FP16 算力，用于估算 prefill 阶段理论上限 |
| `saturation_threshold` | 达到理论上限的比例阈值，默认接近饱和时标记 `hw_saturated` |

`[cost]` 节用于远程模型成本约束：

| 选项 | 说明 |
|------|------|
| `aware_select` | 是否启用成本感知调度 |
| `budget_per_hour` | 小时级预算上限 |
| `weight` | 成本压力对质量因子的影响权重 |
| `saturation_threshold` | 成本速率达到预算速率的比例阈值 |

当成本压力升高时，系统会提高质量因子的下限；该逻辑只对配置了 completion 单价和小时预算的模型生效。

### vLLM Prometheus 指标

OpenAI 兼容后端可通过 `[llm.backend.vllm_metrics].prometheus_url` 抓取 vLLM 的 `/metrics`。当前实现解析以下指标并缓存在后端实例中：

| vLLM 指标 | 用途 |
|-----------|------|
| `vllm:num_requests_running` | 观察服务端当前运行请求数 |
| `vllm:avg_generation_throughput_toks_per_s` | 观察后端聚合生成吞吐量 |
| `vllm:gpu_cache_usage_perc` | 观察 GPU KV cache 使用率 |

这些指标用于运维观测，实时调优仍以本进程收集到的 `LLMMetrics`、模型档案和配置约束为主。

> **实现边界**：当前代码解析的是上表中的指标名。较新的 vLLM 版本可能同时或改为暴露 `vllm:kv_cache_usage_perc` 等指标；在后端解析逻辑扩展前，这些新增名称只会保留在 Prometheus 侧，不会进入本进程缓存。

## Token 消耗量追踪

系统维护一个 `TokenStatsWindow`，对每批次 LLM 调用的 prompt / completion token 消耗进行滑动窗口聚合。

### 滑动窗口

| 窗口 | 秒数 | 说明 |
|------|------|------|
| 1min | 60 | 短期突发检测 |
| 5min | 300 | 近期趋势 |
| 30min | 1800 | 中期消耗 |
| 1h | 3600 | 小时级消耗 |
| 6h | 21600 | 半日消耗 |
| 24h | 86400 | 全日消耗 |

### 统计字段

每个窗口产出三个字段：`{window}_prompt_tokens`、`{window}_completion_tokens`、`{window}_total_tokens`。

此外还有不受窗口过期影响的累计总量：

| 字段 | 说明 |
|------|------|
| `token_total_prompt` | 启动以来累计 prompt token 总量 |
| `token_total_completion` | 启动以来累计 completion token 总量 |
| `token_total` | 启动以来累计 token 总量 |
| `avg_tokens_per_log` | 每条日志的平均 completion token 消耗（来自 `record_token_stats()` 的 EMA） |

这些字段同时写入 ES 统计索引（`suricata-ai-agent-stats-*`）和通过 RMI `/stats` 端点暴露。

## 监控

性能状态可通过以下方式观察：

1. **RMI 端点** `GET /stats` — 返回当前 perf_index、pressure_score、quality_factor、effective_tps 以及 token 消耗量统计
2. **RMI 端点** `GET /perfcfg` — 返回当前生效的 PerfConfig 和已加载的模型档案名称
3. **ES 统计索引** — 如果启用了 `logging.output_to_elasticsearch`，统计数据（含 token 消耗量）会持续写入 `suricata-ai-agent-stats-*` 索引
4. **控制台日志** — 周期性输出 5min/15min/60min 滑窗统计
