<!--
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         performance-tuning.md
Description:  Adaptive performance tuning algorithm based on pressure-quality model.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
-->

# Performance Tuning

## Overview

Suricata LLM Agent includes an EMA-based adaptive performance tuning system. It
adjusts LLM call parameters in real time based on runtime throughput, processing
pressure, local GPU constraints, and optional cost budgets, seeking a balance
between analysis quality and processing speed. The system applies to local
Ollama backends, OpenAI-compatible backends, and the native DeepSeek backend.
When a remote backend has no hardware information, tuning falls back to token
throughput and cost signals.

The core implementation lives in `src/perf_cacl.py`.

## Core Concepts

### Pressure Model

Pressure measures **whether the current workload exceeds processing capacity**:

$$
\text{pressure} = \frac{\text{predicted\_eval\_tokens}}{\text{effective\_throughput} \times \text{poll\_interval}}
$$

Where:

- **predicted_eval_tokens** = predicted total generated tokens for the next
  batch = `predicted_count x tokens_per_log`
- **effective_throughput** = effective throughput =
  `model_tps x concurrency x efficiency_factor`
- **poll_interval** = current poll interval

Pressure interpretation:

- `pressure < 1.0`: the system has headroom and can increase quality parameters.
- `pressure ~= 1.0`: the system is near full capacity.
- `pressure > 1.0`: the system is overloaded and should trade quality for speed.

### Quality Factor

Pressure is normalized into a 0.0 to 1.0 quality factor, shifted by the analysis
value factor (`analysis_value`). The implementation first compresses raw
`pressure` into `pressure_score = clamp(min(2.0, pressure) / 2.0, 0.0, 1.0)`,
then calculates:

$$
\text{headroom} = 1 - \text{pressure\_score}
$$

$$
\text{under\_pressure\_quality} = 0.2 + (1 - 0.2) \times \text{quality\_bias}
$$

$$
\text{quality\_factor} = \text{clamp}\left(\text{headroom} + \text{pressure\_score} \times \text{under\_pressure\_quality}, 0.2, 1.0\right)
$$

When cost-aware scheduling is enabled, cost pressure raises the `0.2` quality
floor.

- `quality_bias` comes from `perf.indexes.analysis_value`.
- `quality_bias = 0.0`: speed-first; quality drops quickly under pressure.
- `quality_bias = 1.0`: quality-first; quality drops only under extreme overload.
- `quality_bias = 0.5`: balanced mode, the default.

### Perf Index

The quality factor is converted into an integer 0 to 999 for monitoring and
logging:

$$
\text{perf\_index} = \text{round}(\text{quality\_factor} \times 999)
$$

## Parameter Interpolation

The algorithm interpolates parameters within the min/max ranges defined in
`ModelProfiles.toml` according to the quality factor.

### Quality-Driven Parameters

Higher `quality_factor` means larger values:

| Parameter | Low quality (0.0) | High quality (1.0) | Effect |
|-----------|-------------------|--------------------|--------|
| `context_length` | min | max | LLM context window; larger means more history |
| `num_predict` | min | max | Maximum generated tokens; larger means more detailed analysis |

### Pressure-Driven Parameters

Higher `pressure_score` makes throughput-related parameters more aggressive:

| Parameter | Low pressure | High pressure | Effect |
|-----------|--------------|---------------|--------|
| `concurrency` | Lower | max | Concurrent LLM requests |
| `batch_size` | Lower | max | Batch size |
| `poll_interval` | min | max | Poll interval; under pressure, longer intervals improve batch efficiency |

## Batch Prediction

`perf_index_predict()` predicts the next batch size for pressure calculation:

1. **EMA rate calculation**: `rate = alpha x observed_rate + (1-alpha) x last_rate`
2. **Moving average blend**: maintain a sliding window of size `window`, then
   blend EMA and window average by `window_weight`
3. **Backlog compensation**: `predicted = blended_rate x poll_interval + backlog_factor`

## Token Statistics

After each processed batch, `record_token_stats()` records unified
`LLMMetrics` returned by the backend:

- **completion_tokens_per_sec**: actual completion token generation speed with
  EMA smoothing. Ollama uses backend-reported generation time; remote backends
  such as OpenAI-compatible APIs and DeepSeek usually fall back to request
  wall-clock time.
- **tokens_per_log**: average completion token cost per log, with EMA smoothing.
- **prompt_tokens / completion_tokens**: recorded into `TokenStatsWindow` for
  `/stats` and ES statistics indexes.

These runtime values replace the initial `baseline_tps` from `ModelProfiles.toml`
so the system becomes more accurate over time.

If a model profile sets `cost_per_1k_completion`, completion tokens are also
recorded in an hourly `CostTracker` for cost-pressure calculation. The currency
used by cost fields must match `[cost].budget_per_hour`.

## Change Thresholds

To prevent tuning jitter, parameter changes must pass significance thresholds
before they take effect (`_perf_config_changed()`):

| Parameter | Minimum change |
|-----------|----------------|
| Model | Any change |
| `context_length` | >= 1024 |
| `num_predict` | >= 64 |
| `concurrency` | Any change |
| `batch_size` | >= 5 |
| `poll_interval` | >= 2 |

## ModelProfiles.toml Configuration

Model profiles define each model's baseline capabilities and tunable ranges.
Example:

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
# backend_type = "ollama"        # Omitted means use global [llm.backend].type
# backend_base_url = ""          # Omitted means use global backend URL
# backend_auth_token = ""        # Omitted means use global auth token
```

### Hybrid Backend

Different models can declare different `backend_type` values, allowing one
instance to use local and remote backends at the same time:

```toml
# Local Ollama model for real-time analysis
[model."local-model:tag"]
backend_type = "ollama"
baseline_tps = 40.0
# ...

# Remote OpenAI-compatible model for daily reports / escalation
[model."gpt-4.1-mini"]
backend_type = "openai"
backend_base_url = "https://api.openai.com"
# Leave backend_auth_token empty to use the global API Key
baseline_tps = 80.0
# ...

# Native DeepSeek model for daily reports / escalation
[model."deepseek-v4-flash"]
backend_type = "deepseek"
# Leave backend_base_url empty to use https://api.deepseek.com
baseline_tps = 80.0
# ...
```

The system caches per-model routed backend instances by `(backend_type, base_url,
auth_token)`. The real-time analysis model is determined by
`CURRENT_PERF_CONFIG.OLLAMA_MODEL`, and `adaptive_select()` adjusts context
length, generation length, concurrency, batch size, and poll interval within the
current model profile range. The daily report model is determined by the `MODEL`
field in `daily_report_llm_conf.toml`. The two can use different backends.

### Escalation and Hybrid Backend

When `[llm.escalation].enabled = true`, escalation triggered by initial analysis
also participates in hybrid backend routing. The escalation model is set by
`[llm.escalation].model`; the system looks up its `backend_type` in
`ModelProfiles.toml` to select the backend instance.

A typical three-backend pattern:

```text
Real-time analysis -> local Ollama (low latency, low cost)
Escalation         -> remote OpenAI API (high accuracy)
Daily report       -> native DeepSeek API (large context)
```

Escalation parameters (`max_tokens`, `context_length`, `temperature`, and
others) are controlled independently by `[llm.escalation]` and are not affected
by the adaptive tuning algorithm because escalation calls are low-frequency and
high-priority.

> **Agent mode compatibility**: when real-time analysis uses a remote model and
> Agent mode is enabled, tool calling, U-A-P policy checks, and capability
> framework matching are all performed locally. The remote backend only
> generates tool-call decisions; the local executor performs policy enforcement
> and action dispatch.

### Field Descriptions

- **baseline_tps**: initial token generation speed estimate, gradually replaced
  by runtime EMA observations.
- **quality_score**: model quality metadata from 0.0 to 1.0. Current
  implementation does not use it for cross-model automatic switching.
- **total_params_b / active_params_b / bytes_per_param**: model size and
  quantization precision for hardware saturation checks. For MoE models,
  `active_params_b` should reflect the parameters actually active per token.
- **vram_calibration_***: reference VRAM calibration point used to estimate
  memory requirements at different context lengths.
- **cost_per_1k_prompt / cost_per_1k_completion**: price fields for remote
  models. Currency must match `[cost].budget_per_hour`. Current cost-pressure
  calculation uses completion price; prompt price remains model metadata.
- **max_requests_per_minute**: request limit for the shared backend limiter. If
  multiple models share one `(backend_type, base_url, auth_token)` backend, the
  strictest non-zero RPM value is used.
- **min/max ranges**: adaptive tuning boundaries. The algorithm never exceeds
  these limits.

### VRAM Estimation

The system estimates VRAM usage for different `context_length` values from the
calibration point:

$$
\text{estimated\_vram} \approx \text{vram\_calibration\_mb} \times \frac{\text{context\_length}}{\text{vram\_calibration\_context}}
$$

This prevents tuned configurations from overflowing GPU VRAM.

### Hardware and Cost Constraints

The `[gpu]` section describes local inference hardware:

| Option | Description |
|--------|-------------|
| `mem_bandwidth_gbps` | Memory bandwidth, used to estimate decode-stage theoretical maximum |
| `fp16_tflops` | FP16 compute, used to estimate prefill-stage theoretical maximum |
| `saturation_threshold` | Fraction of theoretical maximum at which `hw_saturated` is marked; default is near saturation |

The `[cost]` section describes remote model cost constraints:

| Option | Description |
|--------|-------------|
| `aware_select` | Whether cost-aware scheduling is enabled |
| `budget_per_hour` | Hourly budget limit |
| `weight` | Weight of cost pressure in quality-factor adjustment |
| `saturation_threshold` | Fraction of budget rate at which cost saturation is signaled |

When cost pressure rises, the system raises the quality-factor floor. This logic
applies only to models that have a completion price and an hourly budget.

### vLLM Prometheus Metrics

OpenAI-compatible backends can collect vLLM `/metrics` through
`[llm.backend.vllm_metrics].prometheus_url`. The current implementation parses
and caches:

| vLLM metric | Purpose |
|-------------|---------|
| `vllm:num_requests_running` | Observe current server-side running request count |
| `vllm:avg_generation_throughput_toks_per_s` | Observe aggregate backend generation throughput |
| `vllm:gpu_cache_usage_perc` | Observe GPU KV cache usage |

These metrics are used for operational observability. Real-time tuning still
primarily uses `LLMMetrics` collected by this process, model profiles, and
configuration constraints.

> **Implementation boundary**: the current code parses the metric names listed
> above. Newer vLLM versions may also expose or switch to names such as
> `vllm:kv_cache_usage_perc`; until backend parsing logic is extended, those new
> names remain on the Prometheus side and do not enter this process's cache.

## Token Usage Tracking

The system maintains a `TokenStatsWindow` that aggregates prompt and completion
token usage for each batch over sliding windows.

### Sliding Windows

| Window | Seconds | Description |
|--------|---------|-------------|
| 1min | 60 | Short-term burst detection |
| 5min | 300 | Recent trend |
| 30min | 1800 | Medium-term usage |
| 1h | 3600 | Hourly usage |
| 6h | 21600 | Half-day usage |
| 24h | 86400 | Full-day usage |

### Statistics Fields

Each window produces three fields:
`{window}_prompt_tokens`, `{window}_completion_tokens`, and
`{window}_total_tokens`.

There are also cumulative totals that do not expire with windows:

| Field | Description |
|-------|-------------|
| `token_total_prompt` | Total prompt tokens since startup |
| `token_total_completion` | Total completion tokens since startup |
| `token_total` | Total tokens since startup |
| `avg_tokens_per_log` | Average completion tokens per log, from the EMA in `record_token_stats()` |

These fields are written to the ES statistics index
(`suricata-ai-agent-stats-*`) and exposed through the RMI `/stats` endpoint.

## Monitoring

Performance state can be observed through:

1. **RMI endpoint** `GET /stats`: returns current perf_index, pressure_score,
   quality_factor, effective_tps, and token usage statistics.
2. **RMI endpoint** `GET /perfcfg`: returns the active PerfConfig and loaded
   model profile names.
3. **ES statistics index**: when `logging.output_to_elasticsearch` is enabled,
   statistics including token usage are continuously written to
   `suricata-ai-agent-stats-*`.
4. **Console logs**: periodically prints 5min/15min/60min sliding-window
   statistics.
