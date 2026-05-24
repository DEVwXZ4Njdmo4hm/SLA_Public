#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         perf_cacl.py
Description:  Adaptive performance tuning based on EMA pressure-quality model.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Tuple

from .config import config, PerfConfig, ModelProfile
from .llm_backend import LLMMetrics

logger = logging.getLogger(__name__)


@dataclass
class CostTracker:
	"""Sliding-window hourly cost accumulator (thread-safe)."""
	accumulated_cost_hour: float = 0.0
	accumulated_tokens_hour: int = 0
	_window_start: float = 0.0
	_lock: threading.Lock = field(default_factory=threading.Lock)

	def _maybe_reset_window(self) -> None:
		"""Caller must hold ``_lock``."""
		now = time.monotonic()
		if self._window_start == 0.0:
			self._window_start = now
		elif now - self._window_start >= 3600.0:
			self.accumulated_cost_hour = 0.0
			self.accumulated_tokens_hour = 0
			self._window_start = now

	def record(self, completion_tokens: int, cost_per_1k_completion: float) -> None:
		with self._lock:
			self._maybe_reset_window()
			self.accumulated_tokens_hour += completion_tokens
			self.accumulated_cost_hour += completion_tokens * cost_per_1k_completion / 1000.0

	# Minimum window duration (seconds) before rate estimates are
	# considered reliable.  Avoids spurious spikes when very few
	# samples have been recorded right after startup.
	_MIN_RATE_WINDOW: float = 30.0

	@property
	def cost_rate_per_sec(self) -> float:
		with self._lock:
			self._maybe_reset_window()
			elapsed = time.monotonic() - self._window_start
			if elapsed < self._MIN_RATE_WINDOW:
				return 0.0
			return self.accumulated_cost_hour / elapsed

	@property
	def token_rate_per_sec(self) -> float:
		with self._lock:
			self._maybe_reset_window()
			elapsed = time.monotonic() - self._window_start
			if elapsed < self._MIN_RATE_WINDOW:
				return 0.0
			return self.accumulated_tokens_hour / elapsed

	@property
	def snapshot_accumulated_cost(self) -> float:
		"""Thread-safe read of *accumulated_cost_hour*."""
		with self._lock:
			self._maybe_reset_window()
			return self.accumulated_cost_hour


@dataclass
class PerfState:
	last_rate: float = 0.0
	last_predicted: float = 0.0
	alpha: float = 0.6
	rate_window: Deque[float] = field(default_factory=deque)
	# Token-level stats per model
	model_tps: Dict[str, float] = field(default_factory=dict)
	model_tokens_per_log: Dict[str, float] = field(default_factory=dict)
	# Improvement 30: hardware saturation flag
	hw_saturated: bool = False
	# Improvement 30.5: cost saturation flag and tracker
	cost_saturated: bool = False
	cost_tracker: CostTracker = field(default_factory=CostTracker)


_STATE = PerfState()


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
	if value < low:
		return low
	if value > high:
		return high
	return value


def _check_hw_saturation(
	gpu_mem_bandwidth_gbps: float,
	active_params_b: float,
	bytes_per_param: float,
	current_tps: float,
	saturation_threshold: float = 0.9,
	gpu_fp16_tflops: float = 0.0,
) -> bool:
	"""Return True when the local GPU is near its hardware ceiling.

	Checks both decode (memory-bandwidth bound) and prefill (compute bound)
	bottlenecks.  Returns False when any required parameter is zero or
	invalid — gracefully disabling detection for remote models and
	unconfigured setups.
	"""
	if active_params_b <= 0 or bytes_per_param <= 0 or current_tps <= 0:
		return False

	# Decode bottleneck: each generated token reads the active weights once
	weight_bytes = active_params_b * 1e9 * bytes_per_param
	if gpu_mem_bandwidth_gbps > 0 and weight_bytes > 0:
		max_decode_tps = (gpu_mem_bandwidth_gbps * 1e9) / weight_bytes
		if max_decode_tps > 0 and current_tps / max_decode_tps >= saturation_threshold:
			return True

	# Prefill bottleneck: ~2P FLOPs per token (matmul dominant term)
	if gpu_fp16_tflops > 0 and active_params_b > 0:
		flops_per_token = 2.0 * active_params_b * 1e9
		max_prefill_tps = (gpu_fp16_tflops * 1e12) / flops_per_token
		if max_prefill_tps > 0 and current_tps / max_prefill_tps >= saturation_threshold:
			return True

	return False


def _compute_cost_pressure(
	actual_token_rate: float,
	cost_per_1k_completion: float,
	cost_budget_per_hour: float,
	cost_weight: float = 0.5,
) -> float:
	"""Compute cost pressure signal in [0, 1].

	Returns 0.0 when cost_per_1k_completion or budget is zero — fully
	degrades to existing behaviour for free/local models.
	"""
	if cost_per_1k_completion <= 0 or cost_budget_per_hour <= 0:
		return 0.0

	cost_per_token = cost_per_1k_completion / 1000.0
	budget_per_sec = cost_budget_per_hour / 3600.0
	raw_pressure = (actual_token_rate * cost_per_token) / budget_per_sec
	return _clamp(raw_pressure * cost_weight, 0.0, 1.0)


def perf_index_predict(observed_count: int, poll_interval: float, backlog: int = 0) -> float:
	interval = max(1.0, float(poll_interval))
	count = max(0, int(observed_count))
	backlog = max(0, int(backlog))

	alpha = _clamp(getattr(config, "PERF_PREDICT_ALPHA", _STATE.alpha), 0.0, 1.0)
	rate = count / interval

	if _STATE.last_rate <= 0:
		new_rate = rate
	else:
		new_rate = alpha * rate + (1 - alpha) * _STATE.last_rate

	window_size = max(1, int(getattr(config, "PERF_PREDICT_WINDOW", 5)))
	_STATE.rate_window.append(rate)
	while len(_STATE.rate_window) > window_size:
		_STATE.rate_window.popleft()
	window_avg = sum(_STATE.rate_window) / max(1, len(_STATE.rate_window))
	window_weight = _clamp(getattr(config, "PERF_PREDICT_WINDOW_WEIGHT", 0.5), 0.0, 1.0)
	blend_rate = new_rate * window_weight + window_avg * (1 - window_weight)

	_STATE.last_rate = blend_rate
	predicted = max(0.0, blend_rate * interval + backlog)
	_STATE.last_predicted = predicted
	return predicted


def _interpolate_float(low: float, high: float, factor: float) -> float:
	return low + (high - low) * factor


def _interpolate_int(low: int, high: int, factor: float, minimum: int = 1) -> int:
	value = int(round(low + (high - low) * factor))
	return max(minimum, value)


# ---------------------------------------------------------------------------
# Token-level stats recording
# ---------------------------------------------------------------------------

def record_token_stats(metrics_list: List[LLMMetrics]) -> None:
	"""Record token-level stats from a batch of LLM metrics.

	Updates EMA-smoothed tokens-per-second and average completion-tokens-per-log
	per model, used by ``adaptive_select`` to estimate capacity.
	Only completion tokens are tracked because they dominate
	generation time; prompt evaluation is much faster.
	"""
	if not metrics_list:
		return
	alpha = _clamp(getattr(config, "PERF_STATS_ALPHA", 0.5), 0.0, 1.0)

	by_model: Dict[str, List[LLMMetrics]] = {}
	for m in metrics_list:
		if m.model:
			by_model.setdefault(m.model, []).append(m)

	for model_name, model_metrics in by_model.items():
		# EMA for tokens-per-second (generation speed)
		tps_values = [m.completion_tokens_per_sec for m in model_metrics if m.completion_tokens_per_sec > 0]
		if tps_values:
			batch_tps = sum(tps_values) / len(tps_values)
			prev_tps = _STATE.model_tps.get(model_name)
			if prev_tps is None:
				_STATE.model_tps[model_name] = batch_tps
			else:
				_STATE.model_tps[model_name] = alpha * batch_tps + (1 - alpha) * prev_tps

		# EMA for average completion tokens per log
		eval_counts = [m.completion_tokens for m in model_metrics if m.completion_tokens > 0]
		if eval_counts:
			batch_avg = sum(eval_counts) / len(eval_counts)
			prev_avg = _STATE.model_tokens_per_log.get(model_name)
			if prev_avg is None:
				_STATE.model_tokens_per_log[model_name] = batch_avg
			else:
				_STATE.model_tokens_per_log[model_name] = alpha * batch_avg + (1 - alpha) * prev_avg

		if tps_values or eval_counts:
			logger.debug(
				"Token stats [%s]: tps=%.1f  avg_eval_tokens=%.0f",
				model_name,
				_STATE.model_tps.get(model_name, 0.0),
				_STATE.model_tokens_per_log.get(model_name, 0.0),
			)

		# Improvement 30.5: accumulate cost for models with pricing
		profile = config.MODEL_PROFILES.get(model_name)
		if profile and getattr(profile, "cost_per_1k_completion", 0.0) > 0:
			total_completion = sum(
				m.completion_tokens for m in model_metrics if m.completion_tokens > 0
			)
			if total_completion > 0:
				_STATE.cost_tracker.record(total_completion, profile.cost_per_1k_completion)


# ---------------------------------------------------------------------------
# Significance check — prevents constant micro-adjustments
# ---------------------------------------------------------------------------

def _perf_config_changed(a: PerfConfig, b: PerfConfig) -> bool:
	"""Return True if *a* and *b* differ enough to warrant a switch."""
	if a.OLLAMA_MODEL != b.OLLAMA_MODEL:
		return True
	if abs(a.OLLAMA_CONTEXT_LENGTH - b.OLLAMA_CONTEXT_LENGTH) >= 1024:
		return True
	if abs(a.OLLAMA_NUM_PREDICT - b.OLLAMA_NUM_PREDICT) >= 64:
		return True
	if a.LLM_CONCURRENCY != b.LLM_CONCURRENCY:
		return True
	if abs(a.BATCH_SIZE - b.BATCH_SIZE) >= 5:
		return True
	if abs(a.POLL_INTERVAL - b.POLL_INTERVAL) >= 2:
		return True
	return False


# ---------------------------------------------------------------------------
# Adaptive performance selector (token-based)
# ---------------------------------------------------------------------------

def adaptive_select(
	predicted_count: float,
	poll_interval: float,
	quality_bias: float,
	model_profiles: Dict[str, ModelProfile],
	current_model: str = "",
) -> Tuple[PerfConfig, int, Dict[str, float]]:
	"""Token-based adaptive performance selector.

	Uses model profiles and runtime token metrics to compute optimal
	parameters instead of interpolating between predefined PerfConfig levels.

	*quality_bias* (0‒1) expresses the user's Speed↔Quality preference:
	lower values bias toward speed, higher toward quality.

	Returns ``(PerfConfig, perf_index, details)``.
	"""
	if not model_profiles:
		raise RuntimeError("No model profiles available for adaptive selection.")

	# --- Select the active model profile ---
	if current_model and current_model in model_profiles:
		profile = model_profiles[current_model]
	else:
		profile = next(iter(model_profiles.values()))

	quality_bias = _clamp(quality_bias, 0.0, 1.0)

	# --- Runtime metrics (or baseline fallback) ---
	measured_tps = _STATE.model_tps.get(profile.name)
	tps = measured_tps if measured_tps and measured_tps > 0 else profile.baseline_tps

	# avg eval (completion) tokens per log — only eval tokens matter for
	# generation time; prompt evaluation is an order of magnitude faster.
	measured_tpl = _STATE.model_tokens_per_log.get(profile.name)
	avg_eval_tokens = measured_tpl if measured_tpl and measured_tpl > 0 else float(profile.num_predict_max) * 0.6

	# Current concurrency for effective throughput estimation.
	# GPU aggregate throughput ≈ tps (constant regardless of concurrency),
	# so wall-clock batch time for N logs with C concurrent workers is
	# approximately  N * avg_eval_tokens / (tps * C)  when GPU is the
	# bottleneck, with an efficiency factor < 1 to account for scheduling
	# overhead and prompt evaluation.
	current_concurrency = max(1, getattr(config.CURRENT_PERF_CONFIG, "LLM_CONCURRENCY", 1) if config.CURRENT_PERF_CONFIG else 1)
	concurrency_efficiency = 0.75  # conservative estimate
	effective_throughput = tps * current_concurrency * concurrency_efficiency

	# --- Token-based pressure ---
	predicted = max(0.0, float(predicted_count))
	interval = max(1.0, float(poll_interval))
	total_eval_tokens_needed = predicted * avg_eval_tokens
	time_needed = total_eval_tokens_needed / max(0.1, effective_throughput)
	pressure = time_needed / interval
	pressure_score = _clamp(min(2.0, pressure) / 2.0, 0.0, 1.0)

	# --- Improvement 30: hardware saturation detection ---
	hw_saturated = False
	theoretical_max_decode_tps = 0.0
	theoretical_max_prefill_tps = 0.0
	gpu_fp16_tflops = getattr(config, "GPU_FP16_TFLOPS", 0.0)
	gpu_mem_bw = getattr(config, "GPU_MEM_BANDWIDTH_GBPS", 0.0)
	gpu_sat_threshold = getattr(config, "GPU_SATURATION_THRESHOLD", 0.9)

	if profile.active_params_b > 0 and profile.bytes_per_param > 0:
		weight_bytes = profile.active_params_b * 1e9 * profile.bytes_per_param
		if gpu_mem_bw > 0:
			theoretical_max_decode_tps = (gpu_mem_bw * 1e9) / weight_bytes
		if gpu_fp16_tflops > 0:
			theoretical_max_prefill_tps = (gpu_fp16_tflops * 1e12) / (2.0 * profile.active_params_b * 1e9)

		hw_saturated = _check_hw_saturation(
			gpu_mem_bandwidth_gbps=gpu_mem_bw,
			active_params_b=profile.active_params_b,
			bytes_per_param=profile.bytes_per_param,
			current_tps=tps,
			saturation_threshold=gpu_sat_threshold,
			gpu_fp16_tflops=gpu_fp16_tflops,
		)
	_STATE.hw_saturated = hw_saturated

	# --- Improvement 30.5: cost-aware scheduling ---
	cost_score = 0.0
	cost_rate = 0.0
	cost_saturated = False
	cost_remaining_hour = 0.0
	cost_aware = getattr(config, "COST_AWARE_SELECT", False)
	cost_budget_per_hour = getattr(config, "COST_BUDGET_PER_HOUR", 0.0)
	cost_weight = getattr(config, "COST_WEIGHT", 0.5)
	cost_sat_threshold = getattr(config, "COST_SATURATION_THRESHOLD", 0.9)

	if cost_aware and profile.cost_per_1k_completion > 0 and cost_budget_per_hour > 0:
		actual_token_rate = _STATE.cost_tracker.token_rate_per_sec
		if actual_token_rate <= 0:
			actual_token_rate = effective_throughput

		cost_score = _compute_cost_pressure(
			actual_token_rate=actual_token_rate,
			cost_per_1k_completion=profile.cost_per_1k_completion,
			cost_budget_per_hour=cost_budget_per_hour,
			cost_weight=cost_weight,
		)

		cost_per_token = profile.cost_per_1k_completion / 1000.0
		cost_rate = _STATE.cost_tracker.cost_rate_per_sec
		if cost_rate <= 0:
			cost_rate = actual_token_rate * cost_per_token

		budget_per_sec = cost_budget_per_hour / 3600.0
		if budget_per_sec > 0 and cost_rate / budget_per_sec >= cost_sat_threshold:
			cost_saturated = True

		cost_remaining_hour = max(0.0, cost_budget_per_hour - _STATE.cost_tracker.snapshot_accumulated_cost)

	_STATE.cost_saturated = cost_saturated

	# --- Quality factor ---
	# The formula ensures:
	#   - When idle (pressure=0): quality_factor → 1.0 (max quality)
	#   - When maxed (pressure=1): quality_factor → floor + (1-floor) * quality_bias
	#     i.e. quality_bias=0 → floor, quality_bias=1 → 1.0
	#   - quality_bias controls how aggressively quality is sacrificed under pressure.
	headroom = 1.0 - pressure_score
	floor = 0.2

	# Improvement 30.5: cost pressure raises quality floor
	if cost_score > 0:
		floor = max(floor, floor + (1.0 - floor) * cost_score)

	under_pressure_quality = floor + (1.0 - floor) * quality_bias
	quality_factor = _clamp(
		headroom * 1.0 + pressure_score * under_pressure_quality,
		floor, 1.0,
	)

	# --- Compute continuous parameters ---
	ctx_len = _interpolate_int(
		profile.context_length_min, profile.context_length_max, quality_factor,
	)
	num_predict = _interpolate_int(
		profile.num_predict_min, profile.num_predict_max, quality_factor,
	)

	# Concurrency: scales with pressure (more parallel work when busy)
	conc_factor = _clamp(0.3 + 0.7 * pressure_score, 0.0, 1.0)
	concurrency = _interpolate_int(
		profile.concurrency_min, profile.concurrency_max, conc_factor,
	)

	# Batch size: scales with pressure
	batch_factor = _clamp(0.3 + 0.7 * pressure_score, 0.0, 1.0)
	batch_size = _interpolate_int(
		profile.batch_size_min, profile.batch_size_max, batch_factor,
	)

	# Poll interval: longer when busy (batch efficiency), shorter when idle
	poll_factor = _clamp(pressure_score, 0.0, 1.0)
	new_poll = _interpolate_int(
		profile.poll_interval_min, profile.poll_interval_max, poll_factor,
	)

	# --- Map to compatible perf_index ---
	max_index = 999
	perf_index = int(round(quality_factor * max_index))

	selected = PerfConfig(
		index=-1,
		PERF_INDEX_MIN=perf_index,
		PERF_INDEX_MAX=perf_index,
		OLLAMA_MODEL=profile.name,
		OLLAMA_NUM_PREDICT=num_predict,
		OLLAMA_TEMPERATURE=profile.temperature,
		OLLAMA_TOP_P=profile.top_p,
		OLLAMA_TOP_K=profile.top_k,
		LLM_CONCURRENCY=concurrency,
		BATCH_SIZE=batch_size,
		POLL_INTERVAL=new_poll,
		OLLAMA_CONTEXT_LENGTH=ctx_len,
	)

	details = {
		"predicted_count": predicted,
		"pressure": pressure,
		"pressure_score": pressure_score,
		"headroom": headroom,
		"quality_bias": quality_bias,
		"quality_factor": quality_factor,
		"measured_tps": measured_tps or 0.0,
		"effective_tps": tps,
		"effective_throughput": effective_throughput,
		"avg_eval_tokens": avg_eval_tokens,
		"concurrency": current_concurrency,
		# Improvement 30: hardware saturation
		"hw_saturated": 1.0 if hw_saturated else 0.0,
		"theoretical_max_decode_tps": theoretical_max_decode_tps,
		"theoretical_max_prefill_tps": theoretical_max_prefill_tps,
		"gpu_fp16_tflops": gpu_fp16_tflops,
		"gpu_mem_bandwidth_gbps": gpu_mem_bw,
		# Improvement 30.5: cost awareness
		"cost_score": cost_score,
		"cost_rate": cost_rate,
		"cost_saturated": 1.0 if cost_saturated else 0.0,
		"cost_remaining_hour": cost_remaining_hour,
		"cost_accumulated_hour": _STATE.cost_tracker.snapshot_accumulated_cost,
	}
	return selected, perf_index, details

