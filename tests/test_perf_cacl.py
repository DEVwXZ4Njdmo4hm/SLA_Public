#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_perf_cacl.py
Description:  Tests for performance calculation algorithms and numerical functions.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations
import pytest
from tests.conftest import PerfConfig, ModelProfile


# ── _clamp ──────────────────────────────────────────────────────────────

class TestClamp:
    def setup_method(self):
        from src.perf_cacl import _clamp
        self.clamp = _clamp

    @pytest.mark.parametrize("val,lo,hi,expected", [
        (0.5, 0.0, 1.0, 0.5),
        (-1.0, 0.0, 1.0, 0.0),
        (2.0, 0.0, 1.0, 1.0),
        (0.0, 0.0, 1.0, 0.0),
        (1.0, 0.0, 1.0, 1.0),
        (5, 1, 10, 5),
        (0, 1, 10, 1),
        (100, 1, 10, 10),
    ])
    def test_clamp(self, val, lo, hi, expected):
        assert self.clamp(val, lo, hi) == expected


# ── _interpolate_float / _interpolate_int ───────────────────────────────

class TestInterpolation:
    def setup_method(self):
        from src.perf_cacl import _interpolate_float, _interpolate_int
        self.interp_float = _interpolate_float
        self.interp_int = _interpolate_int

    @pytest.mark.parametrize("lo,hi,factor,expected", [
        (0.0, 1.0, 0.0, 0.0),
        (0.0, 1.0, 1.0, 1.0),
        (0.0, 1.0, 0.5, 0.5),
        (10.0, 20.0, 0.25, 12.5),
        (100.0, 200.0, 0.0, 100.0),
    ])
    def test_interpolate_float(self, lo, hi, factor, expected):
        assert self.interp_float(lo, hi, factor) == pytest.approx(expected)

    @pytest.mark.parametrize("lo,hi,factor,minimum,expected", [
        (1, 10, 0.0, 1, 1),
        (1, 10, 1.0, 1, 10),
        (1, 10, 0.5, 1, 6),       # round(5.5) = 6
        (0, 100, 0.0, 5, 5),      # result 0 < minimum 5 -> 5
        (10, 20, 0.25, 1, 12),   # round(12.5) = 12 (banker's rounding)
    ])
    def test_interpolate_int(self, lo, hi, factor, minimum, expected):
        assert self.interp_int(lo, hi, factor, minimum) == expected


# ── perf_index_predict ──────────────────────────────────────────────────

class TestPerfIndexPredict:
    def setup_method(self):
        from src import perf_cacl
        self.mod = perf_cacl
        # Reset global state before each test
        self.mod._STATE = self.mod.PerfState()

    def test_first_call_returns_rate_times_interval(self, fake_config):
        result = self.mod.perf_index_predict(10, 5.0, backlog=0)
        assert result >= 0

    def test_backlog_adds_to_prediction(self, fake_config):
        r1 = self.mod.perf_index_predict(10, 5.0, backlog=0)
        self.mod._STATE = self.mod.PerfState()
        r2 = self.mod.perf_index_predict(10, 5.0, backlog=100)
        assert r2 > r1

    def test_zero_observed(self, fake_config):
        result = self.mod.perf_index_predict(0, 5.0)
        assert result >= 0.0

    def test_negative_values_clamped(self, fake_config):
        result = self.mod.perf_index_predict(-5, -10.0, backlog=-1)
        assert result >= 0.0


# ── _perf_config_changed ───────────────────────────────────────────────

class TestPerfConfigChanged:
    def setup_method(self):
        from src.perf_cacl import _perf_config_changed
        self.changed = _perf_config_changed

    def test_identical_configs(self):
        a = PerfConfig()
        b = PerfConfig()
        assert not self.changed(a, b)

    def test_different_model(self):
        a = PerfConfig()
        b = PerfConfig(OLLAMA_MODEL="other-model")
        assert self.changed(a, b)

    def test_significant_context_change(self):
        a = PerfConfig(OLLAMA_CONTEXT_LENGTH=4096)
        b = PerfConfig(OLLAMA_CONTEXT_LENGTH=6000)
        assert self.changed(a, b)

    def test_insignificant_context_change(self):
        a = PerfConfig(OLLAMA_CONTEXT_LENGTH=4096)
        b = PerfConfig(OLLAMA_CONTEXT_LENGTH=4500)
        assert not self.changed(a, b)

    def test_different_concurrency(self):
        a = PerfConfig(LLM_CONCURRENCY=1)
        b = PerfConfig(LLM_CONCURRENCY=4)
        assert self.changed(a, b)


# ── record_token_stats ─────────────────────────────────────────────────

class TestRecordTokenStats:
    def setup_method(self):
        from src import perf_cacl
        from src.llm_backend import LLMMetrics
        self.mod = perf_cacl
        self.LLMMetrics = LLMMetrics
        self.mod._STATE = self.mod.PerfState()

    def test_empty_list(self, fake_config):
        self.mod.record_token_stats([])
        assert len(self.mod._STATE.model_tps) == 0

    def test_records_tps(self, fake_config):
        m = self.LLMMetrics(
            model="test-model",
            completion_tokens=100,
            completion_duration_sec=2.0,  # 2 seconds -> 50 tps
        )
        self.mod.record_token_stats([m])
        assert "test-model" in self.mod._STATE.model_tps
        assert self.mod._STATE.model_tps["test-model"] == pytest.approx(50.0)

    def test_ema_updates(self, fake_config):
        m1 = self.LLMMetrics(model="m", completion_tokens=100, completion_duration_sec=1.0)
        self.mod.record_token_stats([m1])  # 100 tps
        m2 = self.LLMMetrics(model="m", completion_tokens=50, completion_duration_sec=1.0)
        self.mod.record_token_stats([m2])  # 50 tps
        # EMA smoothed, so should be between 50 and 100
        tps = self.mod._STATE.model_tps["m"]
        assert 50 < tps < 100


# ── adaptive_select ────────────────────────────────────────────────────

class TestAdaptiveSelect:
    def setup_method(self):
        from src import perf_cacl
        self.mod = perf_cacl
        self.mod._STATE = self.mod.PerfState()

    def test_basic_call(self, fake_config):
        profiles = {"test-model": ModelProfile()}
        cfg, idx, details = self.mod.adaptive_select(
            predicted_count=10.0,
            poll_interval=5.0,
            quality_bias=0.5,
            model_profiles=profiles,
        )
        assert isinstance(cfg, PerfConfig)
        assert 0 <= idx <= 999
        assert "pressure_score" in details

    def test_zero_predicted(self, fake_config):
        profiles = {"test-model": ModelProfile()}
        cfg, idx, details = self.mod.adaptive_select(
            predicted_count=0.0,
            poll_interval=5.0,
            quality_bias=0.5,
            model_profiles=profiles,
        )
        # Zero pressure → max quality
        assert details["pressure_score"] == pytest.approx(0.0)
        assert details["quality_factor"] == pytest.approx(1.0)

    def test_high_quality_bias(self, fake_config):
        profiles = {"test-model": ModelProfile()}
        _, _, d_high = self.mod.adaptive_select(50, 5.0, 1.0, profiles)
        _, _, d_low = self.mod.adaptive_select(50, 5.0, 0.0, profiles)
        assert d_high["quality_factor"] >= d_low["quality_factor"]

    def test_no_profiles_raises(self, fake_config):
        with pytest.raises(RuntimeError, match="No model profiles"):
            self.mod.adaptive_select(10, 5.0, 0.5, {})


# ── _check_hw_saturation ───────────────────────────────────────────────

class TestCheckHwSaturation:
    def setup_method(self):
        from src.perf_cacl import _check_hw_saturation
        self.check = _check_hw_saturation

    def test_zero_params_returns_false(self):
        assert not self.check(
            gpu_mem_bandwidth_gbps=1008.0,
            active_params_b=0.0,
            bytes_per_param=0.5,
            current_tps=100.0,
        )

    def test_zero_bandwidth_returns_false(self):
        assert not self.check(
            gpu_mem_bandwidth_gbps=0.0,
            active_params_b=3.0,
            bytes_per_param=0.4375,
            current_tps=100.0,
            gpu_fp16_tflops=0.0,
        )

    def test_decode_saturation_moe_model(self):
        """MoE 3B active, Q3_K_M, RTX 4090 bandwidth.
        max_decode_tps = 1008e9 / (3e9 × 0.4375) ≈ 768; tps=700 → 0.91 > 0.9"""
        assert self.check(
            gpu_mem_bandwidth_gbps=1008.0,
            active_params_b=3.0,
            bytes_per_param=0.4375,
            current_tps=700.0,
            saturation_threshold=0.9,
        )

    def test_decode_not_saturated(self):
        assert not self.check(
            gpu_mem_bandwidth_gbps=1008.0,
            active_params_b=3.0,
            bytes_per_param=0.4375,
            current_tps=100.0,
            saturation_threshold=0.9,
        )

    def test_dense_model_not_saturated(self):
        """8B Q4_K_M: max_decode=252; tps=200 → 0.79 < 0.9"""
        assert not self.check(
            gpu_mem_bandwidth_gbps=1008.0,
            active_params_b=8.0,
            bytes_per_param=0.5,
            current_tps=200.0,
            saturation_threshold=0.9,
        )

    def test_dense_model_saturated(self):
        """8B Q4_K_M: max_decode=252; tps=240 → 0.95 > 0.9"""
        assert self.check(
            gpu_mem_bandwidth_gbps=1008.0,
            active_params_b=8.0,
            bytes_per_param=0.5,
            current_tps=240.0,
            saturation_threshold=0.9,
        )

    def test_prefill_saturation(self):
        """fp16=82.6 TFLOPS, 8B active → max_prefill=5162; tps=4800 → 0.93 > 0.9"""
        assert self.check(
            gpu_mem_bandwidth_gbps=0.0,
            active_params_b=8.0,
            bytes_per_param=0.5,
            current_tps=4800.0,
            saturation_threshold=0.9,
            gpu_fp16_tflops=82.6,
        )

    def test_prefill_not_saturated(self):
        assert not self.check(
            gpu_mem_bandwidth_gbps=0.0,
            active_params_b=8.0,
            bytes_per_param=0.5,
            current_tps=100.0,
            saturation_threshold=0.9,
            gpu_fp16_tflops=82.6,
        )

    def test_remote_model_no_params(self):
        assert not self.check(
            gpu_mem_bandwidth_gbps=1008.0,
            active_params_b=0.0,
            bytes_per_param=0.0,
            current_tps=100.0,
            gpu_fp16_tflops=82.6,
        )


# ── adaptive_select hw_saturated exposure ──────────────────────────────

class TestAdaptiveSelectHwSaturation:
    def setup_method(self):
        from src import perf_cacl
        self.mod = perf_cacl
        self.mod._STATE = self.mod.PerfState()

    def test_hw_saturated_exposed_in_details(self, fake_config):
        fake_config.GPU_FP16_TFLOPS = 82.6
        fake_config.GPU_MEM_BANDWIDTH_GBPS = 1008.0
        fake_config.GPU_SATURATION_THRESHOLD = 0.9

        profile = ModelProfile(
            active_params_b=3.0,
            bytes_per_param=0.4375,
            total_params_b=30.0,
        )
        profiles = {profile.name: profile}
        _, _, details = self.mod.adaptive_select(
            predicted_count=10.0,
            poll_interval=5.0,
            quality_bias=0.5,
            model_profiles=profiles,
        )
        assert "hw_saturated" in details
        assert "theoretical_max_decode_tps" in details

    def test_no_gpu_config_hw_saturated_false(self, fake_config):
        fake_config.GPU_FP16_TFLOPS = 0.0
        fake_config.GPU_MEM_BANDWIDTH_GBPS = 0.0

        profiles = {"test-model": ModelProfile()}
        _, _, details = self.mod.adaptive_select(
            predicted_count=10.0,
            poll_interval=5.0,
            quality_bias=0.5,
            model_profiles=profiles,
        )
        assert details.get("hw_saturated", 0.0) == 0.0


# ── _compute_cost_pressure ─────────────────────────────────────────────

class TestComputeCostPressure:
    def setup_method(self):
        from src.perf_cacl import _compute_cost_pressure
        self.compute = _compute_cost_pressure

    def test_zero_cost_returns_zero(self):
        assert self.compute(
            actual_token_rate=100.0,
            cost_per_1k_completion=0.0,
            cost_budget_per_hour=1.0,
        ) == 0.0

    def test_zero_budget_returns_zero(self):
        assert self.compute(
            actual_token_rate=100.0,
            cost_per_1k_completion=1.6,
            cost_budget_per_hour=0.0,
        ) == 0.0

    def test_moderate_pressure(self):
        result = self.compute(
            actual_token_rate=10.0,
            cost_per_1k_completion=1.6,
            cost_budget_per_hour=1.0,
            cost_weight=0.5,
        )
        assert result == pytest.approx(1.0)

    def test_low_rate_low_pressure(self):
        result = self.compute(
            actual_token_rate=1.0,
            cost_per_1k_completion=0.001,
            cost_budget_per_hour=10.0,
            cost_weight=0.5,
        )
        assert result < 0.01

    def test_clamped_to_one(self):
        result = self.compute(
            actual_token_rate=1000.0,
            cost_per_1k_completion=10.0,
            cost_budget_per_hour=0.1,
            cost_weight=1.0,
        )
        assert result == pytest.approx(1.0)


# ── CostTracker ────────────────────────────────────────────────────────

class TestCostTracker:
    def setup_method(self):
        from src.perf_cacl import CostTracker
        self.CostTracker = CostTracker

    def test_initial_state(self):
        ct = self.CostTracker()
        assert ct.accumulated_cost_hour == 0.0
        assert ct.accumulated_tokens_hour == 0

    def test_record_accumulates(self):
        ct = self.CostTracker()
        ct.record(1000, cost_per_1k_completion=1.6)
        assert ct.accumulated_cost_hour == pytest.approx(1.6)
        assert ct.accumulated_tokens_hour == 1000

        ct.record(500, cost_per_1k_completion=1.6)
        assert ct.accumulated_cost_hour == pytest.approx(2.4)
        assert ct.accumulated_tokens_hour == 1500

    def test_zero_cost_model(self):
        ct = self.CostTracker()
        ct.record(1000, cost_per_1k_completion=0.0)
        assert ct.accumulated_cost_hour == 0.0
        assert ct.accumulated_tokens_hour == 1000

    def test_rate_zero_before_min_window(self):
        """Rates return 0 while elapsed < _MIN_RATE_WINDOW to avoid spikes."""
        ct = self.CostTracker()
        ct.record(5000, cost_per_1k_completion=1.6)
        # Window just started — within _MIN_RATE_WINDOW (30s)
        assert ct.cost_rate_per_sec == 0.0
        assert ct.token_rate_per_sec == 0.0

    def test_rate_nonzero_after_min_window(self):
        """Rates become meaningful after _MIN_RATE_WINDOW elapses."""
        import time as _time
        ct = self.CostTracker()
        ct.record(1000, cost_per_1k_completion=1.6)
        # Backdate the window start to simulate elapsed time
        with ct._lock:
            ct._window_start = _time.monotonic() - 60.0
        assert ct.cost_rate_per_sec > 0.0
        assert ct.token_rate_per_sec > 0.0

    def test_snapshot_accumulated_cost_under_lock(self):
        """snapshot_accumulated_cost returns the correct value thread-safely."""
        ct = self.CostTracker()
        ct.record(2000, cost_per_1k_completion=1.6)
        assert ct.snapshot_accumulated_cost == pytest.approx(3.2)


# ── adaptive_select cost-aware integration ─────────────────────────────

class TestAdaptiveSelectCostAware:
    def setup_method(self):
        from src import perf_cacl
        self.mod = perf_cacl
        self.mod._STATE = self.mod.PerfState()

    def test_cost_disabled_no_effect(self, fake_config):
        fake_config.COST_AWARE_SELECT = False

        profile = ModelProfile(cost_per_1k_completion=1.6)
        profiles = {profile.name: profile}
        _, _, details = self.mod.adaptive_select(
            predicted_count=100.0,
            poll_interval=5.0,
            quality_bias=0.5,
            model_profiles=profiles,
        )
        assert details.get("cost_score", 0.0) == 0.0
        assert details.get("cost_saturated", 0.0) == 0.0

    def test_cost_zero_model_no_effect(self, fake_config):
        fake_config.COST_AWARE_SELECT = True
        fake_config.COST_BUDGET_PER_HOUR = 1.0

        profile = ModelProfile(cost_per_1k_completion=0.0)
        profiles = {profile.name: profile}
        _, _, details = self.mod.adaptive_select(
            predicted_count=100.0,
            poll_interval=5.0,
            quality_bias=0.5,
            model_profiles=profiles,
        )
        assert details.get("cost_score", 0.0) == 0.0

    def test_cost_pressure_raises_floor(self, fake_config):
        fake_config.COST_AWARE_SELECT = True
        fake_config.COST_BUDGET_PER_HOUR = 0.01
        fake_config.COST_WEIGHT = 1.0

        profile_expensive = ModelProfile(cost_per_1k_completion=10.0)
        profile_free = ModelProfile(cost_per_1k_completion=0.0)

        profiles_e = {profile_expensive.name: profile_expensive}
        _, _, details_e = self.mod.adaptive_select(
            predicted_count=100.0,
            poll_interval=5.0,
            quality_bias=0.0,
            model_profiles=profiles_e,
        )

        self.mod._STATE = self.mod.PerfState()
        profiles_f = {profile_free.name: profile_free}
        _, _, details_f = self.mod.adaptive_select(
            predicted_count=100.0,
            poll_interval=5.0,
            quality_bias=0.0,
            model_profiles=profiles_f,
        )

        assert details_e["quality_factor"] >= details_f["quality_factor"]

    def test_cost_saturated_signal(self, fake_config):
        fake_config.COST_AWARE_SELECT = True
        fake_config.COST_BUDGET_PER_HOUR = 0.001
        fake_config.COST_SATURATION_THRESHOLD = 0.9

        profile = ModelProfile(cost_per_1k_completion=100.0)
        profiles = {profile.name: profile}
        _, _, details = self.mod.adaptive_select(
            predicted_count=100.0,
            poll_interval=5.0,
            quality_bias=0.5,
            model_profiles=profiles,
        )
        assert details.get("cost_saturated", 0.0) == 1.0

    def test_cost_details_exposed(self, fake_config):
        fake_config.COST_AWARE_SELECT = True
        fake_config.COST_BUDGET_PER_HOUR = 1.0

        profile = ModelProfile(cost_per_1k_completion=1.6)
        profiles = {profile.name: profile}
        _, _, details = self.mod.adaptive_select(
            predicted_count=10.0,
            poll_interval=5.0,
            quality_bias=0.5,
            model_profiles=profiles,
        )
        for key in ("cost_score", "cost_rate", "cost_saturated",
                     "cost_remaining_hour", "cost_accumulated_hour"):
            assert key in details
