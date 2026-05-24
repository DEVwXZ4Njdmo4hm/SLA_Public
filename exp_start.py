#!/usr/bin/env python3
"""Public RQ1 metric recomputation reference.

The private experiment runner used to orchestrate containers, replay PCAPs,
collect Elasticsearch documents, and trigger the SLA service. Those host-local
operations are intentionally omitted from the public repository.

This public script keeps the reviewer-facing RQ1 computation chain:

    main -> run_rq1 -> recompute_rq1_cell -> load/join data -> compute_metrics

It can recompute RQ1 metrics when `joined_data.jsonl` is available for each
cell. If only `es_data.jsonl` is available, pass `--ground-truth-dir` so the
script can recreate `joined_data` in memory before computing metrics. The
compact repository does not include the raw JSONL files; in that case the
script can still read existing `metrics.json` files unless
`--strict-recompute` is set.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_RQ1_SOURCE_ROOT = PROJECT_ROOT / "exp_data_and_reports" / "data" / "rq1"

RQ1_PRIORS = ("fair", "mismatch", "oracle")
RQ1_REPEATS = ("n1", "n2", "n3")
RQ1_MEMORY_CONFIGS = (
    "mem_none_hier",
    "mem_global_hier",
    "mem_global_rolling_hier",
    "mem_pair_hier",
    "mem_pair_rolling_hier",
)
RQ1_PCAP_DAYS = ("Tuesday", "Friday")

THREAT_LEVELS = ["无危", "低", "中", "高", "严重"]
THREAT_LEVEL_MAP = {v: i for i, v in enumerate(THREAT_LEVELS)}

log = logging.getLogger("exp_public")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load newline-delimited JSON records."""
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSONL record") from exc
            if not isinstance(obj, dict):
                raise ValueError(f"{path}:{lineno}: JSONL record must be an object")
            rows.append(obj)
    return rows


def save_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    """Save newline-delimited JSON records."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_ground_truth(csv_path: Path) -> dict[tuple[str, str, str, str], str]:
    """Load CIC-IDS2017 ground-truth CSV rows.

    The key is `(src_ip, dst_ip, src_port, dst_port)`. A bidirectional entry is
    inserted for each row, matching the original experiment script's behavior.
    If duplicate four-tuples exist, later CSV rows overwrite earlier labels.
    """
    truth: dict[tuple[str, str, str, str], str] = {}
    if not csv_path.is_file():
        log.warning("Ground-truth CSV not found: %s", csv_path)
        return truth

    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            src = row.get("Source IP", row.get(" Source IP", "")).strip()
            dst = row.get("Destination IP", row.get(" Destination IP", "")).strip()
            sp = row.get("Source Port", row.get(" Source Port", "")).strip()
            dp = row.get("Destination Port", row.get(" Destination Port", "")).strip()
            label = row.get("Label", row.get(" Label", "")).strip()

            if src and dst:
                truth[(src, dst, sp, dp)] = label
                truth[(dst, src, dp, sp)] = label

    return truth


def load_rq1_ground_truth(
    ground_truth_dir: Path,
    days: Iterable[str] = RQ1_PCAP_DAYS,
) -> dict[tuple[str, str, str, str], str]:
    """Load and merge the ground-truth CSVs used for the RQ1 PCAP days."""
    all_truth: dict[tuple[str, str, str, str], str] = {}
    for day in days:
        all_truth.update(load_ground_truth(ground_truth_dir / f"{day}.csv"))
    return all_truth


def join_with_ground_truth(
    docs: list[dict[str, Any]],
    truth: dict[tuple[str, str, str, str], str],
) -> list[dict[str, Any]]:
    """Attach `ground_truth_label` to ES-derived documents."""
    joined: list[dict[str, Any]] = []
    for doc in docs:
        src = str(doc.get("src_ip", ""))
        dst = str(doc.get("dest_ip", ""))
        sp = str(doc.get("src_port", ""))
        dp = str(doc.get("dest_port", ""))

        doc_copy = dict(doc)
        doc_copy["ground_truth_label"] = truth.get((src, dst, sp, dp), "UNKNOWN")
        joined.append(doc_copy)

    return joined


@dataclass
class ExperimentMetrics:
    """Quantitative metrics for a single RQ1 run."""

    config_group: str = ""
    total_docs: int = 0
    ai_processed: int = 0

    binary_tp: int = 0
    binary_fp: int = 0
    binary_tn: int = 0
    binary_fn: int = 0
    binary_precision: float = 0.0
    binary_recall: float = 0.0
    binary_f1: float = 0.0

    accuracy_5level: float = 0.0
    weighted_f1: float = 0.0
    precision_high: float = 0.0
    recall_high: float = 0.0

    consistency_mean_std: float = 0.0
    consistency_benign_mean_std: float = 0.0
    consistency_benign_pairs: int = 0

    threat_escalation_rho: float = 0.0
    threat_escalation_p_value: float = 1.0
    threat_escalation_pairs: int = 0

    latency_p50: float = 0.0
    latency_p95: float = 0.0
    latency_p99: float = 0.0

    per_event_type: dict[str, dict[str, Any]] = field(default_factory=dict)

    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExperimentMetrics":
        known = {field.name for field in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in known})


def _gt_label_to_binary(label: str) -> bool:
    """Convert ground-truth label to binary maliciousness."""
    return label not in ("BENIGN", "UNKNOWN", "")


def _threat_to_binary(level: str) -> bool:
    """Convert SLA threat level to binary maliciousness."""
    return level in ("中", "高", "严重")


def _gt_label_to_5level(label: str) -> str:
    """Map CIC-IDS2017 labels to the five-level SLA threat scale."""
    if label in ("BENIGN", "UNKNOWN", ""):
        return "无危"

    high_severity = {"Bot", "Infiltration", "Web Attack", "SSH-Patator", "FTP-Patator"}
    critical_severity = {
        "DDoS",
        "PortScan",
        "DoS Hulk",
        "DoS GoldenEye",
        "DoS slowloris",
        "DoS Slowhttptest",
        "Heartbleed",
    }

    for pattern in critical_severity:
        if pattern.lower() in label.lower():
            return "严重"
    for pattern in high_severity:
        if pattern.lower() in label.lower():
            return "高"

    return "中"


def _extract_ai_fields(doc: dict[str, Any]) -> tuple[bool, str, str]:
    """Read AI fields from either nested or dotted ES source keys."""
    ai = doc.get("ai", {}) if isinstance(doc.get("ai"), dict) else {}
    processed = ai.get("processed", doc.get("ai.processed", False))
    threat = ai.get("threat_level", doc.get("ai.threat_level", ""))
    processed_at = ai.get("processed_at", doc.get("ai.processed_at", ""))
    return bool(processed), str(threat), str(processed_at)


def compute_metrics(
    docs: list[dict[str, Any]],
    config_group: str,
) -> ExperimentMetrics:
    """Compute the RQ1 metrics from joined documents."""
    metrics = ExperimentMetrics(config_group=config_group)
    metrics.total_docs = len(docs)
    metrics.ai_processed = sum(1 for d in docs if _extract_ai_fields(d)[0])

    predictions: list[dict[str, Any]] = []
    for doc in docs:
        processed, threat, processed_at = _extract_ai_fields(doc)
        gt = str(doc.get("ground_truth_label", "UNKNOWN"))
        timestamp = str(doc.get("@timestamp", ""))

        if not processed or not threat or gt == "UNKNOWN":
            continue

        predictions.append({
            "threat_level": threat,
            "ground_truth": gt,
            "gt_5level": _gt_label_to_5level(gt),
            "timestamp": timestamp,
            "processed_at": processed_at,
            "src_ip": str(doc.get("src_ip", "")),
            "dest_ip": str(doc.get("dest_ip", "")),
            "event_type": str(doc.get("event_type", "unknown")),
        })

    if not predictions:
        log.warning("No processed, ground-truth-matched documents for %s", config_group)
        return metrics

    for pred in predictions:
        pred_mal = _threat_to_binary(pred["threat_level"])
        gt_mal = _gt_label_to_binary(pred["ground_truth"])

        if pred_mal and gt_mal:
            metrics.binary_tp += 1
        elif pred_mal and not gt_mal:
            metrics.binary_fp += 1
        elif not pred_mal and not gt_mal:
            metrics.binary_tn += 1
        else:
            metrics.binary_fn += 1

    if metrics.binary_tp + metrics.binary_fp > 0:
        metrics.binary_precision = metrics.binary_tp / (
            metrics.binary_tp + metrics.binary_fp
        )
    if metrics.binary_tp + metrics.binary_fn > 0:
        metrics.binary_recall = metrics.binary_tp / (
            metrics.binary_tp + metrics.binary_fn
        )
    if metrics.binary_precision + metrics.binary_recall > 0:
        metrics.binary_f1 = (
            2 * metrics.binary_precision * metrics.binary_recall
            / (metrics.binary_precision + metrics.binary_recall)
        )

    event_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for pred in predictions:
        event_groups[pred["event_type"]].append(pred)

    for event_type, group in sorted(event_groups.items()):
        tp = fp = tn = fn = 0
        for pred in group:
            pred_mal = _threat_to_binary(pred["threat_level"])
            gt_mal = _gt_label_to_binary(pred["ground_truth"])
            if pred_mal and gt_mal:
                tp += 1
            elif pred_mal and not gt_mal:
                fp += 1
            elif not pred_mal and not gt_mal:
                tn += 1
            else:
                fn += 1
        precision = tp / (tp + fp) if tp + fp > 0 else 0.0
        recall = tp / (tp + fn) if tp + fn > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall > 0 else 0.0
        metrics.per_event_type[event_type] = {
            "count": len(group),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    correct = sum(
        1 for pred in predictions
        if pred["threat_level"] == pred["gt_5level"]
    )
    metrics.accuracy_5level = correct / len(predictions)

    class_metrics: dict[str, dict[str, float | int]] = {}
    for cls in set(THREAT_LEVELS):
        tp = sum(
            1 for pred in predictions
            if pred["threat_level"] == cls and pred["gt_5level"] == cls
        )
        fp = sum(
            1 for pred in predictions
            if pred["threat_level"] == cls and pred["gt_5level"] != cls
        )
        fn = sum(
            1 for pred in predictions
            if pred["threat_level"] != cls and pred["gt_5level"] == cls
        )
        support = tp + fn
        precision = tp / (tp + fp) if tp + fp > 0 else 0.0
        recall = tp / (tp + fn) if tp + fn > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall > 0 else 0.0
        class_metrics[cls] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
        }

    total_support = sum(int(c["support"]) for c in class_metrics.values())
    if total_support > 0:
        metrics.weighted_f1 = sum(
            float(c["f1"]) * int(c["support"]) / total_support
            for c in class_metrics.values()
        )

    high_classes = {"高", "严重"}
    high_tp = sum(
        1 for pred in predictions
        if pred["threat_level"] in high_classes and pred["gt_5level"] in high_classes
    )
    high_fp = sum(
        1 for pred in predictions
        if pred["threat_level"] in high_classes
        and pred["gt_5level"] not in high_classes
    )
    high_fn = sum(
        1 for pred in predictions
        if pred["threat_level"] not in high_classes
        and pred["gt_5level"] in high_classes
    )

    if high_tp + high_fp > 0:
        metrics.precision_high = high_tp / (high_tp + high_fp)
    if high_tp + high_fn > 0:
        metrics.recall_high = high_tp / (high_tp + high_fn)

    pair_data: dict[str, dict[str, list[Any]]] = defaultdict(
        lambda: {"levels": [], "gt_labels": []}
    )
    for pred in predictions:
        pair_key = _comm_pair_key(pred["src_ip"], pred["dest_ip"])
        pair_data[pair_key]["levels"].append(THREAT_LEVEL_MAP.get(pred["threat_level"], 0))
        pair_data[pair_key]["gt_labels"].append(pred["ground_truth"])

    stds: list[float] = []
    for pair in pair_data.values():
        levels = [float(v) for v in pair["levels"]]
        if len(levels) >= 2:
            mean_level = sum(levels) / len(levels)
            var = sum((x - mean_level) ** 2 for x in levels) / len(levels)
            stds.append(var ** 0.5)
    metrics.consistency_mean_std = sum(stds) / len(stds) if stds else 0.0

    benign_stds: list[float] = []
    for pair in pair_data.values():
        if all(gt == "BENIGN" for gt in pair["gt_labels"]):
            levels = [float(v) for v in pair["levels"]]
            if len(levels) >= 2:
                mean_level = sum(levels) / len(levels)
                var = sum((x - mean_level) ** 2 for x in levels) / len(levels)
                benign_stds.append(var ** 0.5)
    metrics.consistency_benign_mean_std = (
        sum(benign_stds) / len(benign_stds) if benign_stds else 0.0
    )
    metrics.consistency_benign_pairs = len(benign_stds)

    pair_mean_levels: list[float] = []
    pair_attack_ratios: list[float] = []
    for pair in pair_data.values():
        levels = [float(v) for v in pair["levels"]]
        if len(levels) < 2:
            continue
        gt_labels = [str(v) for v in pair["gt_labels"]]
        pair_mean_levels.append(sum(levels) / len(levels))
        pair_attack_ratios.append(
            sum(1 for gt in gt_labels if gt != "BENIGN") / len(gt_labels)
        )

    metrics.threat_escalation_pairs = len(pair_mean_levels)
    if len(pair_mean_levels) >= 3:
        rho, p_value = _spearman_rank_corr(pair_mean_levels, pair_attack_ratios)
        metrics.threat_escalation_rho = rho
        metrics.threat_escalation_p_value = p_value

    latencies: list[float] = []
    for pred in predictions:
        if pred["timestamp"] and pred["processed_at"]:
            started = _parse_timestamp(pred["timestamp"])
            finished = _parse_timestamp(pred["processed_at"])
            if started and finished:
                latencies.append((finished - started).total_seconds())

    if latencies:
        latencies.sort()
        n = len(latencies)
        metrics.latency_p50 = latencies[int(n * 0.50)]
        metrics.latency_p95 = latencies[min(int(n * 0.95), n - 1)]
        metrics.latency_p99 = latencies[min(int(n * 0.99), n - 1)]

    return metrics


def _comm_pair_key(a: str, b: str) -> str:
    """Return an order-independent communication-pair key."""
    return f"{min(a, b)}<->{max(a, b)}"


def _spearman_rank_corr(x: list[float], y: list[float]) -> tuple[float, float]:
    """Compute Spearman rank correlation without scipy."""
    n = len(x)
    if n < 3:
        return 0.0, 1.0

    def _rank(values: list[float]) -> list[float]:
        indexed = sorted(range(n), key=lambda i: values[i])
        ranks = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j < n - 1 and values[indexed[j + 1]] == values[indexed[j]]:
                j += 1
            avg_rank = (i + j) / 2.0 + 1.0
            for k in range(i, j + 1):
                ranks[indexed[k]] = avg_rank
            i = j + 1
        return ranks

    rx = _rank(x)
    ry = _rank(y)
    mean_rx = sum(rx) / n
    mean_ry = sum(ry) / n
    cov = sum((rx[i] - mean_rx) * (ry[i] - mean_ry) for i in range(n))
    std_x = math.sqrt(sum((rx[i] - mean_rx) ** 2 for i in range(n)))
    std_y = math.sqrt(sum((ry[i] - mean_ry) ** 2 for i in range(n)))

    if std_x == 0 or std_y == 0:
        return 0.0, 1.0

    rho = cov / (std_x * std_y)
    if abs(rho) >= 1.0:
        return rho, 0.0

    t_stat = rho * math.sqrt((n - 2) / (1 - rho ** 2))
    p_value = math.erfc(abs(t_stat) / math.sqrt(2))
    return rho, p_value


def _parse_timestamp(ts: str | int | float) -> datetime | None:
    """Parse ISO timestamps or epoch milliseconds."""
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
    if isinstance(ts, str) and ts.isdigit() and len(ts) >= 10:
        return datetime.fromtimestamp(int(ts) / 1000, tz=timezone.utc)

    if isinstance(ts, str):
        s = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
    return None


def apply_rmi_stats(metrics: ExperimentMetrics, stats: dict[str, Any] | None) -> None:
    """Attach token totals collected by the runtime management interface."""
    if not stats:
        return
    metrics.total_prompt_tokens = int(stats.get("token_total_prompt", 0) or 0)
    metrics.total_completion_tokens = int(stats.get("token_total_completion", 0) or 0)


def _load_existing_metrics(path: Path) -> ExperimentMetrics:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: metrics JSON must be an object")
    return ExperimentMetrics.from_dict(data)


def _save_metrics(path: Path, metrics: ExperimentMetrics) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(metrics.to_dict(), f, indent=2, ensure_ascii=False)


def _load_cell_docs(
    cell_dir: Path,
    ground_truth_dir: Path | None,
    *,
    save_joined_to: Path | None = None,
) -> list[dict[str, Any]]:
    joined_path = cell_dir / "joined_data.jsonl"
    if joined_path.is_file():
        return load_jsonl(joined_path)

    raw_path = cell_dir / "es_data.jsonl"
    if raw_path.is_file():
        if ground_truth_dir is None:
            raise FileNotFoundError(
                f"{cell_dir}: es_data.jsonl exists but --ground-truth-dir was not provided"
            )
        truth = load_rq1_ground_truth(ground_truth_dir)
        joined = join_with_ground_truth(load_jsonl(raw_path), truth)
        if save_joined_to is not None:
            save_jsonl(save_joined_to, joined)
        return joined

    raise FileNotFoundError(
        f"{cell_dir}: expected joined_data.jsonl or es_data.jsonl"
    )


def recompute_rq1_cell(
    cell_dir: Path,
    output_dir: Path | None = None,
    ground_truth_dir: Path | None = None,
    *,
    strict_recompute: bool = False,
    save_joined: bool = False,
) -> ExperimentMetrics:
    """Recompute or load the metrics for one RQ1 cell."""
    cell_dir = Path(cell_dir)
    output_dir = Path(output_dir) if output_dir is not None else None
    joined_out = output_dir / "joined_data.jsonl" if output_dir and save_joined else None

    try:
        docs = _load_cell_docs(cell_dir, ground_truth_dir, save_joined_to=joined_out)
        metrics = compute_metrics(docs, cell_dir.name)
        stats_path = cell_dir / "rmi_stats.json"
        if stats_path.is_file():
            with stats_path.open("r", encoding="utf-8") as f:
                stats = json.load(f)
            if isinstance(stats, dict):
                apply_rmi_stats(metrics, stats)
    except FileNotFoundError:
        if strict_recompute:
            raise
        metrics_path = cell_dir / "metrics.json"
        if not metrics_path.is_file():
            raise
        metrics = _load_existing_metrics(metrics_path)

    if output_dir is not None:
        _save_metrics(output_dir / "metrics.json", metrics)

    return metrics


def iter_rq1_cells(source_root: Path) -> Iterable[tuple[str, str, str, Path]]:
    """Yield the complete 3 Prior x 3 Repeat x 5 Memory RQ1 grid."""
    for prior in RQ1_PRIORS:
        for repeat in RQ1_REPEATS:
            run_name = f"{prior}_{repeat}"
            for memory in RQ1_MEMORY_CONFIGS:
                yield prior, repeat, memory, source_root / run_name / memory


def run_rq1(
    source_root: Path = DEFAULT_RQ1_SOURCE_ROOT,
    result_dir: Path | None = None,
    ground_truth_dir: Path | None = None,
    *,
    strict_recompute: bool = False,
    save_joined: bool = False,
) -> list[ExperimentMetrics]:
    """Run the public RQ1 recomputation chain over the complete grid."""
    source_root = Path(source_root)
    result_dir = Path(result_dir) if result_dir is not None else None
    ground_truth_dir = Path(ground_truth_dir) if ground_truth_dir is not None else None

    all_metrics: list[ExperimentMetrics] = []
    comparison_rows: list[dict[str, Any]] = []

    for prior, repeat, memory, cell_dir in iter_rq1_cells(source_root):
        if not cell_dir.is_dir():
            raise FileNotFoundError(f"missing RQ1 cell directory: {cell_dir}")

        out_cell = result_dir / f"{prior}_{repeat}" / memory if result_dir else None
        metrics = recompute_rq1_cell(
            cell_dir,
            out_cell,
            ground_truth_dir,
            strict_recompute=strict_recompute,
            save_joined=save_joined,
        )
        all_metrics.append(metrics)
        comparison_rows.append({
            "prior": prior,
            "repeat": repeat,
            "memory": memory,
            "source_cell": str(cell_dir),
            "metrics": metrics.to_dict(),
        })

    if result_dir is not None:
        _save_rq1_comparison(comparison_rows, result_dir / "rq1_comparison.json")

    return all_metrics


def _save_rq1_comparison(rows: list[dict[str, Any]], path: Path) -> None:
    payload = {
        "design": "3 Prior x 5 Memory x n=3",
        "rows": rows,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Public RQ1 metric recomputation reference",
    )
    parser.add_argument(
        "--run",
        choices=["rq1"],
        default="rq1",
        help="Only RQ1 is retained in the public reference script.",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=DEFAULT_RQ1_SOURCE_ROOT,
        help="RQ1 root containing {prior}_n{1,2,3}/{memory}/ directories.",
    )
    parser.add_argument(
        "--save-result-into",
        type=Path,
        required=True,
        help="Directory where recomputed metrics/comparison JSON will be written.",
    )
    parser.add_argument(
        "--ground-truth-dir",
        type=Path,
        default=None,
        help="Directory containing Tuesday.csv and Friday.csv for raw es_data.jsonl.",
    )
    parser.add_argument(
        "--strict-recompute",
        action="store_true",
        help="Fail if a cell has no raw joined_data.jsonl/es_data.jsonl input.",
    )
    parser.add_argument(
        "--save-joined",
        action="store_true",
        help="When recomputing from es_data.jsonl, also save joined_data.jsonl.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    metrics = run_rq1(
        args.source_root,
        args.save_result_into,
        args.ground_truth_dir,
        strict_recompute=args.strict_recompute,
        save_joined=args.save_joined,
    )
    log.info("Processed %d RQ1 cells", len(metrics))
    log.info("Results saved to %s", args.save_result_into)


if __name__ == "__main__":
    main()
