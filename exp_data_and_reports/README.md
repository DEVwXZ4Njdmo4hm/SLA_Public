# Experiment Data and Reports

This directory contains the compact, reviewer-facing artifacts for the RQ1 experiments, the manuscript supplementary material, and the supplementary mini experiment. It is intended to make the reported tables, statistical summaries, configuration snapshots, and representative case studies inspectable without requiring reviewers to download the full raw production JSONL logs.

## Directory Layout

```text
exp_data_and_reports/
├── README.md
├── reports/
│   ├── exp_res_all.md
│   ├── art_anova_results_report.md
│   └── ground_truth_key_conflict_report.md
├── supplementary/
│   ├── supp_table_s1_15_cell_means.md
│   ├── supp_table_s2_45_run_aggregates.md
│   ├── supp_table_s3_per_event_metrics.md
│   ├── supp_table_s4_operational_cost.md
│   └── supp_artifact_s5_case_study.md
├── case_study_artifacts/
│   ├── rq1_case_study_artifact.json
│   └── rq1_case_study_artifact.md
└── data/
    ├── rq1/
    │   ├── fair_n1/ ... fair_n3/
    │   ├── mismatch_n1/ ... mismatch_n3/
    │   ├── oracle_n1/ ... oracle_n3/
    └── mini_exp/
        ├── mem_pair_proto_hier/
        └── mem_pair_proto_rolling_hier/
```

## Reports

`reports/` contains English Markdown reports derived from the experiment outputs:

- `exp_res_all.md`: the main RQ1 metric table for the complete `3 Prior x 5 Memory x n=3` design.
- `art_anova_results_report.md`: ART ANOVA results and diagnostic summaries used for the main statistical interpretation.
- `ground_truth_key_conflict_report.md`: analysis of CIC-IDS2017 four-tuple ground-truth label conflicts and their exposure in the evaluated RQ1 subset.

These files are the most convenient entry point for checking the reported numerical results.

## Supplementary Material

`supplementary/` contains the Markdown supplementary files referenced by the manuscript:

- `supp_table_s1_15_cell_means.md`: full 15-cell mean table for the `3 Prior x 5 Memory` design.
- `supp_table_s2_45_run_aggregates.md`: full 45-run aggregate table, one row per retained run and memory condition.
- `supp_table_s3_per_event_metrics.md`: per-event-type metrics for alert, http, smb, ssh, and tls.
- `supp_table_s4_operational_cost.md`: prompt-token and completion-token cost table.
- `supp_artifact_s5_case_study.md`: index to the case-study artifacts mirrored in `case_study_artifacts/`.

These files are kept as editable Markdown so that reviewers can inspect the exact tables and pointers without relying on generated PDF formatting. They mirror the manuscript supplementary package; the larger machine-readable case-study record remains in `case_study_artifacts/`.

## RQ1 Data

`data/rq1/` contains the compact per-run artifacts for the main experiment. The layout is:

```text
data/rq1/{prior}_n{1,2,3}/{memory_config}/
```

where `prior` is one of `fair`, `mismatch`, or `oracle`, and `memory_config` is one of:

- `mem_none_hier`
- `mem_global_hier`
- `mem_global_rolling_hier`
- `mem_pair_hier`
- `mem_pair_rolling_hier`

Each of the 45 RQ1 cells contains:

- `metrics.json`: per-run evaluation metrics.
- `rmi_stats.json`: runtime memory instrumentation statistics.
- `config_snapshot/`: the configuration files captured for that run.

The full RQ1 `es_data.jsonl` and `joined_data.jsonl` files are not included in this repository.

## Mini Experiment Data

`data/mini_exp/` contains artifacts for the supplementary prototype-memory mini experiment:

- `mem_pair_proto_hier/`
- `mem_pair_proto_rolling_hier/`

These directories follow the same general artifact pattern as the main RQ1 runs: metrics, runtime memory statistics, configuration snapshots, and the experiment-level JSONL files available in the compact working copy.

## Case Study Artifacts

`case_study_artifacts/` contains representative case-study material used to explain selected RQ1 result patterns:

- `rq1_case_study_artifact.json`: machine-readable case-study artifact.
- `rq1_case_study_artifact.md`: human-readable case-study artifact.

Some model outputs and event summaries in the case-study material are preserved in Chinese because they are verbatim outputs from the SLA production workflow. The surrounding field names, reconstruction boundaries, and case-study explanations are provided in English, while the quoted case data are kept in their original language to avoid changing the evidence.

## Raw Data

The full raw RQ1 JSONL artifacts are too large (about 119 GiB) for direct inclusion in this repository.
They are being uploaded separately to OneDrive

[Onedrive Link](https://1drv.ms/f/c/f9301aaf61780f63/IgDSneD2RWJWRKVFXzFVrUOYAfLM-heFLjtEWmAP3h1arcw)

## Notes for Reviewers

The compact artifacts in this directory are sufficient for inspecting the reported metrics, statistical summaries, configuration snapshots, and representative case-study evidence. The external raw-data location is intended for reviewers or readers who need to inspect the full event-level `es_data.jsonl` and `joined_data.jsonl` records.

For a quick review path, start with `reports/`, then inspect `supplementary/` for the manuscript-facing tables, and use `case_study_artifacts/` when the case-study reconstruction details are needed.
