# Ground Truth Four-Tuple Conflict Key Report

## 1. Method

1. Use the actual join key described in `paper_draft.md`: `(src_ip, dst_ip, src_port, dst_port)`, with bidirectional canonicalization. Therefore, `A:port1 -> B:port2` and `B:port2 -> A:port1` are treated as the same key.
2. A conflict key refers to a canonicalized four-tuple that maps to more than one distinct `Label` value in the CIC-IDS2017 CSV rows. This is exactly the type of key for which `exp_start.py::load_ground_truth()` may overwrite an earlier label with a later one when building the dictionary.
3. The SLA evaluated subset uses the paper's main metric boundary: `ai.processed == true`, non-empty `ai.threat_level`, `ground_truth_label != UNKNOWN`, and a complete four-tuple key.

## 2. Summary

| Scope | Value |
|---|---:|
| Raw GT rows read | 1,149,154 |
| Unique bidirectional four-tuple keys in raw GT | 568,243 |
| Conflict keys in raw GT | 21,947 (3.8623%) |
| Raw GT rows attached to conflict keys | 96,575 (8.4040%) |
| Total scanned RQ1 JSONL docs | 163,564,963 |
| RQ1 evaluated docs | 289,521 |
| RQ1 evaluated unique keys | 7,297 |
| RQ1 evaluated conflict keys | 159 (2.1790%) |
| RQ1 evaluated docs falling on conflict keys | 1,563 (0.5399%) |
| Evaluated docs falling on binary-ambiguous conflict keys | 1,307 |
| Evaluated docs falling on severity-ambiguous conflict keys | 1,563 |

Across the 45 RQ1 runs, the per-run evaluated-key conflict rates are as follows:

| Statistic | Conflict key rate | Conflict doc rate |
|---|---:|---:|
| Min | 0.6265% | 0.2732% |
| Mean | 1.2664% | 0.5405% |
| Median | 1.3193% | 0.5510% |
| Max | 1.6829% | 0.7111% |

## 3. Ground Truth CSV Details

| File | Rows | Unique keys | Conflict keys | Conflict key rate | Conflict rows |
|---|---:|---:|---:|---:|---:|
| `exp_res/ground_truth/Tuesday.csv` | 445,909 | 211,625 | 1,600 | 0.7561% | 4,695 |
| `exp_res/ground_truth/Friday.csv` | 703,245 | 396,681 | 20,307 | 5.1192% | 91,691 |

## 4. RQ1 Main Evaluation Subset Details

| Prior/run | Memory config | Evaluated docs | Evaluated keys | Conflict keys | Conflict key rate | Conflict docs | Conflict doc rate |
|---|---|---:|---:|---:|---:|---:|---:|
| `fair_n1` | `mem_global_hier` | 6,400 | 2,833 | 40 | 1.4119% | 40 | 0.6250% |
| `fair_n1` | `mem_global_rolling_hier` | 6,274 | 2,590 | 22 | 0.8494% | 22 | 0.3507% |
| `fair_n1` | `mem_none_hier` | 6,051 | 2,561 | 34 | 1.3276% | 34 | 0.5619% |
| `fair_n1` | `mem_pair_hier` | 6,677 | 2,843 | 46 | 1.6180% | 46 | 0.6889% |
| `fair_n1` | `mem_pair_rolling_hier` | 6,100 | 2,670 | 38 | 1.4232% | 38 | 0.6230% |
| `fair_n2` | `mem_global_hier` | 6,688 | 2,868 | 38 | 1.3250% | 38 | 0.5682% |
| `fair_n2` | `mem_global_rolling_hier` | 6,617 | 2,861 | 41 | 1.4331% | 41 | 0.6196% |
| `fair_n2` | `mem_none_hier` | 6,328 | 2,784 | 37 | 1.3290% | 37 | 0.5847% |
| `fair_n2` | `mem_pair_hier` | 6,348 | 2,705 | 33 | 1.2200% | 33 | 0.5198% |
| `fair_n2` | `mem_pair_rolling_hier` | 6,491 | 2,752 | 37 | 1.3445% | 37 | 0.5700% |
| `fair_n3` | `mem_global_hier` | 6,443 | 2,765 | 39 | 1.4105% | 39 | 0.6053% |
| `fair_n3` | `mem_global_rolling_hier` | 6,286 | 2,744 | 29 | 1.0569% | 29 | 0.4613% |
| `fair_n3` | `mem_none_hier` | 6,549 | 2,630 | 28 | 1.0646% | 28 | 0.4275% |
| `fair_n3` | `mem_pair_hier` | 6,232 | 2,658 | 27 | 1.0158% | 27 | 0.4332% |
| `fair_n3` | `mem_pair_rolling_hier` | 6,538 | 2,671 | 30 | 1.1232% | 30 | 0.4589% |
| `mismatch_n1` | `mem_global_hier` | 6,520 | 2,767 | 41 | 1.4817% | 41 | 0.6288% |
| `mismatch_n1` | `mem_global_rolling_hier` | 6,579 | 2,764 | 24 | 0.8683% | 24 | 0.3648% |
| `mismatch_n1` | `mem_none_hier` | 6,515 | 2,796 | 33 | 1.1803% | 33 | 0.5065% |
| `mismatch_n1` | `mem_pair_hier` | 6,409 | 2,767 | 30 | 1.0842% | 30 | 0.4681% |
| `mismatch_n1` | `mem_pair_rolling_hier` | 6,681 | 2,705 | 29 | 1.0721% | 29 | 0.4341% |
| `mismatch_n2` | `mem_global_hier` | 6,513 | 2,719 | 22 | 0.8091% | 22 | 0.3378% |
| `mismatch_n2` | `mem_global_rolling_hier` | 6,300 | 2,653 | 35 | 1.3193% | 35 | 0.5556% |
| `mismatch_n2` | `mem_none_hier` | 6,617 | 2,775 | 29 | 1.0450% | 29 | 0.4383% |
| `mismatch_n2` | `mem_pair_hier` | 6,396 | 2,820 | 41 | 1.4539% | 41 | 0.6410% |
| `mismatch_n2` | `mem_pair_rolling_hier` | 6,515 | 2,879 | 41 | 1.4241% | 41 | 0.6293% |
| `mismatch_n3` | `mem_global_hier` | 6,543 | 2,853 | 45 | 1.5773% | 45 | 0.6878% |
| `mismatch_n3` | `mem_global_rolling_hier` | 6,328 | 2,674 | 45 | 1.6829% | 45 | 0.7111% |
| `mismatch_n3` | `mem_none_hier` | 6,353 | 2,716 | 42 | 1.5464% | 42 | 0.6611% |
| `mismatch_n3` | `mem_pair_hier` | 6,755 | 2,802 | 45 | 1.6060% | 45 | 0.6662% |
| `mismatch_n3` | `mem_pair_rolling_hier` | 6,354 | 2,828 | 45 | 1.5912% | 45 | 0.7082% |
| `oracle_n1` | `mem_global_hier` | 6,277 | 2,720 | 33 | 1.2132% | 33 | 0.5257% |
| `oracle_n1` | `mem_global_rolling_hier` | 6,418 | 2,764 | 40 | 1.4472% | 40 | 0.6232% |
| `oracle_n1` | `mem_none_hier` | 6,540 | 2,692 | 30 | 1.1144% | 30 | 0.4587% |
| `oracle_n1` | `mem_pair_hier` | 6,488 | 2,760 | 33 | 1.1957% | 33 | 0.5086% |
| `oracle_n1` | `mem_pair_rolling_hier` | 6,294 | 2,669 | 34 | 1.2739% | 34 | 0.5402% |
| `oracle_n2` | `mem_global_hier` | 6,600 | 2,714 | 30 | 1.1054% | 30 | 0.4545% |
| `oracle_n2` | `mem_global_rolling_hier` | 6,083 | 2,691 | 38 | 1.4121% | 38 | 0.6247% |
| `oracle_n2` | `mem_none_hier` | 6,456 | 2,796 | 34 | 1.2160% | 34 | 0.5266% |
| `oracle_n2` | `mem_pair_hier` | 6,588 | 2,873 | 18 | 0.6265% | 18 | 0.2732% |
| `oracle_n2` | `mem_pair_rolling_hier` | 6,045 | 2,626 | 35 | 1.3328% | 35 | 0.5790% |
| `oracle_n3` | `mem_global_hier` | 6,570 | 2,808 | 35 | 1.2464% | 35 | 0.5327% |
| `oracle_n3` | `mem_global_rolling_hier` | 6,030 | 2,591 | 40 | 1.5438% | 40 | 0.6633% |
| `oracle_n3` | `mem_none_hier` | 6,534 | 2,728 | 36 | 1.3196% | 36 | 0.5510% |
| `oracle_n3` | `mem_pair_hier` | 6,666 | 2,746 | 29 | 1.0561% | 29 | 0.4350% |
| `oracle_n3` | `mem_pair_rolling_hier` | 6,532 | 2,692 | 32 | 1.1887% | 32 | 0.4899% |

## 5. Conflict Labels Entering the Evaluation Scope

The table below lists the conflict keys with the largest number of evaluated documents. `Raw labels` denotes all labels that appeared for the bidirectional key in the selected CIC-IDS2017 CSV files; `Current joined labels` denotes the labels materialized into `joined_data.jsonl` after the current dictionary-based join.

| Rank | Key | Evaluated docs | Raw labels | Current joined labels | Binary ambiguity | Severity ambiguity |
|---:|---|---:|---|---|---:|---:|
| 1 | `172.16.0.1:49496 <-> 192.168.10.50:139` | 31 | BENIGN, PortScan | BENIGN:31 | Yes | Yes |
| 2 | `172.16.0.1:41526 <-> 192.168.10.50:445` | 24 | BENIGN, PortScan | BENIGN:24 | Yes | Yes |
| 3 | `172.16.0.1:49296 <-> 192.168.10.50:139` | 21 | BENIGN, PortScan | BENIGN:21 | Yes | Yes |
| 4 | `172.16.0.1:49320 <-> 192.168.10.50:139` | 21 | BENIGN, PortScan | BENIGN:21 | Yes | Yes |
| 5 | `172.16.0.1:46982 <-> 192.168.10.50:22` | 21 | BENIGN, SSH-Patator | SSH-Patator:21 | Yes | Yes |
| 6 | `172.16.0.1:41982 <-> 192.168.10.50:445` | 21 | BENIGN, PortScan | BENIGN:21 | Yes | Yes |
| 7 | `172.16.0.1:45078 <-> 192.168.10.50:22` | 20 | BENIGN, PortScan | BENIGN:20 | Yes | Yes |
| 8 | `172.16.0.1:41550 <-> 192.168.10.50:445` | 19 | BENIGN, PortScan | BENIGN:19 | Yes | Yes |
| 9 | `172.16.0.1:41750 <-> 192.168.10.50:445` | 19 | BENIGN, PortScan | BENIGN:19 | Yes | Yes |
| 10 | `172.16.0.1:45098 <-> 192.168.10.50:22` | 19 | BENIGN, PortScan | BENIGN:19 | Yes | Yes |
| 11 | `172.16.0.1:41812 <-> 192.168.10.50:445` | 19 | BENIGN, PortScan | BENIGN:19 | Yes | Yes |
| 12 | `172.16.0.1:46868 <-> 192.168.10.50:22` | 18 | BENIGN, SSH-Patator | SSH-Patator:18 | Yes | Yes |
| 13 | `172.16.0.1:50684 <-> 192.168.10.50:22` | 17 | PortScan, SSH-Patator | PortScan:17 | No | Yes |
| 14 | `172.16.0.1:49344 <-> 192.168.10.50:139` | 17 | BENIGN, PortScan | BENIGN:17 | Yes | Yes |
| 15 | `172.16.0.1:38374 <-> 192.168.10.50:22` | 17 | BENIGN, PortScan | BENIGN:17 | Yes | Yes |
| 16 | `172.16.0.1:48658 <-> 192.168.10.50:22` | 17 | PortScan, SSH-Patator | PortScan:17 | No | Yes |
| 17 | `172.16.0.1:47256 <-> 192.168.10.50:22` | 16 | PortScan, SSH-Patator | PortScan:16 | No | Yes |
| 18 | `172.16.0.1:50476 <-> 192.168.10.50:22` | 16 | PortScan, SSH-Patator | PortScan:16 | No | Yes |
| 19 | `172.16.0.1:45088 <-> 192.168.10.50:22` | 16 | BENIGN, PortScan | BENIGN:16 | Yes | Yes |
| 20 | `172.16.0.1:45068 <-> 192.168.10.50:22` | 16 | BENIGN, PortScan | BENIGN:16 | Yes | Yes |
| 21 | `172.16.0.1:49654 <-> 192.168.10.50:139` | 16 | BENIGN, PortScan | BENIGN:16 | Yes | Yes |
| 22 | `172.16.0.1:49368 <-> 192.168.10.50:139` | 15 | BENIGN, PortScan | BENIGN:15 | Yes | Yes |
| 23 | `172.16.0.1:41622 <-> 192.168.10.50:445` | 15 | BENIGN, PortScan | BENIGN:15 | Yes | Yes |
| 24 | `172.16.0.1:38660 <-> 192.168.10.50:22` | 15 | BENIGN, PortScan | BENIGN:15 | Yes | Yes |
| 25 | `172.16.0.1:49582 <-> 192.168.10.50:139` | 15 | BENIGN, PortScan | BENIGN:15 | Yes | Yes |
