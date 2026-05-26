# CodeReviewer benchmark results — `test` split

200 cases: 80 vulnerable, 80 matched safe twins, 40 distractors. Intervals are 95% bootstrap CIs resampled over template families.

## Detection and usability

| System | Precision | Recall | F1 | Clean-code flag rate ↓ | FP/clean case ↓ | JSON valid | Error rate ↓ | p50 latency | $/100 reviews |
|---|---|---|---|---|---|---|---|---|---|
| `rules-only` | 88.2 [75–100] | 75.0 [53–94] | 81.1 [66–93] | 0.0 [0–0] | 0.00 | 100.0% | 0.0% | 0.00s | $0.000 |
| `hybrid-Qwen2.5-Coder-1.5B-Instruct-ft-v2` | 59.5 [32–89] | 31.2 [14–52] | 41.0 [20–62] | 2.5 [0–8] | 0.03 | 96.0% | 0.0% | 0.64s | $0.000 |
| `Qwen2.5-Coder-1.5B-Instruct-ft-checkpoint-200-v2` | 34.9 [9–79] | 18.8 [5–37] | 24.4 [7–46] | 11.7 [2–24] | 0.12 | 96.0% | 0.0% | 1.22s | $0.000 |
| `Qwen2.5-Coder-1.5B-Instruct-base-v2` | 14.2 [7–22] | 36.2 [19–55] | 20.4 [10–31] | 93.3 [85–99] | 1.02 | 0.0% | 0.0% | 7.17s | $0.000 |
| `Qwen2.5-Coder-1.5B-Instruct-base-v1` | 12.3 [7–18] | 43.8 [26–63] | 19.2 [12–28] | 95.8 [92–99] | 1.48 | 0.0% | 0.0% | 8.68s | $0.000 |
| `Qwen2.5-Coder-1.5B-Instruct-ft-v2` | 42.1 [0–100] | 10.0 [0–26] | 16.2 [0–38] | 2.5 [0–8] | 0.03 | 94.5% | 0.0% | 0.68s | $0.000 |

## Localization and diagnosis

| System | Recall (type must match) | Recall (line only) | Diagnosis gap | Exact line | Mean line error |
|---|---|---|---|---|---|
| `rules-only` | 75.0% | 75.0% | 0.0% | 86.7% | 0.13 |
| `hybrid-Qwen2.5-Coder-1.5B-Instruct-ft-v2` | 31.2% | 36.2% | 5.0% | 72.4% | 0.28 |
| `Qwen2.5-Coder-1.5B-Instruct-ft-checkpoint-200-v2` | 18.8% | 30.0% | 11.2% | 37.5% | 0.79 |
| `Qwen2.5-Coder-1.5B-Instruct-base-v2` | 36.2% | 88.8% | 52.5% | 43.7% | 0.93 |
| `Qwen2.5-Coder-1.5B-Instruct-base-v1` | 43.8% | 81.2% | 37.5% | 26.2% | 1.25 |
| `Qwen2.5-Coder-1.5B-Instruct-ft-v2` | 10.0% | 15.0% | 5.0% | 66.7% | 0.33 |

*Diagnosis gap = found the right line but named the wrong bug class.*


## Severity calibration

| System | Exact severity | Mean ordinal error | Bias (+ = over-escalates) |
|---|---|---|---|
| `rules-only` | 100.0% | 0.00 | +0.00 |
| `hybrid-Qwen2.5-Coder-1.5B-Instruct-ft-v2` | 60.0% | 0.56 | +0.56 |
| `Qwen2.5-Coder-1.5B-Instruct-ft-checkpoint-200-v2` | 73.3% | 0.27 | +0.27 |
| `Qwen2.5-Coder-1.5B-Instruct-base-v2` | 17.2% | 1.31 | -1.24 |
| `Qwen2.5-Coder-1.5B-Instruct-base-v1` | 20.0% | 1.00 | -0.60 |
| `Qwen2.5-Coder-1.5B-Instruct-ft-v2` | 100.0% | 0.00 | +0.00 |

## Recall by CWE

| CWE | Vulnerability | `rules-only` | `hybrid-Qwen2.5-Coder-1.5B-Instruct-ft-v2` | `Qwen2.5-Coder-1.5B-Instruct-ft-checkpoint-200-v2` | `Qwen2.5-Coder-1.5B-Instruct-base-v2` | `Qwen2.5-Coder-1.5B-Instruct-base-v1` | `Qwen2.5-Coder-1.5B-Instruct-ft-v2` |
|---|---|---|---|---|---|---|---|
| CWE-209 | Information Exposure Through Error Message | 4/4 | 0/4 | 0/4 | 0/4 | 1/4 | 0/4 |
| CWE-22 | Path Traversal | 4/4 | 2/4 | 2/4 | 4/4 | 4/4 | 0/4 |
| CWE-295 | Improper Certificate Validation | 4/4 | 4/4 | 0/4 | 0/4 | 1/4 | 0/4 |
| CWE-306 | Missing Authentication | 4/4 | 0/4 | 1/4 | 0/4 | 0/4 | 0/4 |
| CWE-327 | Broken or Risky Crypto | 4/4 | 4/4 | 4/4 | 0/4 | 3/4 | 0/4 |
| CWE-330 | Insufficiently Random Values | 0/5 | 0/5 | 0/5 | 1/5 | 0/5 | 0/5 |
| CWE-502 | Insecure Deserialization | 8/8 | 0/8 | 0/8 | 2/8 | 0/8 | 0/8 |
| CWE-611 | XML External Entity | 0/5 | 0/5 | 0/5 | 2/5 | 3/5 | 0/5 |
| CWE-732 | Incorrect Permission Assignment | 0/5 | 0/5 | 0/5 | 5/5 | 4/5 | 0/5 |
| CWE-78 | OS Command Injection | 8/8 | 7/8 | 4/8 | 0/8 | 5/8 | 4/8 |
| CWE-79 | Cross-site Scripting | 8/8 | 0/8 | 0/8 | 3/8 | 8/8 | 0/8 |
| CWE-798 | Hardcoded Credentials | 4/4 | 0/4 | 0/4 | 0/4 | 0/4 | 0/4 |
| CWE-89 | SQL Injection | 8/8 | 8/8 | 0/8 | 8/8 | 6/8 | 4/8 |
| CWE-918 | Server-Side Request Forgery | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| CWE-94 | Code Injection | 4/4 | 0/4 | 4/4 | 4/4 | 0/4 | 0/4 |

## Held-out families

Four families (SSRF, XXE, weak randomness, file permissions) never appear in the dev split and are excluded from training-data generation, so their per-CWE rows above measure generalization to bug classes the system was not tuned on.

