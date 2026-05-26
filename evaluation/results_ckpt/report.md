# CodeReviewer benchmark results — `dev` split

40 cases: 15 vulnerable, 15 matched safe twins, 10 distractors. Intervals are 95% bootstrap CIs resampled over template families.

## Detection and usability

| System | Precision | Recall | F1 | Clean-code flag rate ↓ | FP/clean case ↓ | JSON valid | Error rate ↓ | p50 latency | $/100 reviews |
|---|---|---|---|---|---|---|---|---|---|
| `ft-checkpoint-200` | 55.6 [20–100] | 33.3 [8–57] | 41.7 [12–67] | 4.0 [0–12] | 0.04 | 95.0% | 0.0% | 0.65s | $0.000 |
| `ft-checkpoint-150` | 30.0 [12–53] | 40.0 [17–67] | 34.3 [14–57] | 36.0 [16–56] | 0.36 | 95.0% | 0.0% | 11.07s | $0.000 |
| `ft-checkpoint-50` | 40.0 [0–100] | 13.3 [0–33] | 20.0 [0–45] | 4.0 [0–12] | 0.04 | 92.5% | 0.0% | 0.70s | $0.000 |

## Localization and diagnosis

| System | Recall (type must match) | Recall (line only) | Diagnosis gap | Exact line | Mean line error |
|---|---|---|---|---|---|
| `ft-checkpoint-200` | 33.3% | 40.0% | 6.7% | 50.0% | 0.67 |
| `ft-checkpoint-150` | 40.0% | 60.0% | 20.0% | 55.6% | 0.67 |
| `ft-checkpoint-50` | 13.3% | 20.0% | 6.7% | 66.7% | 0.33 |

*Diagnosis gap = found the right line but named the wrong bug class.*


## Severity calibration

| System | Exact severity | Mean ordinal error | Bias (+ = over-escalates) |
|---|---|---|---|
| `ft-checkpoint-200` | 80.0% | 0.20 | +0.20 |
| `ft-checkpoint-150` | 83.3% | 0.17 | +0.17 |
| `ft-checkpoint-50` | 100.0% | 0.00 | +0.00 |

## Recall by CWE

| CWE | Vulnerability | `ft-checkpoint-200` | `ft-checkpoint-150` | `ft-checkpoint-50` |
|---|---|---|---|---|
| CWE-209 | Information Exposure Through Error Message | 0/1 | 0/1 | 0/1 |
| CWE-22 | Path Traversal | 1/1 | 1/1 | 0/1 |
| CWE-295 | Improper Certificate Validation | 0/1 | 1/1 | 0/1 |
| CWE-306 | Missing Authentication | 1/1 | 0/1 | 0/1 |
| CWE-327 | Broken or Risky Crypto | 1/1 | 1/1 | 0/1 |
| CWE-502 | Insecure Deserialization | 0/2 | 0/2 | 0/2 |
| CWE-78 | OS Command Injection | 1/2 | 1/2 | 1/2 |
| CWE-79 | Cross-site Scripting | 0/2 | 0/2 | 0/2 |
| CWE-798 | Hardcoded Credentials | 0/1 | 0/1 | 0/1 |
| CWE-89 | SQL Injection | 0/2 | 2/2 | 1/2 |
| CWE-94 | Code Injection | 1/1 | 0/1 | 0/1 |

## Held-out families

Four families (SSRF, XXE, weak randomness, file permissions) never appear in the dev split and are excluded from training-data generation, so their per-CWE rows above measure generalization to bug classes the system was not tuned on.

