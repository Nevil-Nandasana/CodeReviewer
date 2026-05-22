# Superseded dataset pipeline

`prepare_dataset.py`, `augment_security.py`, `subsample.py` and `validate_format.py` were the
original SFT data pipeline. They are kept for provenance and are **not** wired into anything —
nothing outside this directory imports them, and `make build-data` does not call them.

They are archived rather than deleted because the old README told you to run

    python data/prepare_dataset.py
    python data/augment_security.py

and someone following those instructions would silently rebuild the dataset that motivated the
rewrite. A file that errors is better than a file that quietly produces bad training data.

## Why it was replaced

The old pipeline took real human review comments and wrapped each one as a label. Almost every
comment came out as:

```json
{"line": 1, "severity": "MEDIUM", "category": "quality"}
```

Training on that teaches the model to answer MEDIUM / quality / line-1 for everything, which
destroys exactly the two properties the benchmark measures — **severity calibration** and
**line localisation**. The labels were not wrong so much as constant, and a constant label
carries no gradient signal about the thing you care about.

`build_dataset.py` generates code and labels together, so line numbers and severities are exact
by construction. It also adds what the old pipeline had no way to provide:

- ~50% negative examples (matched safe twins and distractors, target `{"comments": []}`), so
  the model learns that silence is a valid answer
- a random 0–14 line noise prelude that shifts every ground-truth line, so the model has to
  count lines rather than memorise positions
- leakage control against the benchmark by exact hash and token Jaccard
- a **grouped train/val split on template family** — see `split_by_family`

## Use instead

```bash
python -m training.data.build_dataset --examples 6000
# or: make build-data
```
