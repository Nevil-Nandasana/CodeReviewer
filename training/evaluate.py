"""
Superseded. Model evaluation lives in `evaluation/`, not here.

This file used to score the fine-tune with BLEU-4 against reference review text,
plus a "security detection rate" computed by checking whether the generated
string contained any of the words critical / injection / sql / vulnerability.

Both measures were abandoned, and it is worth recording why rather than quietly
deleting the file:

  BLEU-4 rewards paraphrasing the reference comment. A model can score well by
  producing fluent prose about the wrong line, and score badly by finding the
  bug and describing it in different words. It measures surface similarity to
  one arbitrary phrasing, not whether the defect was found.

  Keyword matching is worse. "vulnerability" appears in the sentence "there is
  no vulnerability here", so the metric credits a model for saying the opposite
  of a finding. It also cannot tell whether the model pointed at the right line,
  named the right bug class, or invented the whole thing.

  Neither one can be wrong in a useful direction. If BLEU drops, you learn
  nothing about what to fix.

What replaced them measures findings instead of text: detection precision and
recall with greedy one-to-one matching on line *and* CWE class, localisation
error, false-positive rate on matched safe twins and distractor cases, severity
calibration with a bias sign, and 95% bootstrap confidence intervals resampled
over template families. See `evaluation/metrics.py`.

    # score a fine-tune on the benchmark
    python -m evaluation.run_eval --systems local-ft:<adapter>:v2 --split test

    # rank checkpoints by benchmark F1 rather than validation loss
    python -m evaluation.select_checkpoint --run <run-name> --split dev
"""
import sys

if __name__ == "__main__":
    sys.exit(__doc__)
