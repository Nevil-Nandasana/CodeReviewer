# Archived: failed hosted-API runs

These three runs recorded 200 cases each and produced zero usable predictions.
Every record is an OpenAI `429 insufficient_quota`:

    "json_valid": false,
    "predictions": [],
    "error": "RateLimitError: Error code: 429 ... insufficient_quota"

They are kept for provenance and moved out of `results/` so `evaluation.score`
(which globs `results/*.jsonl`, non-recursively) does not render them as
legitimate 0.0-precision rows. A run that failed is not a system that scored
zero, and the report must not conflate the two.

The scoring table now carries an `Error rate` column so this failure mode is
visible on the face of the report rather than disguised as poor performance.

The project subsequently moved to an all-local benchmark (see `results/report.md`).
To re-run these systems, fund an OpenAI key and:

    python -m evaluation.run_eval --systems gpt-4o-mini:v1,gpt-4o-mini:v2,hybrid:gpt-4o-mini:v2
