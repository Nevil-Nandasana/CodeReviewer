"""
Versioned prompts — re-exported from the production package.

The definitions live in `backend/app/llm_engine/prompts.py` and this module is a
thin alias. They were previously duplicated, which meant the benchmark could
measure one prompt while production shipped another, and every conclusion drawn
from an eval run would be about a system nobody was running.

The dependency points evaluation -> backend rather than the reverse, because the
backend image only copies `backend/`; a production import of `evaluation` would
break the container.

  v1 — the prompt the pipeline originally shipped with.
  v2 — adds an explicit "report nothing if nothing is wrong" instruction, a line
       numbering convention, and severity definitions. v1 never tells the model
       it is allowed to return an empty list, which is a plausible driver of
       false positives on clean code; v2 lets us measure whether that is true.

Comparing v1 vs v2 on the same model is itself an ablation row. Every result
record stores the prompt version that produced it.
"""
from __future__ import annotations

from evaluation.runners.base import add_backend_to_path

add_backend_to_path()

from app.llm_engine.prompts import (  # noqa: E402
    SCHEMA,
    SYSTEM_PROMPTS,
    V1_SYSTEM,
    V2_SYSTEM,
    build_messages,
)

__all__ = ["SCHEMA", "SYSTEM_PROMPTS", "V1_SYSTEM", "V2_SYSTEM", "build_messages"]
