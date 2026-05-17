"""
Prompt Builder — constructs structured prompts for the LLM.

The prompt text itself lives in `app/llm_engine/prompts.py`, and the evaluation
harness imports it from there. It used to be duplicated in both places, which
meant the benchmark measured one prompt while production shipped another and any
conclusion drawn from an eval run was about a system nobody was running.

Production uses **v2**. v1 never tells the model it may return an empty list,
and on the benchmark that shows up as false positives on clean code; v2 states
that an empty list is the correct answer for correct code, defines the severity
levels, and fixes a line-numbering convention.
"""
from __future__ import annotations

import json

from app.ast_engine.extractor import ASTContext
from app.llm_engine.prompts import SYSTEM_PROMPTS, build_messages

PRODUCTION_PROMPT_VERSION = "v2"

# Re-exported so existing imports of SYSTEM_PROMPT keep working.
SYSTEM_PROMPT = SYSTEM_PROMPTS[PRODUCTION_PROMPT_VERSION]


class PromptBuilder:
    def __init__(self, version: str = PRODUCTION_PROMPT_VERSION):
        if version not in SYSTEM_PROMPTS:
            raise ValueError(f"unknown prompt version {version!r}")
        self.version = version

    def build(
        self,
        diff: str,
        ast_context: ASTContext | None,
        pre_flags: list[dict] | None = None,
        language: str = "python",
    ) -> list[dict]:
        """
        Build chat messages for a diff review.

        AST context is appended after the shared prompt body. Pre-flags are
        passed through to `build_messages`, which frames them as *claims to
        verify* rather than findings to repeat — the previous wording here told
        the model to "include them in your response with full explanations",
        which mechanically imported every false positive the rule scanner
        produced.
        """
        messages = build_messages(
            code=diff,
            filename=f"<diff>.{language}",
            language=language,
            pre_flags=pre_flags,
            version=self.version,
        )

        if ast_context is not None:
            ast_json = json.dumps(ast_context.to_dict(), indent=2)
            messages[-1]["content"] += (
                f"\n\n<ast_context>\n{ast_json}\n</ast_context>\n"
                "Static structure extracted from the file. Use it for context; "
                "it is not a list of defects."
            )

        return messages

    def build_single_file_prompt(self, code: str, filename: str) -> list[dict]:
        """Build prompt for single-file review (VS Code extension)."""
        language = filename.rsplit(".", 1)[-1] if "." in filename else "python"
        return build_messages(
            code=code, filename=filename, language=language, version=self.version
        )
