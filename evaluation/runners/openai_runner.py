"""
Hosted-API baseline (gpt-4o-mini by default).

This is the system the product currently ships with, so it is the bar the local
fine-tune has to justify itself against — on quality, and on the cost and
latency numbers recorded alongside it.
"""
from __future__ import annotations

import os
import time

from evaluation.parsing import parse_review_output
from evaluation.prompts import build_messages
from evaluation.runners.base import Reviewer, load_env
from evaluation.schema import BenchmarkCase, CaseResult

# USD per 1M tokens (input, output).
PRICING: dict[str, tuple[float, float]] = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1": (2.00, 8.00),
}


class OpenAIReviewer(Reviewer):
    def __init__(
        self,
        model: str = "gpt-4o-mini",
        prompt_version: str = "v2",
        temperature: float = 0.0,
        max_tokens: int = 1200,
        name: str | None = None,
        max_retries: int = 4,
    ):
        load_env()
        from openai import OpenAI  # imported lazily so other runners don't need it

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY not set (checked env and backend/.env)")

        self.model = model
        self.prompt_version = prompt_version
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_retries = max_retries
        self.name = name or f"{model}-{prompt_version}"
        self.client = OpenAI(api_key=api_key)

    def _cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        rate_in, rate_out = PRICING.get(self.model, PRICING["gpt-4o-mini"])
        return (prompt_tokens * rate_in + completion_tokens * rate_out) / 1_000_000

    def review(self, case: BenchmarkCase, pre_flags: list[dict] | None = None) -> CaseResult:
        messages = build_messages(
            case.code, case.filename, case.language, pre_flags, self.prompt_version
        )

        def run():
            last_error: Exception | None = None
            for attempt in range(self.max_retries):
                try:
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=messages,
                        temperature=self.temperature,
                        max_tokens=self.max_tokens,
                        response_format={"type": "json_object"},
                    )
                    break
                except Exception as exc:  # noqa: BLE001 - retry transient API errors
                    last_error = exc
                    if attempt == self.max_retries - 1:
                        raise
                    time.sleep(2**attempt)
            else:  # pragma: no cover
                raise last_error  # type: ignore[misc]

            raw = response.choices[0].message.content or ""
            comments, strict = parse_review_output(raw)
            usage = response.usage
            prompt_tokens = usage.prompt_tokens if usage else 0
            completion_tokens = usage.completion_tokens if usage else 0
            return comments, strict, {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "cost_usd": self._cost(prompt_tokens, completion_tokens),
                "raw_output": raw,
            }

        return self._timed(case, run)
