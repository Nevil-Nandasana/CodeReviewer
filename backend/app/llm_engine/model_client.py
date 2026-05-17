"""
Unified Model Client — routes to local model or OpenAI based on MODEL_BACKEND env var.
Implements Redis caching keyed on SHA256(diff).
"""
from __future__ import annotations
import hashlib
import json
import time
import structlog

import redis as redis_lib

from app.config import settings
from app.llm_engine.prompt_builder import PromptBuilder
from app.llm_engine.response_parser import ResponseParser

logger = structlog.get_logger(__name__)

_local_model = None


def _get_local_model():
    global _local_model
    if _local_model is None:
        from app.llm_engine.local_model import LocalModelClient
        _local_model = LocalModelClient(settings.LOCAL_MODEL_PATH)
    return _local_model


class ModelClient:
    """Unified client — local model or OpenAI, with Redis caching."""

    def __init__(self, redis_client: redis_lib.Redis | None = None):
        self.redis = redis_client
        self.prompt_builder = PromptBuilder()
        self.response_parser = ResponseParser()

    def review(
        self,
        diff: str,
        ast_context=None,
        pre_flags: list[dict] | None = None,
        language: str = "python",
    ) -> tuple[list[dict], str, float]:
        """
        Run a code review. Returns (comments, model_name, inference_seconds).
        Checks Redis cache first keyed on SHA256(diff).
        """
        cache_key = f"review:{hashlib.sha256(diff.encode()).hexdigest()}"

        # Cache hit
        if self.redis:
            try:
                cached = self.redis.get(cache_key)
                if cached:
                    logger.info("review_cache_hit", key=cache_key[:16])
                    data = json.loads(cached)
                    return data["comments"], data["model"], 0.0
            except Exception:
                pass

        messages = self.prompt_builder.build(diff, ast_context, pre_flags, language)

        start = time.time()
        if settings.MODEL_BACKEND == "local":
            raw, model_name = self._call_local(messages)
        else:
            raw, model_name = self._call_openai(messages)
        elapsed = time.time() - start

        comments = self.response_parser.parse(raw)

        # Cache result
        if self.redis:
            try:
                self.redis.setex(
                    cache_key,
                    settings.REVIEW_CACHE_TTL,
                    json.dumps({"comments": comments, "model": model_name}),
                )
            except Exception:
                pass

        logger.info("review_complete", model=model_name, comments=len(comments), seconds=round(elapsed, 2))
        return comments, model_name, elapsed

    def _call_local(self, messages: list[dict]) -> tuple[str, str]:
        model = _get_local_model()
        raw = model.generate(messages, max_new_tokens=settings.MODEL_MAX_NEW_TOKENS)
        return raw, "deepseek-codereview-6.7b"

    def _call_openai(self, messages: list[dict]) -> tuple[str, str]:
        from openai import OpenAI
        client = OpenAI(api_key=settings.OPENAI_API_KEY)
        resp = client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            messages=messages,
            temperature=settings.MODEL_TEMPERATURE,
            max_tokens=settings.MODEL_MAX_NEW_TOKENS,
            response_format={"type": "json_object"},
        )
        raw = resp.choices[0].message.content or ""
        return raw, settings.OPENAI_MODEL

    def get_status(self) -> dict:
        status = {
            "backend": settings.MODEL_BACKEND,
            "model": settings.OPENAI_MODEL if settings.MODEL_BACKEND == "openai" else "deepseek-codereview-6.7b",
            "ready": True,
        }
        if settings.MODEL_BACKEND == "local":
            try:
                import torch
                status["vram_used_gb"] = round(torch.cuda.memory_allocated() / 1e9, 2)
                status["ready"] = _get_local_model().is_ready
            except Exception:
                status["vram_used_gb"] = None
        return status
