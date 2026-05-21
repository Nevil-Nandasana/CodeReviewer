"""Prometheus metrics middleware."""
import time
from prometheus_client import Counter, Histogram
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

REQUEST_COUNT = Counter(
    "codereviewer_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status_code"],
)

REQUEST_LATENCY = Histogram(
    "codereviewer_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "path"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

REVIEW_COUNT = Counter(
    "codereviewer_reviews_total",
    "Total code reviews run",
    ["model", "status"],
)

INFERENCE_LATENCY = Histogram(
    "codereviewer_model_inference_seconds",
    "LLM inference latency",
    buckets=[0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 30.0],
)


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.time()
        response = await call_next(request)
        elapsed = time.time() - start
        path = request.url.path
        # Don't track metrics endpoint itself
        if path != "/metrics":
            REQUEST_COUNT.labels(
                method=request.method, path=path, status_code=str(response.status_code)
            ).inc()
            REQUEST_LATENCY.labels(method=request.method, path=path).observe(elapsed)
        return response
