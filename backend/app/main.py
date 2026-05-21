"""
CodeReviewer FastAPI application entry point.
All middleware, routers, and startup hooks wired here.
"""
from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app

from app.config import settings
from app.api.router import api_router
from app.middleware.logging import LoggingMiddleware
from app.middleware.metrics import MetricsMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.db.session import Base, engine

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: ensure tables exist. Shutdown: log.

    `create_all` is skipped when the app is started with a dependency override
    for the DB session — that is what the test suite does, and calling it here
    would open a connection to the *production* engine before any override can
    take effect. That is precisely what made all ten API tests error out with a
    connection-refused against Postgres.

    It is also skipped in production, where Alembic owns the schema; leaving
    `create_all` enabled there lets a stale model definition silently diverge
    from the migration history.
    """
    logger.info("codereviewer_starting", version="1.0.0", model_backend=settings.MODEL_BACKEND)

    from app.config import insecure_settings, unknown_env_keys

    stray = unknown_env_keys()
    if stray:
        logger.warning("env_keys_ignored", keys=stray, hint="no Settings field consumes these")

    weak = insecure_settings()
    if weak:
        if settings.ENVIRONMENT == "production":
            raise RuntimeError(
                f"Refusing to start: {', '.join(weak)} still hold placeholder values. "
                "Generate real secrets before deploying."
            )
        logger.warning("placeholder_secrets_in_use", fields=weak)

    from app.dependencies import get_db

    overridden = get_db in app.dependency_overrides
    if overridden:
        logger.info("database_setup_skipped", reason="db_dependency_overridden")
    elif settings.ENVIRONMENT == "production":
        logger.info("database_setup_skipped", reason="alembic_owns_schema")
    else:
        Base.metadata.create_all(bind=engine)
        logger.info("database_tables_ready")

    yield
    logger.info("codereviewer_shutdown")


app = FastAPI(
    title="CodeReviewer API",
    description="AI-powered code review and security intelligence platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middleware (order matters — outer to inner) ────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(LoggingMiddleware)
app.add_middleware(MetricsMiddleware)
app.add_middleware(RateLimitMiddleware, max_requests=200, window_seconds=60)

# ── Prometheus metrics endpoint ────────────────────────────────────────────
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# ── API routes ─────────────────────────────────────────────────────────────
app.include_router(api_router, prefix="/api/v1")


# ── Health check (unauthenticated) ─────────────────────────────────────────
@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy", "version": "1.0.0"}


@app.get("/", tags=["Health"])
def root():
    return {"message": "CodeReviewer API", "docs": "/docs"}
