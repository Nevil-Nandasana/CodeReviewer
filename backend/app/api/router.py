"""API Router — aggregates all v1 endpoints."""
from fastapi import APIRouter
from app.api.v1 import auth, webhook, reviews, repositories, security, quality, analytics, health

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["Auth"])
api_router.include_router(webhook.router, prefix="/webhook", tags=["Webhook"])
api_router.include_router(reviews.router, tags=["Reviews"])
api_router.include_router(repositories.router, prefix="/repositories", tags=["Repositories"])
api_router.include_router(security.router, prefix="/security", tags=["Security"])
api_router.include_router(quality.router, prefix="/quality", tags=["Quality"])
api_router.include_router(analytics.router, prefix="/analytics", tags=["Analytics"])
api_router.include_router(health.router, tags=["Health"])
