"""Health and model status endpoints."""
from fastapi import APIRouter
from app.config import settings

router = APIRouter()


@router.get("/model/status")
def model_status():
    """Show model backend, VRAM usage, and readiness."""
    status = {
        "backend": settings.MODEL_BACKEND,
        "model": settings.OPENAI_MODEL if settings.MODEL_BACKEND == "openai" else "deepseek-codereview-6.7b",
        "ready": True,
        "vram_used_gb": None,
        "inference_count_today": 0,
    }
    if settings.MODEL_BACKEND == "local":
        try:
            import torch
            if torch.cuda.is_available():
                status["vram_used_gb"] = round(torch.cuda.memory_allocated() / 1e9, 2)
                status["vram_total_gb"] = round(torch.cuda.get_device_properties(0).total_memory / 1e9, 1)
                status["gpu_name"] = torch.cuda.get_device_name(0)
        except Exception:
            pass
    return status
