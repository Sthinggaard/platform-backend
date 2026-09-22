"""
Timing configuration endpoints for UC-18 Typeform-like UX.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/timing", tags=["Timing"])


@router.get("/config")
def get_timing_config():
    """
    Return timing constants the frontend should honor.
    """
    return {
        "typing_ms": {"min": 350, "max": 800, "default": 500},
        "bubble_entry_ms": {"min": 120, "max": 180, "hard_max": 250, "default": 150},
        "option_stagger_ms": {"min": 50, "max": 80, "default": 60},
        "ack_delay_ms": {"max": 400, "default": 300},
        "working_indicator_threshold_ms": 1000,
    }
