"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import Request

from app.core.config import Settings


def app_settings(request: Request) -> Settings:
    """The settings this application instance was created with (not the process global)."""
    settings: Settings = request.app.state.settings
    return settings
