"""Shared FastAPI dependencies: per-app settings and security services."""

from __future__ import annotations

from fastapi import Request

from app.core.config import Settings
from app.security.mfa import MfaService
from app.security.passwords import PasswordHasher
from app.security.tokens import TokenService


def app_settings(request: Request) -> Settings:
    """The settings this application instance was created with (not the process global)."""
    settings: Settings = request.app.state.settings
    return settings


def token_service(request: Request) -> TokenService:
    service: TokenService = request.app.state.tokens
    return service


def password_hasher(request: Request) -> PasswordHasher:
    hasher: PasswordHasher = request.app.state.hasher
    return hasher


def mfa_service(request: Request) -> MfaService:
    service: MfaService = request.app.state.mfa
    return service
