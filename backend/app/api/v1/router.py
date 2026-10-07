from fastapi import APIRouter

from app.api.v1 import health, platform

api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(health.router)
api_v1.include_router(platform.router)
