from fastapi import APIRouter

from app.api.v1 import auth, health, platform

api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(health.router)
api_v1.include_router(platform.router)
api_v1.include_router(auth.router)
