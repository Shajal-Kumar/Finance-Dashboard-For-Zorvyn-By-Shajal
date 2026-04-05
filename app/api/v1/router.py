"""
app/api/v1/router.py
─────────────────────
Aggregates all v1 endpoint routers into a single APIRouter
that is mounted on the FastAPI app in main.py.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import auth, dashboard, records, users

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(records.router)
api_router.include_router(dashboard.router)
