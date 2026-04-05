"""
app/api/v1/endpoints/users.py
───────────────────────────────
User management endpoints (Admin only except /me).

GET    /users/me        – current user profile (any authenticated user)
GET    /users           – list all users (admin)
POST   /users           – create user (admin)
GET    /users/{id}      – get user by ID (admin)
PATCH  /users/{id}      – update user (admin)
DELETE /users/{id}      – soft-delete user (admin)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import (
    AdminOnly,
    AnyAuthenticatedUser,
    get_current_user,
    get_pagination,
    verify_csrf_token,
)
from app.db.session import get_db
from app.models import User
from app.schemas import PaginatedResponse, PaginationParams, UserCreate, UserOut, UserUpdate
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "/me",
    response_model=UserOut,
    summary="Get current user profile",
)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
) -> UserOut:
    return UserOut.model_validate(current_user)


@router.get(
    "",
    response_model=PaginatedResponse[UserOut],
    summary="List all users (admin)",
    dependencies=[Depends(AdminOnly)],
)
async def list_users(
    pagination: PaginationParams = Depends(get_pagination),
    db:         AsyncSession     = Depends(get_db),
) -> PaginatedResponse[UserOut]:
    return await UserService.list_users(pagination, db)


@router.post(
    "",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user (admin)",
    dependencies=[Depends(AdminOnly), Depends(verify_csrf_token)],
)
async def create_user(
    payload: UserCreate,
    db:      AsyncSession = Depends(get_db),
) -> UserOut:
    user = await UserService.create(payload, db)
    return UserOut.model_validate(user)


@router.get(
    "/{user_id}",
    response_model=UserOut,
    summary="Get user by ID (admin)",
    dependencies=[Depends(AdminOnly)],
)
async def get_user(
    user_id: str,
    db:      AsyncSession = Depends(get_db),
) -> UserOut:
    user = await UserService.get_by_id(user_id, db)
    return UserOut.model_validate(user)


@router.patch(
    "/{user_id}",
    response_model=UserOut,
    summary="Update user (admin)",
    dependencies=[Depends(AdminOnly), Depends(verify_csrf_token)],
)
async def update_user(
    user_id: str,
    payload: UserUpdate,
    db:      AsyncSession = Depends(get_db),
) -> UserOut:
    user = await UserService.update(user_id, payload, db)
    return UserOut.model_validate(user)


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Soft-delete user (admin)",
    dependencies=[Depends(verify_csrf_token)],
)
async def delete_user(
    user_id:      str,
    current_user: User         = Depends(AdminOnly),
    db:           AsyncSession = Depends(get_db),
) -> None:
    await UserService.delete(user_id, current_user, db)
