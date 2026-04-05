"""
app/services/user_service.py
──────────────────────────────
User management business logic (CRUD + activation).

Accessed only by ADMIN role, with the exception of get_by_id which is used
internally by the auth dependency.
"""

from __future__ import annotations

import math

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models import User
from app.schemas import PaginatedResponse, PaginationParams, UserCreate, UserOut, UserUpdate


class UserService:

    # ── Create ────────────────────────────────────────────────────────────────────

    @staticmethod
    async def create(payload: UserCreate, db: AsyncSession) -> User:
        """
        Create a new user.
        Raises 409 if a user with the same email already exists.
        """
        exists = await db.execute(
            select(User.id).where(User.email == payload.email)
        )
        if exists.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with email '{payload.email}' already exists.",
            )

        user = User(
            email=payload.email,
            password_hash=hash_password(payload.password),
            full_name=payload.full_name,
            role=payload.role,
        )
        db.add(user)
        await db.flush()
        await db.refresh(user)
        return user

    # ── Read ──────────────────────────────────────────────────────────────────────

    @staticmethod
    async def get_by_id(user_id: str, db: AsyncSession) -> User:
        result = await db.execute(
            select(User).where(User.id == user_id, User.deleted_at.is_(None))
        )
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        return user

    @staticmethod
    async def list_users(
        pagination: PaginationParams,
        db:         AsyncSession,
    ) -> PaginatedResponse[UserOut]:
        count_result = await db.execute(
            select(func.count(User.id)).where(User.deleted_at.is_(None))
        )
        total = count_result.scalar_one()

        result = await db.execute(
            select(User)
            .where(User.deleted_at.is_(None))
            .order_by(User.created_at.desc())
            .offset(pagination.offset)
            .limit(pagination.page_size)
        )
        users = result.scalars().all()

        return PaginatedResponse(
            items=[UserOut.model_validate(u) for u in users],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
            total_pages=math.ceil(total / pagination.page_size) if total else 0,
        )

    # ── Update ────────────────────────────────────────────────────────────────────

    @staticmethod
    async def update(user_id: str, payload: UserUpdate, db: AsyncSession) -> User:
        user = await UserService.get_by_id(user_id, db)

        for field, value in payload.model_dump(exclude_none=True).items():
            setattr(user, field, value)

        await db.flush()
        await db.refresh(user)
        return user

    # ── Delete (soft) ─────────────────────────────────────────────────────────────

    @staticmethod
    async def delete(user_id: str, requesting_user: User, db: AsyncSession) -> None:
        """
        Soft-delete a user.
        Prevents self-deletion to avoid accidental admin lockout.
        """
        if user_id == requesting_user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot delete your own account.",
            )

        user = await UserService.get_by_id(user_id, db)

        from datetime import datetime, timezone
        user.deleted_at = datetime.now(timezone.utc)
        user.is_active  = False
        await db.flush()
