"""
app/db/session.py
──────────────────
Async SQLAlchemy engine + session factory.

Why async?
  • FastAPI is an async framework; mixing sync SQLAlchemy blocks the event loop.
  • AsyncSession enables proper connection pool usage under load.

Swapping databases:
  Change DATABASE_URL in .env.
    SQLite   → sqlite+aiosqlite:///./data/finance.db   (dev / tests)
    Postgres → postgresql+asyncpg://user:pass@host/db  (staging / prod)

The engine is created once at import time (module-level singleton pattern).
The session factory is a dependency injected into every route that needs DB access.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings, Environment

# ── Engine ────────────────────────────────────────────────────────────────────────

_connect_args: dict = {}
_engine_kwargs: dict = {
    "echo": settings.DEBUG,   # logs SQL when DEBUG=True
}

if "sqlite" in settings.DATABASE_URL:
    # SQLite: disable the check_same_thread restriction (not needed for async)
    _connect_args["check_same_thread"] = False
else:
    # PostgreSQL / other RDBMS: apply pool settings
    _engine_kwargs.update({
        "pool_size":     settings.DATABASE_POOL_SIZE,
        "max_overflow":  settings.DATABASE_MAX_OVERFLOW,
        "pool_timeout":  settings.DATABASE_POOL_TIMEOUT,
        "pool_pre_ping": True,   # verify connections before checkout
    })

engine = create_async_engine(
    settings.DATABASE_URL,
    connect_args=_connect_args,
    **_engine_kwargs,
)

# ── Session Factory ───────────────────────────────────────────────────────────────

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,   # avoids lazy-load errors on detached objects after commit
    autocommit=False,
    autoflush=False,
)

# ── FastAPI Dependency ────────────────────────────────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yield an async database session for the duration of a single request.

    Usage in a route:
        @router.get("/example")
        async def example(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
