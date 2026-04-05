"""
scripts/seed.py
────────────────
Bootstrap script: creates an admin user, two regular users, and sample
financial records so you can test the API immediately after setup.

Run:
    python scripts/seed.py

Safe to re-run: skips records that already exist.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Ensure project root is on sys.path when running as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.db.base import Base
from app.db.session import AsyncSessionLocal, engine
from app.models import FinancialRecord, TransactionType, User, UserRole


# ── Sample data ────────────────────────────────────────────────────────────────────

SEED_USERS = [
    {
        "email":     "admin@finance.local",
        "password":  "Admin1234secure!",
        "full_name": "System Administrator",
        "role":      UserRole.ADMIN,
    },
    {
        "email":     "analyst@finance.local",
        "password":  "Analyst1234secure!",
        "full_name": "Finance Analyst",
        "role":      UserRole.ANALYST,
    },
    {
        "email":     "viewer@finance.local",
        "password":  "Viewer1234secure!",
        "full_name": "Dashboard Viewer",
        "role":      UserRole.VIEWER,
    },
]

SEED_RECORDS = [
    {"amount": 85000.00, "type": TransactionType.INCOME,  "category": "Salary",      "date": "2024-01-15", "notes": "Monthly salary"},
    {"amount":  3200.00, "type": TransactionType.EXPENSE, "category": "Rent",         "date": "2024-01-01", "notes": "Office rent"},
    {"amount":  1500.00, "type": TransactionType.EXPENSE, "category": "Software",     "date": "2024-01-10", "notes": "SaaS subscriptions"},
    {"amount":  5000.00, "type": TransactionType.INCOME,  "category": "Consulting",   "date": "2024-02-20", "notes": "Q1 consulting project"},
    {"amount":   800.00, "type": TransactionType.EXPENSE, "category": "Marketing",    "date": "2024-02-05", "notes": "Ad spend"},
    {"amount": 12000.00, "type": TransactionType.INCOME,  "category": "Sales",        "date": "2024-03-01", "notes": "Product sales"},
    {"amount":  2200.00, "type": TransactionType.EXPENSE, "category": "Payroll",      "date": "2024-03-15", "notes": "Contractor payment"},
    {"amount":   350.00, "type": TransactionType.EXPENSE, "category": "Travel",       "date": "2024-03-22", "notes": "Client visit"},
    {"amount":  9500.00, "type": TransactionType.INCOME,  "category": "Consulting",   "date": "2024-04-10", "notes": "April consulting"},
    {"amount":  3200.00, "type": TransactionType.EXPENSE, "category": "Rent",         "date": "2024-04-01", "notes": "Office rent"},
]


# ── Seed logic ─────────────────────────────────────────────────────────────────────

async def seed() -> None:
    # Ensure tables exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        admin_user = await _seed_users(db)
        await _seed_records(db, admin_user)
        await db.commit()

    print("\n✓ Seed complete.")
    print("\nTest credentials:")
    for u in SEED_USERS:
        print(f"  {u['role'].value:<10}  {u['email']}  /  {u['password']}")
    print()


async def _seed_users(db: AsyncSession) -> User:
    admin = None
    for data in SEED_USERS:
        existing = await db.execute(select(User).where(User.email == data["email"]))
        if existing.scalar_one_or_none():
            print(f"  skip user  {data['email']}  (already exists)")
            if data["role"] == UserRole.ADMIN:
                result = await db.execute(select(User).where(User.email == data["email"]))
                admin  = result.scalar_one()
            continue

        user = User(
            email=data["email"],
            password_hash=hash_password(data["password"]),
            full_name=data["full_name"],
            role=data["role"],
        )
        db.add(user)
        await db.flush()
        print(f"  created    {data['email']}  ({data['role'].value})")
        if data["role"] == UserRole.ADMIN:
            admin = user

    return admin


async def _seed_records(db: AsyncSession, admin_user: User) -> None:
    for data in SEED_RECORDS:
        record = FinancialRecord(
            amount=data["amount"],
            type=data["type"],
            category=data["category"],
            date=data["date"],
            notes=data.get("notes"),
            created_by_user_id=admin_user.id,
        )
        db.add(record)

    await db.flush()
    print(f"  created    {len(SEED_RECORDS)} financial records")


if __name__ == "__main__":
    asyncio.run(seed())
