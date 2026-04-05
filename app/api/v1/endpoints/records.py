"""
app/api/v1/endpoints/records.py
─────────────────────────────────
Financial record CRUD endpoints.

Access control matrix:
  ┌──────────────────────────────┬────────┬─────────┬───────┐
  │ Operation                    │ VIEWER │ ANALYST │ ADMIN │
  ├──────────────────────────────┼────────┼─────────┼───────┤
  │ GET  /records                │  ✓     │  ✓      │  ✓    │
  │ GET  /records/{id}           │  ✓     │  ✓      │  ✓    │
  │ POST /records                │  ✗     │  ✗      │  ✓    │
  │ PATCH /records/{id}          │  ✗     │  ✗      │  ✓    │
  │ DELETE /records/{id}         │  ✗     │  ✗      │  ✓    │
  └──────────────────────────────┴────────┴─────────┴───────┘
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import (
    AdminOnly,
    AnyAuthenticatedUser,
    get_pagination,
    get_record_filters,
    verify_csrf_token,
)
from app.db.session import get_db
from app.models import User
from app.schemas import (
    FinancialRecordCreate,
    FinancialRecordFilter,
    FinancialRecordOut,
    FinancialRecordUpdate,
    PaginatedResponse,
    PaginationParams,
)
from app.services.record_service import RecordService

router = APIRouter(prefix="/records", tags=["Financial Records"])


@router.get(
    "",
    response_model=PaginatedResponse[FinancialRecordOut],
    summary="List financial records (all roles)",
)
async def list_records(
    filters:    FinancialRecordFilter = Depends(get_record_filters),
    pagination: PaginationParams      = Depends(get_pagination),
    _user:      User                  = Depends(AnyAuthenticatedUser),
    db:         AsyncSession          = Depends(get_db),
) -> PaginatedResponse[FinancialRecordOut]:
    return await RecordService.list_records(filters, pagination, db)


@router.get(
    "/{record_id}",
    response_model=FinancialRecordOut,
    summary="Get a single record (all roles)",
)
async def get_record(
    record_id: str,
    _user:     User         = Depends(AnyAuthenticatedUser),
    db:        AsyncSession = Depends(get_db),
) -> FinancialRecordOut:
    record = await RecordService.get_by_id(record_id, db)
    return FinancialRecordOut.model_validate(record)


@router.post(
    "",
    response_model=FinancialRecordOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a financial record (admin only)",
    dependencies=[Depends(verify_csrf_token)],
)
async def create_record(
    payload:      FinancialRecordCreate,
    current_user: User         = Depends(AdminOnly),
    db:           AsyncSession = Depends(get_db),
) -> FinancialRecordOut:
    record = await RecordService.create(payload, current_user, db)
    return FinancialRecordOut.model_validate(record)


@router.patch(
    "/{record_id}",
    response_model=FinancialRecordOut,
    summary="Update a financial record (admin only)",
    dependencies=[Depends(verify_csrf_token)],
)
async def update_record(
    record_id:    str,
    payload:      FinancialRecordUpdate,
    _user:        User         = Depends(AdminOnly),
    db:           AsyncSession = Depends(get_db),
) -> FinancialRecordOut:
    record = await RecordService.update(record_id, payload, db)
    return FinancialRecordOut.model_validate(record)


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Soft-delete a financial record (admin only)",
    dependencies=[Depends(verify_csrf_token)],
)
async def delete_record(
    record_id: str,
    _user:     User         = Depends(AdminOnly),
    db:        AsyncSession = Depends(get_db),
) -> None:
    await RecordService.delete(record_id, db)
