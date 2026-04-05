# Finance Dashboard API

A production-grade FastAPI backend for a multi-role financial record management system. Built with enterprise scaling, maintainability, and OWASP Top 10 security hardening as first-class concerns.

---

## Why I built it this way

I picked FastAPI and SQLAlchemy async because I wanted the code to say what it means. When you look at a route handler, the dependency injection in the function signature is a self-documenting contract — `user: User = Depends(AdminOnly)` tells you who can call this endpoint without needing to dig into middleware or read a comment. Pydantic v2 handles the request validation layer in the same declarative style: if a field has `Field(gt=0)`, the API literally cannot accept a negative amount — you don't write that check, the schema is the check. SQLAlchemy async was a deliberate choice over lighter ORMs because I wanted proper connection pooling, type-safe queries, and a clean path to PostgreSQL in production without touching any business logic. The whole stack composes well and stays readable when you come back to it six months later, which I think matters more than cleverness.

I treated the security side as if this were handling real money, because in the scenario it is. That meant going beyond "add JWT auth" and thinking through each OWASP category specifically: bcrypt with a tunable work factor and a hard password-length ceiling to prevent DoS through the hash function, refresh tokens stored as SHA-256 hashes so a database breach doesn't hand an attacker live session tokens, CSRF double-submit cookies because the frontend will almost certainly be a SPA sending cookies alongside Bearer tokens, HTML sanitisation on free-text fields before they hit the database because stored XSS in a finance dashboard is a particularly bad outcome, and brute-force lockout with constant-time error messages so you can't enumerate which emails are registered. None of these are exotic — they're the expected baseline for anything touching financial data — but they all have to be present and correct at the same time to actually matter.

If I had more time, the next things I'd build are multi-tenancy, an audit log, and a proper category management system. Multi-tenancy is the biggest gap: right now all records and users share one database, which is fine for a single company but breaks the moment you want to serve multiple clients. I'd add an `Organisation` model and scope every query through an org ID pulled from the JWT, with a database-level row-security policy as a second line of defence. The audit log would be an append-only table — every create, update, and delete writes a row recording who changed what and what the previous value was, which is non-negotiable for anything in a regulated industry. And categories are currently free-text strings, which works but makes reporting messy; I'd promote them to a proper FK relationship with a seeded list of standard categories, while still letting admins add custom ones. Those three changes would take this from "solid demo" to something you could actually hand to a compliance team.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Security Design](#security-design)
3. [Quick Start](#quick-start)
4. [Project Structure](#project-structure)
5. [API Reference](#api-reference)
6. [Role-Based Access Control](#role-based-access-control)
7. [Running Tests](#running-tests)
8. [Production Deployment](#production-deployment)
9. [Design Decisions & Trade-offs](#design-decisions--trade-offs)
10. [Assumptions](#assumptions)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                     HTTP Request                         │
└──────────────────────┬───────────────────────────────────┘
                       │
        ┌──────────────▼──────────────┐
        │      Middleware Stack        │
        │  ProcessTime → RequestID     │
        │  SecurityHeaders → CSRF      │
        │  CORS → RateLimiter          │
        └──────────────┬──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │        API Router            │
        │   /auth  /users  /records    │
        │         /dashboard           │
        └──────────────┬──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │      FastAPI Dependencies    │
        │  get_current_user            │
        │  RequireRole (RBAC)          │
        │  verify_csrf_token           │
        └──────────────┬──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │         Services             │
        │  AuthService  UserService    │
        │  RecordService DashboardSvc  │
        └──────────────┬──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │   SQLAlchemy Async ORM       │
        │     AsyncSession pool        │
        └──────────────┬──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │         Database             │
        │  SQLite (dev) / PostgreSQL   │
        └─────────────────────────────┘
```

### Layer responsibilities

| Layer | Responsibility |
|---|---|
| **Middleware** | Cross-cutting concerns: security headers, CSRF cookie, rate limiting, request ID |
| **Router / Endpoints** | HTTP binding only — map requests to service calls, return responses |
| **Dependencies** | Reusable FastAPI injections: auth token extraction, RBAC enforcement |
| **Services** | All business logic, validation rules, aggregations |
| **Models** | Database schema, relationships |
| **Schemas** | Request validation (Pydantic) and response serialisation |

---

## Security Design

### OWASP Top 10 coverage

| OWASP Category | Controls Implemented |
|---|---|
| **A01 Broken Access Control** | Role-based guards on every endpoint; CSRF double-submit cookie; refresh token scoped to `/api/v1/auth` path |
| **A02 Cryptographic Failures** | bcrypt (work factor 12) for passwords; HS256 JWT with configurable secret; refresh tokens stored as SHA-256 hashes |
| **A03 Injection** | SQLAlchemy ORM with parameterised queries throughout; free-text fields sanitised with HTML stripping before persistence |
| **A04 Insecure Design** | Separation of concerns enforced by layer architecture; role model documented and enforced at the dependency layer |
| **A05 Security Misconfiguration** | Security headers middleware (CSP, HSTS, X-Frame-Options, etc.); Swagger UI disabled in production; generic 500 responses (no stack traces) |
| **A07 Identification & Auth Failures** | Short-lived access tokens (30 min); refresh token rotation on every use; account lockout after 5 failed logins; no user enumeration in error messages |
| **A08 Software & Data Integrity** | Input validation via Pydantic before any DB write; Alembic for migration integrity |
| **A09 Security Logging** | Structured logging (structlog) on all auth events, integrity errors, and unhandled exceptions; `X-Request-ID` for tracing |

### Token architecture

```
Login
  │
  ├─► Access Token (JWT, 30 min, returned in JSON body)
  │     Stored in SPA memory only — never localStorage
  │
  └─► Refresh Token (JWT, 7 days, returned as HttpOnly cookie)
        path=/api/v1/auth  ← only sent to auth endpoints
        SameSite=Strict     ← not sent on cross-origin requests
        Secure=True         ← HTTPS only (staging/prod)
        Stored as SHA-256 hash in DB (never raw)

Refresh
  └─► Old token revoked + new token issued (rotation)
        Replay of a rotated token → 401

Logout
  └─► Token revoked in DB, cookie cleared
```

### CSRF protection

Uses the **double-submit cookie pattern**:
1. Server sets a `csrf_token` cookie (HttpOnly=**false** — JS must read it).
2. SPA reads the cookie and echoes it in the `X-CSRF-Token` request header.
3. `verify_csrf_token` dependency compares them with `hmac.compare_digest`.
4. Applied to all `POST`, `PATCH`, `DELETE` endpoints.

---

## Quick Start

### Prerequisites

- Python 3.11+
- `pip`

### Setup

```bash
# 1. Clone and enter the project
git clone <repo-url>
cd finance-dashboard

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — at minimum, set a strong JWT_SECRET_KEY

# 5. Create data directory
mkdir -p data

# 6. Seed the database
python scripts/seed.py

# 7. Run the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Test credentials (after seeding)

| Role | Email | Password |
|---|---|---|
| ADMIN | admin@finance.local | Admin1234secure! |
| ANALYST | analyst@finance.local | Analyst1234secure! |
| VIEWER | viewer@finance.local | Viewer1234secure! |

### Interactive API docs

Open `http://localhost:8000/docs` (Swagger UI, available in dev/staging only).

---

## Project Structure

```
finance-dashboard/
├── app/
│   ├── main.py                    # App factory, middleware, exception handlers
│   ├── api/
│   │   ├── dependencies.py        # Reusable FastAPI dependencies (auth, RBAC, CSRF)
│   │   └── v1/
│   │       ├── router.py          # Aggregates all v1 routers
│   │       └── endpoints/
│   │           ├── auth.py        # Login, refresh, logout
│   │           ├── users.py       # User CRUD
│   │           ├── records.py     # Financial record CRUD
│   │           └── dashboard.py   # Aggregation summary
│   ├── core/
│   │   ├── config.py              # All settings (Pydantic-Settings, .env)
│   │   └── security.py            # Passwords, JWT, CSRF, sanitisation
│   ├── db/
│   │   ├── base.py                # DeclarativeBase + TimestampMixin + SoftDeleteMixin
│   │   └── session.py             # Async engine, session factory, get_db dependency
│   ├── middleware/
│   │   └── security.py            # SecurityHeaders, CSRF cookie, RequestID, ProcessTime
│   ├── models/
│   │   └── __init__.py            # User, FinancialRecord, RefreshToken ORM models
│   ├── schemas/
│   │   └── __init__.py            # Pydantic schemas (Create/Update/Out/Filter)
│   └── services/
│       ├── auth_service.py        # Login logic, token management, lockout
│       ├── user_service.py        # User CRUD
│       ├── record_service.py      # Record CRUD + filtering
│       └── dashboard_service.py   # DB-side aggregations
├── alembic/
│   └── env.py                     # Async-aware migration environment
├── tests/
│   └── integration/
│       └── test_auth_and_rbac.py  # Full-stack integration tests
├── scripts/
│   └── seed.py                    # Dev data bootstrap
├── alembic.ini
├── pytest.ini
├── requirements.txt
└── .env.example
```

---

## API Reference

### Authentication

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| POST | `/api/v1/auth/login` | Exchange credentials for tokens | — |
| POST | `/api/v1/auth/refresh` | Rotate refresh token | Cookie + CSRF |
| POST | `/api/v1/auth/logout` | Revoke refresh token | Cookie + CSRF |

### Users

| Method | Endpoint | Description | Min Role |
|---|---|---|---|
| GET | `/api/v1/users/me` | Current user profile | VIEWER |
| GET | `/api/v1/users` | List all users | ADMIN |
| POST | `/api/v1/users` | Create user | ADMIN |
| GET | `/api/v1/users/{id}` | Get user by ID | ADMIN |
| PATCH | `/api/v1/users/{id}` | Update user | ADMIN |
| DELETE | `/api/v1/users/{id}` | Soft-delete user | ADMIN |

### Financial Records

| Method | Endpoint | Description | Min Role |
|---|---|---|---|
| GET | `/api/v1/records` | List records (filterable, paginated) | VIEWER |
| GET | `/api/v1/records/{id}` | Get single record | VIEWER |
| POST | `/api/v1/records` | Create record | ADMIN |
| PATCH | `/api/v1/records/{id}` | Update record | ADMIN |
| DELETE | `/api/v1/records/{id}` | Soft-delete record | ADMIN |

**Record list query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `type` | `INCOME` \| `EXPENSE` | Filter by type |
| `category` | string | Filter by category (case-insensitive) |
| `date_from` | YYYY-MM-DD | Start of date range |
| `date_to` | YYYY-MM-DD | End of date range |
| `search` | string | Substring search in notes |
| `page` | int | Page number (default: 1) |
| `page_size` | int | Records per page (default: 20, max: 100) |

### Dashboard

| Method | Endpoint | Description | Min Role |
|---|---|---|---|
| GET | `/api/v1/dashboard/summary` | Aggregated financial summary | VIEWER |

---

## Role-Based Access Control

```
VIEWER   → GET /records, GET /records/{id}, GET /dashboard/summary, GET /users/me
ANALYST  → Everything VIEWER can do
ADMIN    → Everything + POST/PATCH/DELETE /records + all /users endpoints
```

RBAC is enforced via the `RequireRole` dependency injected directly into route signatures. There is no way to bypass it — every protected route explicitly declares which roles are permitted.

---

## Running Tests

```bash
# Install test dependencies (included in requirements.txt)
pytest tests/ -v

# With coverage
pytest tests/ -v --tb=short
```

Tests use an **in-memory SQLite database** — no external services required.

---

## Production Deployment

1. **Set `APP_ENVIRONMENT=production`** in your environment — this disables Swagger UI and enables HSTS.
2. **Override `JWT_SECRET_KEY`** with a cryptographically random 64-byte hex string.
3. **Switch `DATABASE_URL`** to a PostgreSQL connection string.
4. **Use Alembic** for schema migrations: `alembic upgrade head`
5. **Run behind a reverse proxy** (nginx/Caddy) that terminates TLS — the app trusts `X-Forwarded-For` for rate limiting.
6. **Scale horizontally** — the app is stateless (tokens validated from JWT signature, not in-memory session). Any number of instances can run behind a load balancer sharing the same database.

---

## Design Decisions & Trade-offs

**SQLite in development, PostgreSQL in production.** SQLite eliminates external dependencies for local setup. The `DATABASE_URL` swap is the only change needed. The `func.substr` used in monthly trend aggregation is portable between both.

**Soft deletes via `deleted_at`.** Deleted records and users are retained for audit trails and regulatory compliance. The `is_(None)` filter is indexed to keep query performance consistent.

**Refresh tokens stored as SHA-256 hashes.** A raw token in the database is an authentication credential — if the database were breached, all sessions would be compromisable. Hashing neutralises that risk.

**No separate Category table.** Categories are stored as a normalised string. This keeps the schema simple for the assessment scope. A `Category` FK table is a natural v2 enhancement that would add category management without breaking existing queries.

**Synchronous bcrypt in async handler.** Bcrypt is CPU-bound. Wrapping it in `asyncio.run_in_executor` would be the production-correct approach; it is omitted here for readability. The `PASSWORD_MAX_LENGTH` guard prevents the bcrypt DoS vector regardless.

**ANALYST role has read-only access identical to VIEWER** in this implementation. The schema supports differentiating them (e.g., granting ANALYST access to CSV export endpoints) without any structural changes.

---

## Assumptions

- The API serves a Single Page Application. Refresh tokens are delivered via HttpOnly cookies; access tokens are stored in SPA memory (not `localStorage`).
- All financial amounts are stored as positive floats; the `type` field (INCOME/EXPENSE) carries the sign semantics.
- "Delete" means soft-delete (`ENABLE_SOFT_DELETE=true` by default). Hard-delete is not exposed via the API.
- Dates are stored as ISO 8601 strings (`YYYY-MM-DD`) for portability between SQLite and PostgreSQL.
- The system manages a single shared pool of financial records visible to all authenticated users. Per-user record scoping (multi-tenancy) would be a straightforward extension: add a `WHERE created_by_user_id = :current_user_id` filter to the record service.
