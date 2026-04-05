"""
app/core/logging.py
────────────────────
Structured logging using structlog, compatible with both dev and production.
"""
from __future__ import annotations
import logging
import sys
import structlog
from app.core.config import settings, Environment


def configure_logging() -> None:
    """Configure structlog. Call once at application startup."""
    shared_processors = [
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]

    if settings.LOG_FORMAT == "json" or settings.APP_ENVIRONMENT == Environment.PRODUCTION:
        processors = shared_processors + [structlog.processors.JSONRenderer()]
    else:
        processors = shared_processors + [structlog.dev.ConsoleRenderer(colors=False)]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(settings.LOG_LEVEL)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    handler = logging.StreamHandler(sys.stdout)
    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(settings.LOG_LEVEL)

    if settings.APP_ENVIRONMENT != Environment.DEVELOPMENT:
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str):
    """Return a structlog bound logger."""
    return structlog.get_logger(name)
