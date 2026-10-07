"""Engine and session management.

The engine is created per application instance (``create_app``) rather than at import time, so
tests and tools can point the app at different databases, and importing the app never opens a
connection. Only the APP role is ever used here; the migrator role is used by Alembic alone.
"""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import DbRole, Settings


def build_engine(settings: Settings, role: DbRole = DbRole.APP) -> Engine:
    return create_engine(
        settings.database_url(role),
        pool_pre_ping=True,  # drop dead connections (RDS failover, restarts) transparently
        pool_size=5,
        max_overflow=5,
        pool_timeout=5,  # fail fast under exhaustion instead of queueing requests indefinitely
        pool_recycle=1800,
    )


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    # expire_on_commit=False: response models can read attributes after commit without a
    # surprise lazy-load round trip.
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db(request: Request) -> Iterator[Session]:
    """FastAPI dependency: one session per request.

    Services commit explicitly at the point a unit of work is complete (so security-relevant
    writes, such as an audit record and the change it describes, commit together or not at all).
    Anything left uncommitted is rolled back when the request ends.
    """
    factory: sessionmaker[Session] = request.app.state.session_factory
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
