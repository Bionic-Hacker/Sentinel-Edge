"""Column helpers shared by models."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import TypeVar

from sqlalchemy import DateTime, Dialect, String, TypeDecorator, Uuid
from sqlalchemy.orm import MappedColumn, mapped_column

from app.core.clock import utcnow


def uuid_pk() -> MappedColumn[uuid.UUID]:
    return mapped_column(Uuid, primary_key=True, default=uuid.uuid4)


def created_at() -> MappedColumn[datetime]:
    return mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


def timestamp(*, nullable: bool = True) -> MappedColumn[datetime]:
    return mapped_column(DateTime(timezone=True), nullable=nullable)


E = TypeVar("E", bound=StrEnum)


class StrEnumType(TypeDecorator[E]):
    """A VARCHAR column that stores a StrEnum's value and loads it back *as the enum*.

    Without this, a plain String column returns `str`, and an identity check such as
    `user.role is Role.ADMIN` is silently always False. That exact bug was caught by
    test_admin_can_read_any_record; this type removes the trap at its source. Binding also
    validates: an unknown value raises before reaching the database's CHECK constraint.
    """

    impl = String
    cache_ok = True

    def __init__(self, enum_cls: type[E], length: int) -> None:
        super().__init__(length)
        self.enum_cls = enum_cls

    def process_bind_param(self, value: E | str | None, dialect: Dialect) -> str | None:
        return None if value is None else self.enum_cls(value).value

    def process_result_value(self, value: str | None, dialect: Dialect) -> E | None:
        return None if value is None else self.enum_cls(value)
