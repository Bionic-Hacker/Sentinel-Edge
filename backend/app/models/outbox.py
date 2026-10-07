"""Local email outbox (LOCAL provenance).

Messages that would be emailed are stored here instead of being sent. They are readable only by
the operator through the CLI (`make outbox`), never through the API, because they contain
password-reset links. Real delivery (Amazon SES) would be a later, separately approved
integration.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models._types import created_at, uuid_pk


class OutboxMessage(Base):
    __tablename__ = "outbox_messages"

    id: Mapped[uuid.UUID] = uuid_pk()
    recipient: Mapped[str] = mapped_column(String(254), nullable=False)
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = created_at()
