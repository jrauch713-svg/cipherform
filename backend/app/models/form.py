"""Form database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Text, Boolean, Integer, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Form(Base):
    """Encrypted form definition. Stores metadata ONLY — no plaintext data."""

    __tablename__ = "forms"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    fields: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    settings: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    response_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __init__(self, **kwargs):
        kwargs.setdefault("fields", [])
        kwargs.setdefault("settings", {})
        kwargs.setdefault("response_count", 0)
        kwargs.setdefault("is_active", True)
        kwargs.setdefault("created_at", datetime.now(timezone.utc))
        kwargs.setdefault("updated_at", datetime.now(timezone.utc))
        kwargs.setdefault("id", str(uuid.uuid4()))
        super().__init__(**kwargs)

    def __repr__(self) -> str:
        return f"<Form {self.title}>"
