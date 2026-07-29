"""User database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Text, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class User(Base):
    """CipherForm user account."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    tier: Mapped[str] = mapped_column(String(20), default="starter", nullable=False)
    stripe_customer_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def __init__(self, **kwargs):
        kwargs.setdefault("tier", "starter")
        kwargs.setdefault("created_at", datetime.now(timezone.utc))
        kwargs.setdefault("id", str(uuid.uuid4()))
        super().__init__(**kwargs)

    def __repr__(self) -> str:
        return f"<User {self.email}>"
