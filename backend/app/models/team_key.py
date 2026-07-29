"""Team key sharing database model.

Stores form private keys encrypted for specific team members.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, LargeBinary, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class TeamKey(Base):
    """Encrypted form private key shared with a team member."""

    __tablename__ = "team_keys"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    form_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    encrypted_form_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def __init__(self, **kwargs):
        kwargs.setdefault("created_at", datetime.now(timezone.utc))
        kwargs.setdefault("id", str(uuid.uuid4()))
        super().__init__(**kwargs)

    def __repr__(self) -> str:
        return f"<TeamKey form_id={self.form_id} user_id={self.user_id}>"
