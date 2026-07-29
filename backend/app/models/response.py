"""Encrypted response database model.

Stores ONLY ciphertext blobs — the server can never read plaintext responses.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, LargeBinary, Text, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Response(Base):
    """Encrypted form response. Ciphertext only — zero server-side plaintext."""

    __tablename__ = "responses"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    form_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ephemeral_public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    respondent_ip_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def __init__(self, **kwargs):
        kwargs.setdefault("created_at", datetime.now(timezone.utc))
        kwargs.setdefault("id", str(uuid.uuid4()))
        super().__init__(**kwargs)

    def __repr__(self) -> str:
        return f"<Response form_id={self.form_id}>"
