"""Authentication service — password hashing, JWT creation/verification."""

from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    """Authentication utilities for CipherForm."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its bcrypt hash."""
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def create_access_token(data: dict[str, Any]) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
        to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
        return jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)

    @staticmethod
    def decode_access_token(token: str) -> dict[str, Any] | None:
        """Decode and validate a JWT access token.

        Returns the payload dict if valid, None otherwise.
        """
        try:
            payload = jwt.decode(
                token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
            )
            return payload
        except JWTError:
            return None
