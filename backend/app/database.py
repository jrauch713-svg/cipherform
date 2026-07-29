"""Database engine and session management."""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

_engine = None
_async_session = None


def get_engine():
    """Lazily create and return the async engine."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(settings.database_url, echo=settings.app_debug)
    return _engine


def get_async_session():
    """Lazily create and return the async session factory."""
    global _async_session
    if _async_session is None:
        _async_session = async_sessionmaker(
            get_engine(), class_=AsyncSession, expire_on_commit=False
        )
    return _async_session


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


async def get_db() -> AsyncSession:
    """Dependency that provides a database session."""
    session_factory = get_async_session()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
