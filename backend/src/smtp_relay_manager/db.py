"""MySQL engine and transaction factory."""

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from smtp_relay_manager.config import Settings


def create_database(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    """Create the shared MySQL connection pool.

    Args:
        settings: Application configuration containing the connection URL.

    Returns:
        The engine and a factory for short READ COMMITTED transactions.
    """
    if not settings.database_url.startswith("mysql+asyncmy://"):
        raise ValueError("DATABASE_URL must use mysql+asyncmy")
    engine = create_async_engine(
        settings.database_url, pool_pre_ping=True, pool_recycle=1800,
        isolation_level="READ COMMITTED", pool_size=10, max_overflow=10,
        hide_parameters=True,
    )
    return engine, async_sessionmaker(engine, expire_on_commit=False)
