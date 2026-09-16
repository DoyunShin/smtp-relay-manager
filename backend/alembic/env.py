"""Run migrations using the same MySQL settings as the applications."""

import asyncio

from sqlalchemy import Connection

from alembic import context
from smtp_relay_manager.config import Settings
from smtp_relay_manager.db import create_database
from smtp_relay_manager.models import Base


def run_migrations(connection: Connection) -> None:
    """Apply migration operations on an existing connection."""
    context.configure(
        connection=connection, target_metadata=Base.metadata, compare_type=True
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_online() -> None:
    """Acquire a deployment-wide migration lock before altering the schema."""
    from sqlalchemy import text

    engine, _ = create_database(Settings())
    try:
        async with engine.connect() as connection:
            locked = await connection.scalar(
                text("SELECT GET_LOCK('srm-schema-migration', 60)")
            )
            if locked != 1:
                raise RuntimeError("Another migration is still running")
            await connection.commit()
            try:
                await connection.run_sync(run_migrations)
                await connection.commit()
            finally:
                await connection.execute(
                    text("SELECT RELEASE_LOCK('srm-schema-migration')")
                )
    finally:
        await engine.dispose()


if context.is_offline_mode():
    context.configure(
        url=Settings().database_url,
        target_metadata=Base.metadata,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(run_online())
