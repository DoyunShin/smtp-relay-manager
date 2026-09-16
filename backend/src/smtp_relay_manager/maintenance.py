"""Periodic cleanup for delivery metadata and abandoned attempts."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .models import Invitation, RateLimit, SendAttempt, WebSession, utc_now

LOGGER = logging.getLogger(__name__)


async def run_maintenance_once(
    session_factory: async_sessionmaker[AsyncSession], retention_days: int
) -> None:
    """Mark abandoned attempts unknown and delete expired delivery logs.

    Args:
        session_factory: Shared database session factory.
        retention_days: Number of days delivery metadata is retained.
    """
    now = utc_now()
    async with session_factory.begin() as database:
        await database.execute(
            update(SendAttempt)
            .where(
                SendAttempt.status == "pending",
                SendAttempt.updated_at < now - timedelta(minutes=10),
            )
            .values(
                status="unknown",
                error_stage="relay",
                error_message="Relay stopped before recording a final result",
                updated_at=now,
            )
        )
        await database.execute(
            delete(SendAttempt).where(
                SendAttempt.created_at < now - timedelta(days=retention_days)
            )
        )
        await database.execute(
            delete(RateLimit).where(RateLimit.expires_at <= now)
        )
        await database.execute(
            delete(WebSession).where(WebSession.expires_at <= now)
        )
        await database.execute(
            delete(Invitation).where(Invitation.expires_at <= now)
        )


async def maintenance_loop(
    session_factory: async_sessionmaker[AsyncSession], retention_days: int
) -> None:
    """Run maintenance at startup and then once per hour."""
    while True:
        try:
            await run_maintenance_once(session_factory, retention_days)
        except Exception:
            LOGGER.exception("Delivery metadata maintenance failed")
        await asyncio.sleep(3600)
