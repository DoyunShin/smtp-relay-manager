"""Replaceable identity boundary for management authentication."""

from __future__ import annotations

from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import User
from .security import verify_password


class IdentityProvider(Protocol):
    """Resolve management credentials to an internal user identity."""

    async def authenticate(
        self, database: AsyncSession, username: str, password: str
    ) -> User | None:
        """Return an internal user when provider credentials are valid."""
        ...


class LocalIdentityProvider:
    """Authenticate users against local Argon2id password hashes."""

    async def authenticate(
        self, database: AsyncSession, username: str, password: str
    ) -> User | None:
        """Return an active user when the supplied password is valid."""
        user = await database.scalar(select(User).where(User.username == username))
        if (
            user is None
            or not user.active
            or user.password_hash is None
            or not await verify_password(password, user.password_hash)
        ):
            return None
        return user
