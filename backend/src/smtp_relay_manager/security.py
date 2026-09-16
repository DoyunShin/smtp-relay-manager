"""Credential primitives and atomic, shared authentication throttling."""

import asyncio
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.dialects.mysql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from smtp_relay_manager.models import RateLimit, utc_now


def generate_secret() -> str:
    """Generate a random credential.

    Returns:
        A URL-safe token containing 256 bits of randomness.
    """
    return secrets.token_urlsafe(32)


def hash_secret(secret: str) -> str:
    """Hash a high-entropy token for lookup or verification.

    Args:
        secret: A server-generated random credential.

    Returns:
        The hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_secret(secret: str, expected_hash: str) -> bool:
    """Compare a supplied random token against its stored hash.

    Args:
        secret: Supplied credential.
        expected_hash: Previously stored digest.

    Returns:
        Whether the digests match in constant time.
    """
    return hmac.compare_digest(hash_secret(secret), expected_hash)


async def hash_password(password: str) -> str:
    """Hash a password outside the event loop.

    Args:
        password: User-selected password.

    Returns:
        An Argon2id encoded password hash.
    """
    return await asyncio.to_thread(PasswordHasher().hash, password)


async def verify_password(password: str, encoded: str) -> bool:
    """Verify a password without blocking asynchronous connections.

    Args:
        password: Supplied password.
        encoded: Stored Argon2 hash.

    Returns:
        Whether the password is valid.
    """
    try:
        return await asyncio.to_thread(
            PasswordHasher().verify, encoded, password
        )
    except (VerificationError, InvalidHashError):
        return False


def encrypt_password(password: str, key: str) -> str:
    """Encrypt an upstream password with the deployment master key.

    Args:
        password: Plaintext upstream credential.
        key: Base64-encoded Fernet key.

    Returns:
        Authenticated ciphertext safe for database storage.
    """
    return (
        Fernet(key.encode("ascii"))
        .encrypt(password.encode("utf-8"))
        .decode("ascii")
    )


def decrypt_password(encrypted: str, key: str) -> str:
    """Decrypt an upstream password immediately before authentication.

    Args:
        encrypted: Stored Fernet ciphertext.
        key: Deployment encryption key.

    Returns:
        The plaintext credential.
    """
    return (
        Fernet(key.encode("ascii"))
        .decrypt(encrypted.encode("ascii"))
        .decode("utf-8")
    )


async def consume_rate_limit(
    factory: async_sessionmaker[AsyncSession],
    keys: list[str],
    limits: list[int],
    window_seconds: int = 900,
    *,
    started_at: datetime | None = None,
) -> bool:
    """Atomically consume authentication attempts across service instances.

    Args:
        factory: Factory for independent database transactions.
        keys: Buckets ordered from the IP to the IP and identity pair.
        limits: Maximum attempts corresponding to each key.
        window_seconds: Fixed-window duration.
        started_at: Reservation timestamp shared with successful releases.

    Returns:
        Whether all buckets permit this attempt. Outer limits prevent creation
        of attacker-controlled inner buckets once the IP is blocked.
    """
    if len(keys) != len(limits):
        raise ValueError("Each rate bucket needs a limit")
    # MySQL DATETIME stores whole seconds; truncate before it can round upward.
    now = (started_at or utc_now()).replace(microsecond=0)
    allowed = True
    async with factory.begin() as db:
        for key, limit in zip(keys, limits, strict=True):
            digest = hash_secret(key)
            statement = (
                insert(RateLimit)
                .values(
                    key=digest,
                    attempts=0,
                    expires_at=now + timedelta(seconds=window_seconds),
                )
                .on_duplicate_key_update(key=digest)
            )
            await db.execute(statement)
            bucket = (
                await db.execute(
                    select(RateLimit)
                    .where(RateLimit.key == digest)
                    .with_for_update()
                )
            ).scalar_one()
            if bucket.expires_at <= now:
                bucket.attempts = 0
                bucket.expires_at = now + timedelta(seconds=window_seconds)
            if bucket.attempts >= limit:
                allowed = False
                break
            bucket.attempts += 1
    return allowed


async def release_rate_limit(
    factory: async_sessionmaker[AsyncSession],
    keys: list[str],
    started_at: datetime,
    window_seconds: int = 900,
) -> None:
    """Release successful auth reservations without clearing failures.

    Args:
        factory: Factory for independent database transactions.
        keys: Buckets reserved immediately before authentication.
        started_at: UTC time recorded before reserving the attempt.
        window_seconds: The duration used when reserving the buckets.
    """
    async with factory.begin() as db:
        for key in keys:
            bucket = await db.scalar(
                select(RateLimit)
                .where(
                    RateLimit.key == hash_secret(key),
                )
                .with_for_update()
            )
            if bucket and bucket.expires_at <= started_at + timedelta(
                seconds=window_seconds
            ):
                bucket.attempts = max(0, bucket.attempts - 1)
