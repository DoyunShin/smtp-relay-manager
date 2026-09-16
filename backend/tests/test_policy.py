"""Exercise shared authorization against an actual MySQL database."""

import asyncio
import os
from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from smtp_relay_manager.config import Settings
from smtp_relay_manager.db import create_database
from smtp_relay_manager.errors import AppError
from smtp_relay_manager.models import (
    Base,
    CredentialScope,
    Domain,
    RateLimit,
    SenderGrant,
    SMTPCredential,
    User,
    new_id,
    utc_now,
)
from smtp_relay_manager.policy import (
    authenticate_smtp,
    authorize_sender,
    normalize_address,
    validate_scope,
)
from smtp_relay_manager.security import (
    consume_rate_limit,
    hash_secret,
    release_rate_limit,
)

DatabaseFactory = async_sessionmaker[AsyncSession]


@pytest.fixture
async def database() -> AsyncIterator[DatabaseFactory]:
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip(
            "TEST_DATABASE_URL must point to a disposable MySQL database"
        )
    engine, factory = create_database(Settings(database_url=url))
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    yield factory
    await engine.dispose()


async def seed_sender(factory: DatabaseFactory) -> tuple[str, str, str]:
    user_id, domain_id, token_id = new_id(), new_id(), new_id()
    async with factory.begin() as db:
        db.add(User(id=user_id, username="sender", active=True))
        await db.flush()
        db.add(
            Domain(
                id=domain_id,
                name="example.com",
                active_name="example.com",
                owner_user_id=user_id,
                status="approved",
            )
        )
        db.add(
            SMTPCredential(
                id=token_id,
                user_id=user_id,
                name="app",
                secret_hash=hash_secret("token"),
            )
        )
        await db.flush()
        db.add(SenderGrant(domain_id=domain_id, user_id=user_id, address="*"))
        db.add(
            CredentialScope(
                credential_id=token_id,
                domain_id=domain_id,
                address="notice@example.com",
            )
        )
    return user_id, domain_id, token_id


async def test_current_grant_intersects_token_scope(
    database: DatabaseFactory,
) -> None:
    user_id, domain_id, token_id = await seed_sender(database)
    async with database() as db:
        assert (
            await authorize_sender(db, token_id, "notice@EXAMPLE.com")
        ).id == domain_id
        with pytest.raises(AppError):
            await authorize_sender(db, token_id, "other@example.com")
    async with database.begin() as db:
        await db.execute(
            delete(SenderGrant).where(SenderGrant.user_id == user_id)
        )
    async with database() as db:
        with pytest.raises(AppError):
            await authorize_sender(db, token_id, "notice@example.com")


async def test_revoked_token_rejected_after_authentication(
    database: DatabaseFactory,
) -> None:
    _, _, token_id = await seed_sender(database)
    async with database() as db:
        assert (await authenticate_smtp(db, token_id, "token")).id == token_id
    async with database.begin() as db:
        token = await db.get(SMTPCredential, token_id)
        assert token is not None
        token.revoked_at = utc_now()
    async with database() as db:
        with pytest.raises(AppError):
            await authorize_sender(db, token_id, "notice@example.com")


async def test_deleted_domain_cannot_resurrect_grants(
    database: DatabaseFactory,
) -> None:
    user_id, domain_id, token_id = await seed_sender(database)
    async with database.begin() as db:
        domain = await db.get(Domain, domain_id)
        assert domain is not None
        domain.active_name = None
        domain.deleted_at = utc_now()
        await db.flush()
        db.add(
            Domain(
                name="example.com",
                active_name="example.com",
                owner_user_id=user_id,
                status="approved",
            )
        )
    async with database() as db:
        with pytest.raises(AppError):
            await authorize_sender(db, token_id, "notice@example.com")


async def test_exact_grants_cannot_issue_domain_scope(
    database: DatabaseFactory,
) -> None:
    user_id, domain_id, _ = await seed_sender(database)
    async with database.begin() as db:
        await db.execute(
            delete(SenderGrant).where(SenderGrant.user_id == user_id)
        )
        db.add(
            SenderGrant(
                domain_id=domain_id,
                user_id=user_id,
                address="notice@example.com",
            )
        )
    async with database() as db:
        await validate_scope(db, user_id, domain_id, "notice@example.com")
        with pytest.raises(AppError):
            await validate_scope(db, user_id, domain_id, "*")


async def test_disabled_user_and_expired_token_deny(
    database: DatabaseFactory,
) -> None:
    user_id, _, token_id = await seed_sender(database)
    async with database.begin() as db:
        token = await db.get(SMTPCredential, token_id)
        assert token is not None
        token.expires_at = utc_now() - timedelta(seconds=1)
    async with database() as db:
        with pytest.raises(AppError):
            await authenticate_smtp(db, token_id, "token")
    async with database.begin() as db:
        token = await db.get(SMTPCredential, token_id)
        assert token is not None
        token.expires_at = None
        user = await db.get(User, user_id)
        assert user is not None
        user.active = False
    async with database() as db:
        with pytest.raises(AppError):
            await authorize_sender(db, token_id, "notice@example.com")


async def test_concurrent_rate_limit_is_atomic(
    database: DatabaseFactory,
) -> None:
    results = await asyncio.gather(
        *(
            consume_rate_limit(
                database, ["smtp:127.0.0.1", "smtp:127.0.0.1:sender"], [20, 5]
            )
            for _ in range(12)
        )
    )
    assert sum(results) == 5


async def test_successful_auth_does_not_accumulate_failures(
    database: DatabaseFactory,
) -> None:
    keys = ["auth:ip", "auth:ip:user"]
    for _ in range(8):
        started = utc_now()
        assert await consume_rate_limit(
            database, keys, [20, 5], started_at=started
        )
        await release_rate_limit(database, keys, started)
    for _ in range(5):
        assert await consume_rate_limit(database, keys, [20, 5])
    assert not await consume_rate_limit(database, keys, [20, 5])


async def test_blocked_ip_cannot_create_unbounded_identity_buckets(
    database: DatabaseFactory,
) -> None:
    for number in range(30):
        await consume_rate_limit(database, ["ip", f"ip:{number}"], [5, 5])
    async with database() as db:
        assert (
            await db.scalar(select(func.count()).select_from(RateLimit)) == 6
        )


def test_sender_normalization_preserves_local_part() -> None:
    assert normalize_address("Alerts@EXAMPLE.com") == "Alerts@example.com"
    for value in [
        "a\r\nBcc:x@example.com",
        "a..b@example.com",
        "@example.com",
        "a@localhost",
        "a@example.com\n",
    ]:
        with pytest.raises(AppError):
            normalize_address(value)
