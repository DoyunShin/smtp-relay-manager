"""Database-backed authentication, authorization, and synchronous delivery."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from smtp_relay_manager import models
from smtp_relay_manager.errors import AppError
from smtp_relay_manager.policy import authenticate_smtp, authorize_sender
from smtp_relay_manager.security import (
    consume_rate_limit,
    decrypt_password,
    release_rate_limit,
)
from smtp_relay_manager.upstream import (
    DeliveryResult,
    UpstreamAuth,
    UpstreamEndpoint,
    UpstreamError,
    UpstreamSecurity,
    UpstreamSMTP,
)

LOGGER = logging.getLogger(__name__)
AttemptStatus = Literal["pending", "accepted", "failed", "unknown"]


@dataclass(frozen=True, slots=True)
class AuthenticatedCredential:
    """Identity attached to one authenticated SMTP connection."""

    id: str
    user_id: str


@dataclass(frozen=True, slots=True)
class AttemptIdentity:
    """IDs needed to finalize an already durable send attempt."""

    attempt_id: str
    domain_id: str


class RelayService:
    """Coordinate policy and delivery while keeping DB transactions short."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        encryption_key: str,
        *,
        connect_timeout: float = 15.0,
        command_timeout: float = 30.0,
        upstream_factory: Callable[..., UpstreamSMTP] = UpstreamSMTP,
    ) -> None:
        self.session_factory = session_factory
        self.encryption_key = encryption_key
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        self.upstream_factory = upstream_factory

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        async with self.session_factory() as session:
            yield session

    async def authenticate(
        self, credential_id: str, secret: str, peer: str = "unknown"
    ) -> AuthenticatedCredential:
        """Authenticate an SMTP token in a fresh transaction."""

        keys = [
            f"smtp-auth-ip:{peer}",
            f"smtp-auth-ip-credential:{peer}:{credential_id}",
        ]
        started_at = models.utc_now()
        permitted = await consume_rate_limit(
            self.session_factory,
            keys,
            [20, 5],
            started_at=started_at,
        )
        if not permitted:
            raise AppError(429, "Too many authentication attempts")
        async with self._session() as session:
            credential = await authenticate_smtp(
                session, credential_id, secret
            )
            authenticated = AuthenticatedCredential(
                credential.id, credential.user_id
            )
        await release_rate_limit(self.session_factory, keys, started_at)
        return authenticated

    async def authorize(self, credential_id: str, sender: str) -> str:
        """Authorize a sender and return its current domain ID."""

        async with self._session() as session:
            domain = await authorize_sender(session, credential_id, sender)
            return domain.id

    async def _prepare_attempt(
        self,
        credential: AuthenticatedCredential,
        sender: str,
        recipients: Sequence[str],
    ) -> tuple[AttemptIdentity, UpstreamEndpoint]:
        async with self._session() as session:
            domain = await authorize_sender(session, credential.id, sender)
            config = await session.scalar(
                select(models.SMTPConfig).where(
                    models.SMTPConfig.domain_id == domain.id
                )
            )
            if config is None:
                raise AppError(409, "upstream SMTP is not configured")
            password = (
                decrypt_password(
                    config.password_encrypted, self.encryption_key
                )
                if config.password_encrypted is not None
                else None
            )
            endpoint = UpstreamEndpoint(
                host=config.host,
                port=config.port,
                security=UpstreamSecurity(config.security),
                auth=UpstreamAuth(config.auth),
                username=config.username,
                password=password,
            )
            attempt = models.SendAttempt(
                id=models.new_id(),
                user_id=credential.user_id,
                credential_id=credential.id,
                domain_id=domain.id,
                sender=sender,
                status="pending",
            )
            session.add(attempt)
            session.add_all(
                models.SendRecipient(
                    id=models.new_id(),
                    attempt_id=attempt.id,
                    address=recipient,
                )
                for recipient in recipients
            )
            await session.commit()
            return AttemptIdentity(attempt.id, domain.id), endpoint

    async def _finalize(
        self,
        attempt_id: str,
        status: AttemptStatus,
        *,
        code: str | None = None,
        stage: str | None = None,
        message: str | None = None,
    ) -> None:
        async with self._session() as session:
            attempt = await session.get(
                models.SendAttempt, attempt_id, with_for_update=True
            )
            if attempt is None:
                raise RuntimeError("send attempt disappeared")
            attempt.status = status
            attempt.error_code = code[:32] if code is not None else None
            attempt.error_stage = stage[:32] if stage is not None else None
            attempt.error_message = (
                message[:255] if message is not None else None
            )
            attempt.updated_at = models.utc_now()
            await session.commit()

    async def relay(
        self,
        credential: AuthenticatedCredential,
        sender: str,
        recipients: Sequence[str],
        message: bytes,
    ) -> tuple[AttemptIdentity, DeliveryResult]:
        """Persist metadata, relay once, and record a definitive success."""

        attempt, endpoint = await self._prepare_attempt(
            credential, sender, recipients
        )
        upstream: UpstreamSMTP | None = None

        async def reauthorize() -> None:
            # Use a READ COMMITTED view immediately before DATA.
            await self.authorize(credential.id, sender)

        try:
            upstream = self.upstream_factory(
                endpoint,
                connect_timeout=self.connect_timeout,
                command_timeout=self.command_timeout,
            )
            await upstream.connect()
            result = await upstream.deliver(
                sender, recipients, message, pre_data_hook=reauthorize
            )
        except asyncio.CancelledError as exc:
            failure = UpstreamError(
                "upstream transaction timed out before DATA"
            )
            setattr(failure, "attempt_id", attempt.attempt_id)
            raise failure from exc
        except BaseException as exc:
            setattr(exc, "attempt_id", attempt.attempt_id)
            raise
        finally:
            if upstream is not None:
                await upstream.close()
        return attempt, result

    async def mark_accepted(self, attempt_id: str) -> None:
        """Best-effort success logging after the upstream accepted DATA."""

        try:
            await self._finalize(attempt_id, "accepted")
        except BaseException as error:
            LOGGER.warning(
                "Upstream accepted but attempt finalization failed (%s)",
                type(error).__name__,
            )

    async def mark_failed(
        self, attempt_id: str, code: str, stage: str, message: str
    ) -> None:
        await self._finalize(
            attempt_id, "failed", code=code, stage=stage, message=message
        )

    async def mark_unknown(
        self, attempt_id: str, code: str, stage: str, message: str
    ) -> None:
        await self._finalize(
            attempt_id, "unknown", code=code, stage=stage, message=message
        )


__all__ = ["AuthenticatedCredential", "AttemptIdentity", "RelayService"]
