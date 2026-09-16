"""Shared authorization boundary for HTTP and SMTP adapters."""

import re
from typing import Literal

from sqlalchemy import exists, or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from smtp_relay_manager.errors import AppError
from smtp_relay_manager.models import (
    CredentialScope,
    Domain,
    DomainAdmin,
    SenderGrant,
    SMTPCredential,
    User,
    utc_now,
)
from smtp_relay_manager.security import verify_secret


def normalize_domain(value: str) -> str:
    """Normalize a DNS domain while rejecting ambiguous input.

    Args:
        value: The submitted DNS name.

    Returns:
        Lowercase IDNA ASCII domain without a trailing dot.
    """
    if (
        not value
        or value != value.strip()
        or any(c in value for c in "\r\n\x00/@:")
    ):
        raise AppError(422, "Invalid domain name")
    try:
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise AppError(422, "Invalid domain name") from exc
    labels = domain.split(".")
    if (
        len(domain) > 253
        or len(labels) < 2
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        )
    ):
        raise AppError(422, "Invalid domain name")
    return domain


def normalize_address(value: str) -> str:
    """Validate an ASCII dot-atom address and normalize only its domain.

    Args:
        value: A mailbox without a display name.

    Returns:
        A canonical domain and case-preserved local part.
    """
    if value.count("@") != 1 or len(value) > 254:
        raise AppError(422, "Invalid sender address")
    local, domain = value.rsplit("@", 1)
    if len(local) > 64 or not re.fullmatch(
        r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*",
        local,
    ):
        raise AppError(422, "Invalid sender address")
    return f"{local}@{normalize_domain(domain)}"


async def get_domain_role(
    db: AsyncSession, user: User, domain: Domain
) -> Literal["owner", "admin"] | None:
    """Resolve a user's management role in a live domain.

    Args:
        db: Current database transaction.
        user: Authenticated local identity.
        domain: Requested domain.

    Returns:
        Owner, admin, or no domain management role.
    """
    if not user.active or domain.deleted_at is not None:
        return None
    if domain.owner_user_id == user.id:
        return "owner"
    membership = await db.get(DomainAdmin, (domain.id, user.id))
    return "admin" if membership else None


async def require_domain_role(
    db: AsyncSession,
    user: User,
    domain: Domain,
    roles: tuple[str, ...],
) -> None:
    """Reject domain operations outside the supplied role set.

    Args:
        db: Current database transaction.
        user: Authenticated identity.
        domain: Requested resource.
        roles: Allowed management roles.

    Raises:
        AppError: If the role does not authorize the operation.
    """
    if await get_domain_role(db, user, domain) not in roles:
        raise AppError(403, "Domain permission denied")


async def validate_scope(
    db: AsyncSession, user_id: str, domain_id: str, address: str
) -> None:
    """Ensure a proposed token scope cannot exceed current sender grants.

    Args:
        db: Current database transaction.
        user_id: Credential owner.
        domain_id: Immutable domain identity.
        address: Exact address or an asterisk for the entire domain.

    Raises:
        AppError: If the scope is invalid or not granted.
    """
    domain = await db.get(Domain, domain_id)
    if not domain or domain.deleted_at or domain.status != "approved":
        raise AppError(403, "Domain is not approved")
    if (
        address != "*"
        and normalize_address(address).rsplit("@", 1)[1] != domain.name
    ):
        raise AppError(422, "Address does not belong to the domain")
    granted = await db.scalar(
        select(SenderGrant.id)
        .where(
            SenderGrant.domain_id == domain_id,
            SenderGrant.user_id == user_id,
            SenderGrant.address.in_(["*", address]),
        )
        .limit(1)
    )
    if not granted:
        raise AppError(403, "Scope exceeds current sender permissions")


async def authenticate_smtp(
    db: AsyncSession, credential_id: str, secret: str
) -> SMTPCredential:
    """Authenticate an SMTP token against the live user and token state.

    Args:
        db: Fresh database transaction.
        credential_id: SMTP username.
        secret: SMTP password.

    Returns:
        The validated credential.
    """
    credential = await db.scalar(
        select(SMTPCredential)
        .join(User)
        .where(
            SMTPCredential.id == credential_id,
            SMTPCredential.revoked_at.is_(None),
            or_(
                SMTPCredential.expires_at.is_(None),
                SMTPCredential.expires_at > utc_now(),
            ),
            User.active.is_(True),
        )
    )
    expected = credential.secret_hash if credential else "0" * 64
    if not verify_secret(secret, expected) or not credential:
        raise AppError(401, "Invalid SMTP credentials")
    return credential


async def authorize_sender(
    db: AsyncSession, credential_id: str, sender: str
) -> Domain:
    """Authorize a sender using a single current database snapshot.

    Args:
        db: A fresh READ COMMITTED transaction, including before DATA.
        credential_id: Previously authenticated SMTP credential.
        sender: Envelope and header sender address.

    Returns:
        The approved domain to route through.
    """
    address = normalize_address(sender)
    domain_name = address.rsplit("@", 1)[1]
    grant = exists(
        select(SenderGrant.id).where(
            SenderGrant.domain_id == Domain.id,
            SenderGrant.user_id == SMTPCredential.user_id,
            SenderGrant.address.in_(["*", address]),
        )
    ).correlate(Domain, SMTPCredential)
    scope = exists(
        select(CredentialScope.id).where(
            CredentialScope.credential_id == SMTPCredential.id,
            CredentialScope.domain_id == Domain.id,
            CredentialScope.address.in_(["*", address]),
        )
    ).correlate(Domain, SMTPCredential)
    statement = (
        select(Domain)
        .join(SMTPCredential, true())
        .join(
            User,
            User.id == SMTPCredential.user_id,
        )
        .where(
            Domain.active_name == domain_name,
            Domain.status == "approved",
            Domain.deleted_at.is_(None),
            SMTPCredential.id == credential_id,
            SMTPCredential.revoked_at.is_(None),
            User.active.is_(True),
            or_(
                SMTPCredential.expires_at.is_(None),
                SMTPCredential.expires_at > utc_now(),
            ),
            grant,
            scope,
        )
    )
    domain = await db.scalar(statement)
    if not domain:
        raise AppError(403, "Sender is not authorized")
    return domain
