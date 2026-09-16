"""Persistent identities, domain policies, credentials, and delivery metadata."""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now() -> datetime:
    """Read the current UTC timestamp.

    Returns:
        A timezone-naive UTC datetime suitable for MySQL DATETIME storage.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_id() -> str:
    """Generate an immutable resource identifier.

    Returns:
        A UUID version 4 in its standard string representation.
    """
    return str(uuid4())


class Base(DeclarativeBase):
    """Provide metadata shared by migrations and both services."""


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64, collation="utf8mb4_bin"), unique=True)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    is_operator: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)


class Invitation(Base):
    __tablename__ = "invitations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)


class WebSession(Base):
    __tablename__ = "web_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)


class Domain(Base):
    __tablename__ = "domains"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(253, collation="utf8mb4_bin"))
    active_name: Mapped[str | None] = mapped_column(String(253, collation="utf8mb4_bin"), unique=True)
    owner_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    __table_args__ = (CheckConstraint("status IN ('pending', 'approved', 'rejected')"),)


class DomainAdmin(Base):
    __tablename__ = "domain_admins"
    domain_id: Mapped[str] = mapped_column(ForeignKey("domains.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)


class SenderAddress(Base):
    __tablename__ = "sender_addresses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    domain_id: Mapped[str] = mapped_column(ForeignKey("domains.id"))
    address: Mapped[str] = mapped_column(String(254, collation="utf8mb4_bin"))
    __table_args__ = (UniqueConstraint("domain_id", "address"),)


class SenderGrant(Base):
    __tablename__ = "sender_grants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    domain_id: Mapped[str] = mapped_column(ForeignKey("domains.id"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    address: Mapped[str] = mapped_column(String(254, collation="utf8mb4_bin"))
    __table_args__ = (UniqueConstraint("domain_id", "user_id", "address"),)


class SMTPConfig(Base):
    __tablename__ = "smtp_configs"
    domain_id: Mapped[str] = mapped_column(ForeignKey("domains.id"), primary_key=True)
    host: Mapped[str] = mapped_column(String(253))
    port: Mapped[int] = mapped_column(Integer)
    security: Mapped[str] = mapped_column(String(16))
    auth: Mapped[str] = mapped_column(String(16))
    username: Mapped[str | None] = mapped_column(String(255))
    password_encrypted: Mapped[str | None] = mapped_column(Text)
    __table_args__ = (
        CheckConstraint("port BETWEEN 1 AND 65535"),
        CheckConstraint("security IN ('none', 'starttls', 'tls')"),
        CheckConstraint("auth IN ('none', 'password')"),
        CheckConstraint("auth = 'none' OR (security IN ('starttls', 'tls') AND username IS NOT NULL AND password_encrypted IS NOT NULL)"),
    )


class SMTPCredential(Base):
    __tablename__ = "smtp_credentials"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    secret_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)


class CredentialScope(Base):
    __tablename__ = "credential_scopes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    credential_id: Mapped[str] = mapped_column(ForeignKey("smtp_credentials.id"))
    domain_id: Mapped[str] = mapped_column(ForeignKey("domains.id"))
    address: Mapped[str] = mapped_column(String(254, collation="utf8mb4_bin"))
    __table_args__ = (UniqueConstraint("credential_id", "domain_id", "address"),)


class SendAttempt(Base):
    __tablename__ = "send_attempts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True)
    credential_id: Mapped[str | None] = mapped_column(ForeignKey("smtp_credentials.id"))
    domain_id: Mapped[str | None] = mapped_column(ForeignKey("domains.id"), index=True)
    sender: Mapped[str] = mapped_column(String(254))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    error_code: Mapped[str | None] = mapped_column(String(32))
    error_stage: Mapped[str | None] = mapped_column(String(32))
    error_message: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, onupdate=utc_now)


class SendRecipient(Base):
    __tablename__ = "send_recipients"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    attempt_id: Mapped[str] = mapped_column(ForeignKey("send_attempts.id", ondelete="CASCADE"), index=True)
    address: Mapped[str] = mapped_column(String(254))


class RateLimit(Base):
    __tablename__ = "rate_limits"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
