"""Socket-level tests for the strict inbound SMTP protocol."""

from __future__ import annotations

import asyncio
import base64
import os
import ssl
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from smtp_relay_manager.config import Settings
from smtp_relay_manager.db import create_database
from smtp_relay_manager.models import (
    Base,
    RateLimit,
    SMTPCredential,
    User,
)
from smtp_relay_manager.security import hash_secret
from smtp_relay_manager.smtp.certificates import CertificateManager
from smtp_relay_manager.smtp.server import (
    SMTPRelayServer,
    validate_message_headers,
)
from smtp_relay_manager.smtp.service import (
    AttemptIdentity,
    AuthenticatedCredential,
    RelayService,
)
from smtp_relay_manager.upstream import DeliveryResult

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


def _write_certificate(
    directory: Path, hostname: str = "localhost"
) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), False
        )
        .sign(key, hashes.SHA256())
    )
    (directory / "fullchain.pem").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )
    (directory / "privkey.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate


class _Service:
    def __init__(self) -> None:
        self.messages: list[tuple[str, tuple[str, ...], bytes]] = []
        self.accepted: list[str] = []

    async def authenticate(
        self, username: str, password: str, peer: str = "unknown"
    ) -> AuthenticatedCredential:
        if (username, password) != ("token-id", "token-secret"):
            raise ValueError("invalid")
        return AuthenticatedCredential("token-id", "user-id")

    async def authorize(self, credential_id: str, sender: str) -> str:
        if sender != "sender@example.com":
            raise ValueError("denied")
        return "domain-id"

    async def relay(
        self,
        credential: AuthenticatedCredential,
        sender: str,
        recipients: tuple[str, ...],
        message: bytes,
    ) -> tuple[AttemptIdentity, DeliveryResult]:
        self.messages.append((sender, recipients, message))
        return (
            AttemptIdentity("attempt-id", "domain-id"),
            DeliveryResult(250, "queued", ()),
        )

    async def mark_accepted(self, attempt_id: str) -> None:
        self.accepted.append(attempt_id)


async def _response(reader: asyncio.StreamReader) -> bytes:
    return await asyncio.wait_for(reader.readline(), timeout=2)


async def _ehlo(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> bytes:
    writer.write(b"EHLO client.example\r\n")
    await writer.drain()
    lines = bytearray()
    while True:
        line = await _response(reader)
        lines.extend(line)
        if line[:3] == b"250" and line[3:4] == b" ":
            return bytes(lines)


@pytest.mark.asyncio
async def test_starttls_auth_and_relay_over_actual_socket(
    tmp_path: Path,
) -> None:
    _write_certificate(tmp_path)
    certificates = CertificateManager(tmp_path, "localhost")
    certificates.reload(required=True)
    service = _Service()
    server = SMTPRelayServer(
        service,  # type: ignore[arg-type]
        certificates,
        host="127.0.0.1",
        tls_port=0,
        starttls_port=0,
    )
    await server.start()
    port = server._servers[1].sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        assert (await _response(reader)).startswith(b"220 ")
        features = await _ehlo(reader, writer)
        assert b"STARTTLS" in features
        assert b"AUTH" not in features

        writer.write(b"AUTH PLAIN invalid\r\n")
        await writer.drain()
        assert (await _response(reader)).startswith(b"530 ")

        writer.write(b"STARTTLS\r\n")
        await writer.drain()
        assert (await _response(reader)).startswith(b"220 ")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        await writer.start_tls(context, server_hostname="localhost")

        features = await _ehlo(reader, writer)
        assert b"AUTH LOGIN PLAIN" in features
        credentials = base64.b64encode(b"\x00token-id\x00token-secret")
        writer.write(b"AUTH PLAIN " + credentials + b"\r\n")
        await writer.drain()
        assert (await _response(reader)).startswith(b"235 ")

        commands = [
            b"MAIL FROM:<sender@example.com>\r\n",
            b"RCPT TO:<recipient@example.net>\r\n",
            b"DATA\r\n",
        ]
        for command, expected in zip(
            commands, [b"250 ", b"250 ", b"354 "], strict=True
        ):
            writer.write(command)
            await writer.drain()
            assert (await _response(reader)).startswith(expected)
        writer.write(b"From: sender@example.com\r\n\r\nHello\r\n.\r\n")
        await writer.drain()
        assert (await _response(reader)).startswith(b"250 ")
    finally:
        writer.close()
        await writer.wait_closed()
        await server.close()

    assert service.messages == [
        (
            "sender@example.com",
            ("recipient@example.net",),
            b"From: sender@example.com\r\n\r\nHello\r\n",
        )
    ]
    assert service.accepted == ["attempt-id"]


@pytest.mark.asyncio
async def test_implicit_tls_supports_login_authentication(
    tmp_path: Path,
) -> None:
    _write_certificate(tmp_path)
    certificates = CertificateManager(tmp_path, "localhost")
    certificates.reload(required=True)
    service = _Service()
    server = SMTPRelayServer(
        service,  # type: ignore[arg-type]
        certificates,
        host="127.0.0.1",
        tls_port=0,
        starttls_port=0,
    )
    await server.start()
    port = server._servers[0].sockets[0].getsockname()[1]
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(
        "127.0.0.1",
        port,
        ssl=context,
        server_hostname="localhost",
    )
    try:
        assert (await _response(reader)).startswith(b"220 ")
        features = await _ehlo(reader, writer)
        assert b"AUTH LOGIN PLAIN" in features
        assert b"STARTTLS" not in features

        writer.write(b"AUTH LOGIN\r\n")
        await writer.drain()
        assert (await _response(reader)).startswith(b"334 ")
        writer.write(base64.b64encode(b"token-id") + b"\r\n")
        await writer.drain()
        assert (await _response(reader)).startswith(b"334 ")
        writer.write(base64.b64encode(b"token-secret") + b"\r\n")
        await writer.drain()
        assert (await _response(reader)).startswith(b"235 ")
    finally:
        writer.close()
        await writer.wait_closed()
        await server.close()


@pytest.mark.asyncio
async def test_implicit_tls_accepts_client_without_sni(tmp_path: Path) -> None:
    _write_certificate(tmp_path)
    certificates = CertificateManager(tmp_path, "localhost")
    certificates.reload(required=True)
    server = SMTPRelayServer(
        _Service(),  # type: ignore[arg-type]
        certificates,
        host="127.0.0.1",
        tls_port=0,
        starttls_port=0,
    )
    await server.start()
    port = server._servers[0].sockets[0].getsockname()[1]
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=context, server_hostname=""
    )
    try:
        assert (await _response(reader)).startswith(b"220 ")
    finally:
        writer.close()
        await writer.wait_closed()
        await server.close()


@pytest.mark.asyncio
async def test_failed_implicit_tls_handshakes_do_not_consume_slots(
    tmp_path: Path,
) -> None:
    _write_certificate(tmp_path)
    certificates = CertificateManager(tmp_path, "localhost")
    certificates.reload(required=True)
    server = SMTPRelayServer(
        _Service(),  # type: ignore[arg-type]
        certificates,
        host="127.0.0.1",
        tls_port=0,
        starttls_port=0,
        max_connections=1,
    )
    await server.start()
    port = server._servers[0].sockets[0].getsockname()[1]
    for _ in range(3):
        _, invalid = await asyncio.open_connection("127.0.0.1", port)
        invalid.write(b"not tls\r\n")
        await invalid.drain()
        invalid.close()
        await invalid.wait_closed()

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=context, server_hostname="localhost"
    )
    try:
        assert (await _response(reader)).startswith(b"220 ")
    finally:
        writer.close()
        await writer.wait_closed()
        await server.close()


def test_headers_require_exact_envelope_match() -> None:
    with pytest.raises(ValueError, match="does not match"):
        validate_message_headers(
            b"From: other@example.com\r\n\r\nmessage\r\n",
            "sender@example.com",
        )


def test_headers_reject_duplicate_from() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        validate_message_headers(
            b"From: sender@example.com\r\n"
            b"From: sender@example.com\r\n\r\nmessage\r\n",
            "sender@example.com",
        )


@pytest.mark.parametrize(
    "header",
    [
        b"From: sender@example.com <victim@example.org>\r\n",
        b"From: sender@example.com (unterminated\r\n",
        b"From: sender@example.com trailing garbage\r\n",
    ],
)
def test_headers_reject_parser_recovery_from_ambiguous_from(
    header: bytes,
) -> None:
    with pytest.raises(ValueError, match="malformed"):
        validate_message_headers(
            header + b"\r\nmessage\r\n", "sender@example.com"
        )


def test_invalid_certificate_reload_keeps_valid_active_context(
    tmp_path: Path,
) -> None:
    _write_certificate(tmp_path)
    manager = CertificateManager(tmp_path, "localhost")
    manager.reload(required=True)
    context = manager.context
    (tmp_path / "privkey.pem").write_text(
        "not a private key", encoding="ascii"
    )

    assert manager.reload() is False
    assert manager.usable is True
    assert manager.context is context


def test_certificate_reload_activates_validated_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_certificate(tmp_path)
    manager = CertificateManager(tmp_path, "localhost")
    read_snapshot = manager._read_files

    def replace_mount_after_read() -> tuple[bytes, bytes, bytes]:
        snapshot = read_snapshot()
        (tmp_path / "privkey.pem").write_text(
            "replaced after read", encoding="ascii"
        )
        return snapshot

    monkeypatch.setattr(manager, "_read_files", replace_mount_after_read)
    assert manager.reload(required=True) is True
    assert manager.usable is True


@pytest.mark.asyncio
async def test_certificate_watcher_recovers_after_invalid_files(
    tmp_path: Path,
) -> None:
    (tmp_path / "fullchain.pem").write_text("invalid", encoding="ascii")
    (tmp_path / "privkey.pem").write_text("invalid", encoding="ascii")
    manager = CertificateManager(tmp_path, "localhost")
    stop = asyncio.Event()
    watcher = asyncio.create_task(manager.watch(0.01, stop))
    await asyncio.sleep(0.03)
    assert watcher.done() is False

    _write_certificate(tmp_path)
    for _ in range(100):
        if manager.usable:
            break
        await asyncio.sleep(0.01)
    stop.set()
    await watcher
    assert manager.usable is True


@pytest.mark.asyncio
async def test_certificate_reload_updates_new_connections_only(
    tmp_path: Path,
) -> None:
    first_certificate = _write_certificate(tmp_path)
    manager = CertificateManager(tmp_path, "localhost")
    manager.reload(required=True)
    server = SMTPRelayServer(
        _Service(),  # type: ignore[arg-type]
        manager,
        host="127.0.0.1",
        tls_port=0,
        starttls_port=0,
    )
    await server.start()
    port = server._servers[0].sockets[0].getsockname()[1]
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    reader_one, writer_one = await asyncio.open_connection(
        "127.0.0.1", port, ssl=context, server_hostname="localhost"
    )
    assert (await _response(reader_one)).startswith(b"220 ")
    peer_one = writer_one.get_extra_info("ssl_object").getpeercert(
        binary_form=True
    )
    assert (
        x509.load_der_x509_certificate(peer_one).serial_number
        == first_certificate.serial_number
    )

    second_certificate = _write_certificate(tmp_path)
    assert manager.reload() is True
    reader_two, writer_two = await asyncio.open_connection(
        "127.0.0.1", port, ssl=context, server_hostname="localhost"
    )
    try:
        assert (await _response(reader_two)).startswith(b"220 ")
        peer_two = writer_two.get_extra_info("ssl_object").getpeercert(
            binary_form=True
        )
        assert (
            x509.load_der_x509_certificate(peer_two).serial_number
            == second_certificate.serial_number
        )
        assert (
            first_certificate.serial_number != second_certificate.serial_number
        )
        assert b"250-localhost" in await _ehlo(reader_one, writer_one)
    finally:
        writer_one.close()
        writer_two.close()
        await writer_one.wait_closed()
        await writer_two.wait_closed()
        await server.close()


async def test_successful_authentication_releases_rate_reservations(
    database: DatabaseFactory,
) -> None:
    async with database.begin() as db:
        db.add(User(id="user-id", username="sender", active=True))
        await db.flush()
        db.add(
            SMTPCredential(
                id="token-id",
                user_id="user-id",
                name="application",
                secret_hash=hash_secret("token-secret"),
            )
        )
    service = RelayService(database, Fernet.generate_key().decode("ascii"))

    for _ in range(7):
        credential = await service.authenticate(
            "token-id", "token-secret", "192.0.2.10"
        )
        assert credential.id == "token-id"

    async with database() as db:
        buckets = (await db.scalars(select(RateLimit))).all()
        assert [bucket.attempts for bucket in buckets] == [0, 0]
