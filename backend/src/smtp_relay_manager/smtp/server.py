"""Authenticated SMTP submission built on aiosmtpd."""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
from email import policy as email_policy
from email.headerregistry import AddressHeader
from email.parser import BytesParser
from typing import Any, cast

import aiosmtplib
from aiosmtpd.smtp import AuthResult, Envelope, MISSING, SMTP, Session

from smtp_relay_manager.errors import AppError
from smtp_relay_manager.policy import normalize_address
from smtp_relay_manager.upstream import DeliveryUncertain, RecipientRejected

from .certificates import CertificateManager
from .service import AuthenticatedCredential, RelayService

LOGGER = logging.getLogger(__name__)
_MAX_HEADER_BYTES = 64 * 1024


class SMTPProtocolError(ValueError):
    """Raised when a submitted message violates relay policy."""


def _single_header_address(message: Any, name: str, *, required: bool) -> str | None:
    values = message.get_all(name, [])
    if not values:
        if required:
            raise SMTPProtocolError(f"exactly one {name} header is required")
        return None
    if len(values) != 1 or not isinstance(values[0], AddressHeader):
        raise SMTPProtocolError(f"exactly one {name} header is required")
    if values[0].defects:
        raise SMTPProtocolError(f"{name} header is malformed")
    addresses = values[0].addresses
    if len(addresses) != 1 or not addresses[0].addr_spec:
        raise SMTPProtocolError(f"{name} must contain one mailbox")
    return normalize_address(addresses[0].addr_spec)


def validate_message_headers(message: bytes, envelope_sender: str) -> None:
    """Require one From and an optional matching Sender in at most 64 KiB."""

    separator = message.find(b"\r\n\r\n", 0, _MAX_HEADER_BYTES + 1)
    if separator < 0:
        raise SMTPProtocolError("message has no complete header block within 64 KiB")
    parsed = BytesParser(policy=email_policy.default).parsebytes(
        message[: separator + 4], headersonly=True
    )
    if parsed.defects:
        raise SMTPProtocolError("message headers are malformed")
    from_address = _single_header_address(parsed, "From", required=True)
    sender_address = _single_header_address(parsed, "Sender", required=False)
    if from_address != envelope_sender:
        raise SMTPProtocolError("From header does not match MAIL FROM")
    if sender_address is not None and sender_address != envelope_sender:
        raise SMTPProtocolError("Sender header does not match MAIL FROM")


def _smtp_code(error: BaseException, default: int = 451) -> int:
    if isinstance(error, AppError):
        return 553 if error.status_code in {401, 403} else 550
    if isinstance(error, RecipientRejected):
        rejected = [item.code for item in error.results if not 200 <= item.code < 300]
        temporary = next((code for code in rejected if 400 <= code < 500), None)
        permanent = next((code for code in rejected if 500 <= code < 600), None)
        return temporary or permanent or default
    if isinstance(error, aiosmtplib.SMTPResponseException):
        return error.code if 400 <= error.code <= 599 else default
    return default


def _safe_failure(error: BaseException) -> str:
    """Categorize failures without exposing credentials or library diagnostics."""

    if isinstance(error, AppError):
        if error.status_code == 403:
            return "Sender is no longer authorized"
        if error.status_code == 409:
            return "Upstream SMTP is not configured"
        return "Relay policy rejected the message"
    if isinstance(error, RecipientRejected):
        return "One or more recipients were rejected by upstream"
    if isinstance(error, aiosmtplib.SMTPResponseException):
        return "Upstream SMTP rejected the request"
    if isinstance(error, (TimeoutError, ConnectionError, OSError)):
        return "Upstream SMTP connection failed"
    if isinstance(error, ValueError):
        return "Upstream SMTP configuration is invalid"
    return "Temporary upstream delivery failure"


class _RelayHandler:
    def __init__(
        self,
        service: RelayService,
        data_limit: asyncio.Semaphore,
        max_recipients: int,
        transaction_timeout: float,
    ) -> None:
        self.service = service
        self.data_limit = data_limit
        self.max_recipients = max_recipients
        self.transaction_timeout = transaction_timeout

    async def handle_MAIL(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        mail_options: list[str],
    ) -> str:
        del server, mail_options
        credential = session.auth_data
        if not isinstance(credential, AuthenticatedCredential):
            return "530 5.7.0 Authentication required"
        try:
            sender = normalize_address(address)
            await self.service.authorize(credential.id, sender)
        except (AppError, ValueError):
            return "553 5.7.1 Sender is not authorized"
        except Exception as error:
            LOGGER.warning("Sender authorization backend failed (%s)", type(error).__name__)
            return "451 4.3.0 Temporary authorization failure"
        envelope.mail_from = sender
        envelope.transaction_started = asyncio.get_running_loop().time()
        return "250 2.1.0 Sender accepted"

    async def handle_RCPT(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        del server, session, rcpt_options
        if len(envelope.rcpt_tos) >= self.max_recipients:
            return "452 4.5.3 Too many recipients"
        try:
            recipient = normalize_address(address)
        except (AppError, ValueError):
            return "501 5.1.3 Invalid recipient address"
        envelope.rcpt_tos.append(recipient)
        return "250 2.1.5 Recipient accepted"

    def remaining_time(self, envelope: Envelope) -> float:
        started = getattr(envelope, "transaction_started", None)
        if started is None:
            return self.transaction_timeout
        elapsed = asyncio.get_running_loop().time() - cast(float, started)
        return max(0.001, self.transaction_timeout - elapsed)

    async def handle_DATA(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
    ) -> str:
        del server
        credential = session.auth_data
        if not isinstance(credential, AuthenticatedCredential):
            return "530 5.7.0 Authentication required"
        content = envelope.original_content
        if not isinstance(content, bytes):
            return "451 4.3.0 Message content unavailable"
        try:
            sender = normalize_address(envelope.mail_from)
            validate_message_headers(content, sender)
        except (SMTPProtocolError, AppError, ValueError):
            return "550 5.7.1 From or Sender header does not match MAIL FROM"

        attempt_id: str | None = None
        try:
            attempt, response = await self.service.relay(
                credential, sender, tuple(envelope.rcpt_tos), content
            )
            attempt_id = attempt.attempt_id
            if 200 <= response.code < 300:
                await self.service.mark_accepted(attempt_id)
                return "250 2.0.0 Message accepted by upstream"
            message = "Upstream SMTP rejected message data"
            await self.service.mark_failed(attempt_id, str(response.code), "data", message)
            code = response.code if 400 <= response.code <= 599 else 451
            return f"{code} {_enhanced_status(code)} {message}"
        except DeliveryUncertain as error:
            attempt_id = getattr(error, "attempt_id", None)
            if attempt_id is not None:
                await self._record_failure(
                    attempt_id, "unknown", "451", "data", "Delivery result is unknown"
                )
            return "451 4.4.2 Upstream delivery result is unknown"
        except Exception as error:
            attempt_id = getattr(error, "attempt_id", None)
            code = _smtp_code(error)
            safe_message = _safe_failure(error)
            if attempt_id is not None:
                await self._record_failure(
                    attempt_id, "failed", str(code), "upstream", safe_message
                )
            LOGGER.warning("SMTP relay failed (%s)", type(error).__name__)
            return f"{code} {_enhanced_status(code)} {safe_message}"

    async def _record_failure(
        self,
        attempt_id: str,
        status: str,
        code: str,
        stage: str,
        message: str,
    ) -> None:
        try:
            if status == "unknown":
                await self.service.mark_unknown(attempt_id, code, stage, message)
            else:
                await self.service.mark_failed(attempt_id, code, stage, message)
        except Exception as error:
            LOGGER.warning("Could not finalize send attempt (%s)", type(error).__name__)


def _enhanced_status(code: int) -> str:
    return "4.0.0" if 400 <= code < 500 else "5.0.0"


class _RelaySMTP(SMTP):
    """aiosmtpd protocol with async token auth and pre-354 DATA admission."""

    def __init__(
        self,
        handler: _RelayHandler,
        *,
        implicit_tls: bool,
        admit_connection: Any,
        release_connection: Any,
        **kwargs: Any,
    ) -> None:
        self._relay_handler = handler
        self._implicit_tls = implicit_tls
        self._admit_connection = admit_connection
        self._release_connection = release_connection
        self._admitted = False
        self._connection_released = False
        super().__init__(handler, **kwargs)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        if not self._admitted:
            if not self._admit_connection():
                transport.write(b"421 4.3.2 Too many connections\r\n")
                transport.close()
                return
            self._admitted = True
        super().connection_made(transport)
        if self._implicit_tls:
            # aiosmtpd tracks only STARTTLS internally. Set its marker only
            # after confirming this is an actual TLS transport.
            if transport.get_extra_info("ssl_object") is None:
                transport.close()
            else:
                self._tls_protocol = cast(Any, object())

    def connection_lost(self, error: Exception | None) -> None:
        if not self._admitted:
            return
        try:
            super().connection_lost(error)
        finally:
            if self._admitted and not self._connection_released:
                self._connection_released = True
                self._release_connection()

    async def smtp_STARTTLS(self, arg: str | None) -> None:
        if self.transport is not None and self.transport.get_extra_info("ssl_object"):
            await self.push("503 5.5.1 TLS is already active")
            return
        await super().smtp_STARTTLS(arg or "")

    async def smtp_DATA(self, arg: str | None) -> None:
        if self._relay_handler.data_limit.locked():
            await self.push("452 4.3.1 Too many messages in progress")
            return
        await self._relay_handler.data_limit.acquire()
        try:
            assert self.envelope is not None
            try:
                async with asyncio.timeout(
                    self._relay_handler.remaining_time(self.envelope)
                ):
                    await super().smtp_DATA(arg or "")
            except TimeoutError:
                self._set_post_data_state()
                await self.push("451 4.4.2 SMTP transaction timed out")
        finally:
            self._relay_handler.data_limit.release()

    async def _authenticate_values(
        self, authz: bytes, username: bytes, password: bytes
    ) -> AuthResult:
        if authz and authz != username:
            return AuthResult(success=False)
        if self.transport is None or self.transport.get_extra_info("ssl_object") is None:
            return AuthResult(success=False, message="538 5.7.11 Encryption required")
        assert self.session is not None
        peer_info = self.session.peer
        peer = str(peer_info[0]) if peer_info else "unknown"
        try:
            credential = await self._relay_handler.service.authenticate(
                username.decode("utf-8"), password.decode("utf-8"), peer
            )
        except (UnicodeDecodeError, AppError):
            return AuthResult(success=False)
        except Exception as error:
            LOGGER.warning("SMTP authentication backend failed (%s)", type(error).__name__)
            return AuthResult(
                success=False, message="454 4.7.0 Temporary authentication failure"
            )
        return AuthResult(success=True, auth_data=credential)

    async def auth_PLAIN(self, _: SMTP, args: list[str]) -> AuthResult:
        if len(args) == 1:
            raw = await self.challenge_auth("")
            if raw is MISSING:
                return AuthResult(success=False)
        else:
            try:
                raw = base64.b64decode(args[1].encode("ascii"), validate=True)
            except (UnicodeEncodeError, binascii.Error):
                await self.push("501 5.5.2 Invalid base64 authentication value")
                return AuthResult(success=False, handled=True)
        try:
            authz, username, password = raw.split(b"\x00")
        except ValueError:
            await self.push("501 5.5.2 Invalid PLAIN authentication value")
            return AuthResult(success=False, handled=True)
        return await self._authenticate_values(authz, username, password)

    async def auth_LOGIN(self, _: SMTP, args: list[str]) -> AuthResult:
        if len(args) == 1:
            username = await self.challenge_auth(self.AuthLoginUsernameChallenge)
            if username is MISSING:
                return AuthResult(success=False)
        else:
            try:
                username = base64.b64decode(args[1].encode("ascii"), validate=True)
            except (UnicodeEncodeError, binascii.Error):
                await self.push("501 5.5.2 Invalid base64 authentication value")
                return AuthResult(success=False, handled=True)
        password = await self.challenge_auth(self.AuthLoginPasswordChallenge)
        if password is MISSING:
            return AuthResult(success=False)
        return await self._authenticate_values(b"", username, password)


class SMTPRelayServer:
    """Run implicit-TLS and mandatory-STARTTLS aiosmtpd listeners."""

    def __init__(
        self,
        service: RelayService,
        certificates: CertificateManager,
        *,
        host: str = "0.0.0.0",
        tls_port: int = 8465,
        starttls_port: int = 8587,
        max_message_bytes: int = 25 * 1024**2,
        max_recipients: int = 100,
        max_connections: int = 32,
        max_data_connections: int = 4,
        idle_timeout: float = 60.0,
        transaction_timeout: float = 120.0,
    ) -> None:
        self.service = service
        self.certificates = certificates
        self.host = host
        self.tls_port = tls_port
        self.starttls_port = starttls_port
        self.max_message_bytes = max_message_bytes
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self._data_limit = asyncio.Semaphore(max_data_connections)
        self._handler = _RelayHandler(
            service, self._data_limit, max_recipients, transaction_timeout
        )
        self._servers: list[asyncio.Server] = []
        self._protocols: set[_RelaySMTP] = set()
        self._drained = asyncio.Event()
        self._drained.set()

    def _release_connection(self, protocol: _RelaySMTP) -> None:
        self._protocols.discard(protocol)
        if not self._protocols:
            self._drained.set()

    def _admit_connection(self, protocol: _RelaySMTP) -> bool:
        if len(self._protocols) >= self.max_connections:
            return False
        self._protocols.add(protocol)
        self._drained.clear()
        return True

    def _protocol_factory(self, *, implicit_tls: bool) -> asyncio.Protocol:
        protocol: _RelaySMTP
        protocol = _RelaySMTP(
            self._handler,
            implicit_tls=implicit_tls,
            admit_connection=lambda: self._admit_connection(protocol),
            release_connection=lambda: self._release_connection(protocol),
            data_size_limit=self.max_message_bytes,
            enable_SMTPUTF8=False,
            decode_data=False,
            hostname=self.certificates.hostname,
            ident="SMTP Relay Manager",
            tls_context=self.certificates.context,
            require_starttls=True,
            timeout=self.idle_timeout,
            auth_required=True,
            auth_require_tls=True,
            auth_exclude_mechanism={"CRAM-MD5"},
        )
        return protocol

    async def start(self) -> None:
        """Start both listeners after the certificate has been validated."""

        if self._servers:
            return
        if not self.certificates.usable:
            raise RuntimeError("SMTP TLS certificate is unavailable or expired")
        loop = asyncio.get_running_loop()
        implicit = await loop.create_server(
            lambda: self._protocol_factory(implicit_tls=True),
            self.host,
            self.tls_port,
            ssl=self.certificates.context,
            ssl_handshake_timeout=15.0,
        )
        try:
            starttls = await loop.create_server(
                lambda: self._protocol_factory(implicit_tls=False),
                self.host,
                self.starttls_port,
            )
        except BaseException:
            implicit.close()
            await implicit.wait_closed()
            raise
        self._servers = [implicit, starttls]

    async def close(self) -> None:
        """Stop both listeners."""

        servers, self._servers = self._servers, []
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))

    async def shutdown(self, timeout: float) -> None:
        """Stop listeners, then give established sessions bounded drain time."""

        await self.close()
        try:
            await asyncio.wait_for(self._drained.wait(), timeout=timeout)
        except TimeoutError:
            for protocol in tuple(self._protocols):
                if protocol.transport is not None:
                    protocol.transport.close()

    async def serve_forever(self) -> None:
        """Serve until cancelled."""

        await self.start()
        await asyncio.gather(*(server.serve_forever() for server in self._servers))


__all__ = ["SMTPProtocolError", "SMTPRelayServer", "validate_message_headers"]
