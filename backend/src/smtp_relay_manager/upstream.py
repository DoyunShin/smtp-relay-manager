"""Validated, DNS-pinned connections to an upstream SMTP server."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

import aiosmtplib


class UpstreamSecurity(StrEnum):
    """Transport security used by an upstream SMTP server."""

    NONE = "none"
    STARTTLS = "starttls"
    TLS = "tls"


class UpstreamAuth(StrEnum):
    """Authentication used by an upstream SMTP server."""

    NONE = "none"
    PASSWORD = "password"


@dataclass(frozen=True, slots=True)
class UpstreamEndpoint:
    """Decrypted connection settings for one domain's upstream server."""

    host: str
    port: int
    security: UpstreamSecurity
    auth: UpstreamAuth = UpstreamAuth.NONE
    username: str | None = None
    password: str | None = None


@dataclass(frozen=True, slots=True)
class RecipientResult:
    """An upstream SMTP response for a recipient."""

    recipient: str
    code: int
    message: str


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    """The final response returned after upstream DATA."""

    code: int
    message: str
    recipients: tuple[RecipientResult, ...]


class UpstreamError(Exception):
    """Base class for failures before a final upstream DATA response."""


class UnsafeUpstreamHost(UpstreamError):
    """Raised when a host is invalid or resolves outside the public Internet."""


class RecipientRejected(UpstreamError):
    """Raised before DATA when at least one recipient is rejected."""

    def __init__(self, results: Sequence[RecipientResult]) -> None:
        self.results = tuple(results)
        super().__init__("one or more upstream recipients were rejected")


class DeliveryUncertain(UpstreamError):
    """Raised when the connection is lost after DATA begins."""


Resolver = Callable[[str, int], Awaitable[Sequence[tuple[int, str]]]]
SocketConnector = Callable[[int, str, int, float], Awaitable[socket.socket]]


class SMTPClient(Protocol):
    """Subset of aiosmtplib.SMTP used by the relay."""

    async def connect(self, **kwargs: Any) -> Any: ...
    async def starttls(self, **kwargs: Any) -> Any: ...
    async def login(self, username: str, password: str, **kwargs: Any) -> Any: ...
    async def mail(self, sender: str, **kwargs: Any) -> Any: ...
    async def rcpt(self, recipient: str, **kwargs: Any) -> Any: ...
    async def data(self, message: bytes, **kwargs: Any) -> Any: ...
    async def rset(self, **kwargs: Any) -> Any: ...
    async def quit(self, **kwargs: Any) -> Any: ...
    def close(self) -> None: ...


def normalize_upstream_host(host: str) -> str:
    """Return a safe ASCII host name, rejecting SMTP/config injection."""

    if host != host.strip():
        raise UnsafeUpstreamHost("upstream host contains surrounding whitespace")
    if host.endswith(".."):
        raise UnsafeUpstreamHost("upstream host has multiple trailing dots")
    candidate = host.rstrip(".")
    if not candidate or any(ord(character) < 32 for character in candidate):
        raise UnsafeUpstreamHost("upstream host is empty or contains control characters")
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    try:
        ascii_host = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise UnsafeUpstreamHost("upstream host is not a valid DNS name") from exc
    if len(ascii_host) > 253 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(character.isalnum() or character == "-" for character in label)
        for label in ascii_host.split(".")
    ):
        raise UnsafeUpstreamHost("upstream host is not a valid DNS name")
    return ascii_host


def validate_upstream_endpoint(endpoint: UpstreamEndpoint) -> None:
    """Validate settings which do not require DNS or a network connection."""

    normalize_upstream_host(endpoint.host)
    if not 1 <= endpoint.port <= 65535:
        raise ValueError("upstream port must be between 1 and 65535")
    if endpoint.auth is UpstreamAuth.PASSWORD:
        if endpoint.security is UpstreamSecurity.NONE:
            raise ValueError("password authentication requires TLS")
        if not endpoint.username or endpoint.password is None:
            raise ValueError("password authentication requires username and password")
        if any(character in endpoint.username for character in "\r\n\x00"):
            raise ValueError("upstream username contains control characters")
    elif endpoint.username is not None or endpoint.password is not None:
        raise ValueError("credentials must be omitted when authentication is disabled")


async def _system_resolver(host: str, port: int) -> Sequence[tuple[int, str]]:
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    unique: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    for family, _, _, _, sockaddr in records:
        item = (family, sockaddr[0])
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _is_public_address(address: str) -> bool:
    return ipaddress.ip_address(address).is_global


async def resolve_public_addresses(
    host: str,
    port: int,
    *,
    resolver: Resolver | None = None,
) -> tuple[tuple[int, str], ...]:
    """Resolve a host and require every returned address to be globally routable."""

    normalized = normalize_upstream_host(host)
    try:
        literal = ipaddress.ip_address(normalized)
    except ValueError:
        try:
            addresses = tuple(await (resolver or _system_resolver)(normalized, port))
        except OSError as exc:
            raise UnsafeUpstreamHost("upstream host could not be resolved") from exc
    else:
        family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
        addresses = ((family, str(literal)),)
    if not addresses:
        raise UnsafeUpstreamHost("upstream host did not resolve")
    if any(family not in {socket.AF_INET, socket.AF_INET6} for family, _ in addresses):
        raise UnsafeUpstreamHost("resolver returned an unsupported address family")
    try:
        unsafe = [address for _, address in addresses if not _is_public_address(address)]
    except ValueError as exc:
        raise UnsafeUpstreamHost("resolver returned an invalid IP address") from exc
    if unsafe:
        raise UnsafeUpstreamHost("upstream host resolved to a non-public IP address")
    return addresses


async def validate_upstream_host(
    host: str,
    port: int = 25,
    *,
    resolver: Resolver | None = None,
) -> None:
    """Validate that a host currently resolves only to public addresses."""

    await resolve_public_addresses(host, port, resolver=resolver)


async def _connect_socket(
    family: int,
    address: str,
    port: int,
    timeout: float,
) -> socket.socket:
    sock = socket.socket(family=family, type=socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(
            asyncio.get_running_loop().sock_connect(sock, (address, port)), timeout
        )
    except BaseException:
        sock.close()
        raise
    return sock


def _response_parts(response: Any) -> tuple[int, str]:
    code = int(response.code)
    message = response.message
    if isinstance(message, bytes):
        message = message.decode("utf-8", "replace")
    return code, str(message)


class UpstreamSMTP:
    """Connect to a validated address and synchronously relay one message."""

    def __init__(
        self,
        endpoint: UpstreamEndpoint,
        *,
        resolver: Resolver | None = None,
        socket_connector: SocketConnector = _connect_socket,
        connect_timeout: float = 15.0,
        command_timeout: float = 30.0,
        tls_context: ssl.SSLContext | None = None,
        client_factory: Callable[..., SMTPClient] = aiosmtplib.SMTP,
    ) -> None:
        validate_upstream_endpoint(endpoint)
        self.endpoint = endpoint
        self.resolver = resolver
        self.socket_connector = socket_connector
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        self.tls_context = tls_context or ssl.create_default_context()
        self.client_factory = client_factory
        self.client: SMTPClient | None = None

    async def connect(self) -> None:
        """Resolve, validate, pin, connect, secure, and authenticate."""

        host = normalize_upstream_host(self.endpoint.host)
        addresses = await resolve_public_addresses(
            host, self.endpoint.port, resolver=self.resolver
        )
        last_error: BaseException | None = None
        sock: socket.socket | None = None
        for family, address in addresses:
            try:
                sock = await self.socket_connector(
                    family, address, self.endpoint.port, self.connect_timeout
                )
                break
            except (OSError, TimeoutError) as exc:
                last_error = exc
        if sock is None:
            raise UpstreamError("could not connect to any validated upstream address") from last_error

        client = self.client_factory(
            hostname=host,
            port=self.endpoint.port,
            use_tls=self.endpoint.security is UpstreamSecurity.TLS,
            start_tls=False,
            validate_certs=True,
            tls_context=self.tls_context,
            timeout=self.command_timeout,
        )
        try:
            await client.connect(sock=sock, timeout=self.connect_timeout)
            if self.endpoint.security is UpstreamSecurity.STARTTLS:
                await client.starttls(
                    validate_certs=True,
                    tls_context=self.tls_context,
                    timeout=self.command_timeout,
                )
            if self.endpoint.auth is UpstreamAuth.PASSWORD:
                assert self.endpoint.username is not None
                assert self.endpoint.password is not None
                await client.login(
                    self.endpoint.username,
                    self.endpoint.password,
                    timeout=self.command_timeout,
                )
        except BaseException:
            client.close()
            raise
        self.client = client

    async def deliver(
        self,
        sender: str,
        recipients: Sequence[str],
        message: bytes,
        *,
        pre_data_hook: Callable[[], Awaitable[None]] | None = None,
    ) -> DeliveryResult:
        """Send all envelopes before DATA and never partially deliver recipients."""

        if self.client is None:
            raise RuntimeError("upstream SMTP client is not connected")
        client = self.client
        await client.mail(sender, timeout=self.command_timeout)
        results: list[RecipientResult] = []
        rejected = False
        for recipient in recipients:
            try:
                response = await client.rcpt(recipient, timeout=self.command_timeout)
                code, detail = _response_parts(response)
            except aiosmtplib.SMTPRecipientRefused as exc:
                code = int(exc.code)
                detail = str(exc.message)
            results.append(RecipientResult(recipient, code, detail))
            rejected = rejected or not 200 <= code < 300
        if rejected:
            try:
                await client.rset(timeout=self.command_timeout)
            finally:
                raise RecipientRejected(results)
        if pre_data_hook is not None:
            await pre_data_hook()
        try:
            response = await client.data(message, timeout=self.command_timeout)
        except asyncio.CancelledError as exc:
            raise DeliveryUncertain("upstream result is unknown after DATA began") from exc
        except (
            OSError,
            TimeoutError,
            asyncio.IncompleteReadError,
            aiosmtplib.SMTPServerDisconnected,
        ) as exc:
            raise DeliveryUncertain("upstream result is unknown after DATA began") from exc
        code, detail = _response_parts(response)
        return DeliveryResult(code, detail, tuple(results))

    async def close(self) -> None:
        """Close the SMTP session without obscuring a delivery result."""

        if self.client is None:
            return
        client, self.client = self.client, None
        try:
            await client.quit(timeout=self.command_timeout)
        except BaseException:
            client.close()


__all__ = [
    "DeliveryResult",
    "DeliveryUncertain",
    "RecipientRejected",
    "RecipientResult",
    "UnsafeUpstreamHost",
    "UpstreamAuth",
    "UpstreamEndpoint",
    "UpstreamError",
    "UpstreamSMTP",
    "UpstreamSecurity",
    "normalize_upstream_host",
    "resolve_public_addresses",
    "validate_upstream_endpoint",
    "validate_upstream_host",
]
