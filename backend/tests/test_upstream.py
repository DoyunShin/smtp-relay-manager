"""Unit tests for upstream validation and all-recipient delivery semantics."""

from __future__ import annotations

import socket
from dataclasses import dataclass

import pytest

from smtp_relay_manager.upstream import (
    RecipientRejected,
    UnsafeUpstreamHost,
    UpstreamAuth,
    UpstreamEndpoint,
    UpstreamSecurity,
    UpstreamSMTP,
    resolve_public_addresses,
    validate_upstream_endpoint,
)


async def test_resolution_rejects_mixed_public_and_private_answer() -> None:
    async def resolver(host: str, port: int) -> list[tuple[int, str]]:
        assert (host, port) == ("smtp.example.com", 25)
        return [(socket.AF_INET, "203.0.113.2"), (socket.AF_INET, "127.0.0.1")]

    with pytest.raises(UnsafeUpstreamHost):
        await resolve_public_addresses(
            "smtp.example.com", 25, resolver=resolver
        )


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "10.0.0.1", "169.254.1.1", "::1", "fc00::1", "0.0.0.0"],
)
async def test_resolution_rejects_non_public_literals(host: str) -> None:
    with pytest.raises(UnsafeUpstreamHost):
        await resolve_public_addresses(host, 25)


async def test_resolution_error_is_safe_validation_failure() -> None:
    async def resolver(host: str, port: int) -> list[tuple[int, str]]:
        raise socket.gaierror("resolver detail")

    with pytest.raises(UnsafeUpstreamHost, match="could not be resolved"):
        await resolve_public_addresses(
            "missing.example", 25, resolver=resolver
        )


def test_password_authentication_requires_tls() -> None:
    endpoint = UpstreamEndpoint(
        "smtp.example.com",
        25,
        UpstreamSecurity.NONE,
        UpstreamAuth.PASSWORD,
        "user",
        "secret",
    )
    with pytest.raises(ValueError, match="requires TLS"):
        validate_upstream_endpoint(endpoint)


@pytest.mark.parametrize(
    "host", [" smtp.example.com", "smtp.example.com\nother"]
)
def test_host_rejects_ambiguous_lexical_input(host: str) -> None:
    endpoint = UpstreamEndpoint(host, 25, UpstreamSecurity.NONE)
    with pytest.raises(UnsafeUpstreamHost):
        validate_upstream_endpoint(endpoint)


@dataclass
class _Response:
    code: int
    message: str


class _Client:
    def __init__(self, rcpt_codes: list[int]) -> None:
        self.rcpt_codes = iter(rcpt_codes)
        self.events: list[str] = []

    async def mail(self, sender: str, **kwargs: object) -> _Response:
        self.events.append(f"mail:{sender}")
        return _Response(250, "ok")

    async def rcpt(self, recipient: str, **kwargs: object) -> _Response:
        self.events.append(f"rcpt:{recipient}")
        code = next(self.rcpt_codes)
        return _Response(code, "recipient response")

    async def data(self, message: bytes, **kwargs: object) -> _Response:
        self.events.append("data")
        return _Response(250, "queued")

    async def rset(self, **kwargs: object) -> _Response:
        self.events.append("rset")
        return _Response(250, "reset")


async def test_all_recipients_are_checked_before_data() -> None:
    upstream = UpstreamSMTP(
        UpstreamEndpoint("smtp.example.com", 25, UpstreamSecurity.NONE)
    )
    client = _Client([250, 550])
    upstream.client = client  # type: ignore[assignment]

    with pytest.raises(RecipientRejected) as rejected:
        await upstream.deliver(
            "sender@example.com",
            ["one@example.net", "two@example.net"],
            b"message",
        )

    assert [result.code for result in rejected.value.results] == [250, 550]
    assert client.events == [
        "mail:sender@example.com",
        "rcpt:one@example.net",
        "rcpt:two@example.net",
        "rset",
    ]


async def test_fresh_authorization_runs_after_rcpt_before_data() -> None:
    upstream = UpstreamSMTP(
        UpstreamEndpoint("smtp.example.com", 25, UpstreamSecurity.NONE)
    )
    client = _Client([250])
    upstream.client = client  # type: ignore[assignment]

    async def authorize() -> None:
        client.events.append("authorize")

    result = await upstream.deliver(
        "sender@example.com",
        ["recipient@example.net"],
        b"message",
        pre_data_hook=authorize,
    )

    assert result.code == 250
    assert client.events == [
        "mail:sender@example.com",
        "rcpt:recipient@example.net",
        "authorize",
        "data",
    ]
