"""Integration tests for management API authorization boundaries."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Callable
from datetime import timedelta
from typing import Any

import httpx
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import create_async_engine

from smtp_relay_manager.config import Settings
from smtp_relay_manager.main import create_app
from smtp_relay_manager.maintenance import run_maintenance_once
from smtp_relay_manager.models import (
    Base,
    Domain,
    Invitation,
    RateLimit,
    SendAttempt,
    SendRecipient,
    User,
    WebSession,
    new_id,
    utc_now,
)
from smtp_relay_manager.security import hash_password, hash_secret

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL, reason="TEST_DATABASE_URL is required"
)


class APIClient:
    """Authenticated test client that carries its current CSRF token."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self.csrf_token: str | None = None

    async def login(
        self, username: str, password: str = "correct horse battery staple"
    ) -> None:
        response = await self.client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )
        assert response.status_code == 200, response.text
        self.csrf_token = response.json()["data"]["csrf_token"]

    async def request(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}))
        if (
            method.upper() not in {"GET", "HEAD", "OPTIONS"}
            and self.csrf_token
        ):
            headers["X-CSRF-Token"] = self.csrf_token
        return await self.client.request(
            method, url, headers=headers, **kwargs
        )


@pytest.fixture
async def application() -> AsyncIterator[Any]:
    assert TEST_DATABASE_URL is not None
    bootstrap_engine = create_async_engine(TEST_DATABASE_URL)
    async with bootstrap_engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    await bootstrap_engine.dispose()

    settings = Settings(
        database_url=TEST_DATABASE_URL,
        encryption_key=Fernet.generate_key().decode("ascii"),
        public_base_url="https://relay.example.test",
        session_cookie_name="relay_session",
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        yield app


@pytest.fixture
def client_factory(application: Any) -> Callable[[], httpx.AsyncClient]:
    def create_client() -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="https://relay.example.test",
        )

    return create_client


async def add_user(
    application: Any,
    username: str,
    *,
    operator: bool = False,
    active: bool = True,
    password: str = "correct horse battery staple",
) -> User:
    user = User(
        id=new_id(),
        username=username,
        password_hash=await hash_password(password),
        active=active,
        is_operator=operator,
    )
    async with application.state.session_factory.begin() as database:
        database.add(user)
    return user


@pytest.mark.asyncio
async def test_operator_invites_user_and_invitation_is_single_use(
    application: Any, client_factory: Callable[[], httpx.AsyncClient]
) -> None:
    await add_user(application, "operator", operator=True)
    async with client_factory() as raw_operator:
        operator = APIClient(raw_operator)
        await operator.login("operator")

        missing_csrf = await raw_operator.post(
            "/api/v1/users", json={"username": "alice"}
        )
        assert missing_csrf.status_code == 403
        assert missing_csrf.json()["status"] == 403

        created = await operator.request(
            "POST", "/api/v1/users", json={"username": "alice"}
        )
        assert created.status_code == 201
        assert created.json()["data"]["user"]["active"] is False
        assert created.json()["data"]["user"]["created_at"].endswith("Z")
        invitation = created.json()["data"]["invitation"]
        assert invitation["invitation_url"].startswith(
            "https://relay.example.test/invite#token="
        )
        assert invitation["token"] not in str(created.headers)

    async with (
        client_factory() as first_client,
        client_factory() as second_client,
    ):
        responses = await asyncio.gather(
            first_client.post(
                "/api/v1/auth/invitations/accept",
                json={
                    "token": invitation["token"],
                    "password": "alice has a sufficiently long password",
                },
            ),
            second_client.post(
                "/api/v1/auth/invitations/accept",
                json={
                    "token": invitation["token"],
                    "password": "another sufficiently long password",
                },
            ),
        )
        assert sorted(response.status_code for response in responses) == [
            200,
            400,
        ]
        accepted = next(
            response for response in responses if response.status_code == 200
        )
        assert accepted.json()["data"]["user"]["username"] == "alice"


@pytest.mark.asyncio
async def test_framework_errors_use_the_api_envelope(
    application: Any, client_factory: Callable[[], httpx.AsyncClient]
) -> None:
    async with client_factory() as client:
        missing = await client.get("/api/v1/does-not-exist")
        assert missing.status_code == 404
        assert missing.json() == {
            "status": 404,
            "message": "Not Found",
            "data": None,
        }


@pytest.mark.asyncio
async def test_concurrent_operator_disables_preserve_one_active_operator(
    application: Any, client_factory: Callable[[], httpx.AsyncClient]
) -> None:
    first_user = await add_user(application, "operator-a", operator=True)
    second_user = await add_user(application, "operator-b", operator=True)
    async with client_factory() as first_raw, client_factory() as second_raw:
        first = APIClient(first_raw)
        second = APIClient(second_raw)
        await first.login("operator-a")
        await second.login("operator-b")
        responses = await asyncio.gather(
            first.request(
                "PATCH",
                f"/api/v1/users/{second_user.id}",
                json={"active": False},
            ),
            second.request(
                "PATCH",
                f"/api/v1/users/{first_user.id}",
                json={"active": False},
            ),
        )
        assert 200 in {response.status_code for response in responses}
        assert any(
            response.status_code in {401, 403, 409} for response in responses
        )

    async with application.state.session_factory() as database:
        active_operators = await database.scalar(
            select(func.count())
            .select_from(User)
            .where(User.active.is_(True), User.is_operator.is_(True))
        )
        assert active_operators == 1


@pytest.mark.asyncio
async def test_disabled_invitee_cannot_reuse_invitation_and_login_is_limited(
    application: Any, client_factory: Callable[[], httpx.AsyncClient]
) -> None:
    await add_user(application, "operator", operator=True)
    async with client_factory() as raw_operator:
        operator = APIClient(raw_operator)
        await operator.login("operator")
        created = await operator.request(
            "POST", "/api/v1/users", json={"username": "pending"}
        )
        user_id = created.json()["data"]["user"]["id"]
        invitation = created.json()["data"]["invitation"]
        disabled = await operator.request(
            "PATCH", f"/api/v1/users/{user_id}", json={"active": False}
        )
        assert disabled.status_code == 200

    async with client_factory() as raw_pending:
        rejected = await raw_pending.post(
            "/api/v1/auth/invitations/accept",
            json={
                "token": invitation["token"],
                "password": "pending account password",
            },
        )
        assert rejected.status_code == 400

    async with client_factory() as raw_login:
        for _ in range(5):
            failed = await raw_login.post(
                "/api/v1/auth/login",
                json={"username": "operator", "password": "incorrect"},
            )
            assert failed.status_code == 401
        blocked = await raw_login.post(
            "/api/v1/auth/login",
            json={
                "username": "operator",
                "password": "correct horse battery staple",
            },
        )
        assert blocked.status_code == 429


@pytest.mark.asyncio
async def test_domain_roles_grants_credentials_and_smtp_config_are_isolated(
    application: Any,
    client_factory: Callable[[], httpx.AsyncClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def allow_public_host(
        _host: str, _port: int = 25, **_kwargs: Any
    ) -> None:
        return None

    monkeypatch.setattr(
        "smtp_relay_manager.api.validate_upstream_host", allow_public_host
    )
    await add_user(application, "operator", operator=True)
    owner_user = await add_user(application, "owner")
    await add_user(application, "manager")
    await add_user(application, "sender")
    await add_user(application, "outsider")

    async with (
        client_factory() as raw_operator,
        client_factory() as raw_owner,
        client_factory() as raw_manager,
        client_factory() as raw_sender,
        client_factory() as raw_outsider,
    ):
        operator = APIClient(raw_operator)
        owner = APIClient(raw_owner)
        manager = APIClient(raw_manager)
        sender = APIClient(raw_sender)
        outsider = APIClient(raw_outsider)
        await operator.login("operator")
        await owner.login("owner")
        await manager.login("manager")
        await sender.login("sender")
        await outsider.login("outsider")

        created = await owner.request(
            "POST", "/api/v1/domains", json={"name": "Example.COM."}
        )
        assert created.status_code == 201
        domain_id = created.json()["data"]["id"]
        assert created.json()["data"]["name"] == "example.com"

        approved = await operator.request(
            "POST", f"/api/v1/domains/{domain_id}/approve"
        )
        assert approved.status_code == 200

        add_admin = await owner.request(
            "PUT", f"/api/v1/domains/{domain_id}/admins/manager"
        )
        assert add_admin.status_code == 200
        address = await manager.request(
            "POST",
            f"/api/v1/domains/{domain_id}/addresses",
            json={"address": "Notice@EXAMPLE.COM"},
        )
        assert address.status_code == 201
        assert address.json()["data"]["address"] == "Notice@example.com"

        grant = await manager.request(
            "POST",
            f"/api/v1/domains/{domain_id}/grants",
            json={"username": "sender", "address": "Notice@example.com"},
        )
        assert grant.status_code == 201

        credential = await sender.request(
            "POST",
            "/api/v1/smtp-credentials",
            json={
                "name": "production app",
                "scopes": [
                    {"domain_id": domain_id, "address": "Notice@example.com"}
                ],
                "expires_at": (utc_now() + timedelta(days=7)).isoformat()
                + "Z",
            },
        )
        assert credential.status_code == 201
        assert (
            credential.json()["data"]["username"]
            == credential.json()["data"]["credential"]["id"]
        )
        assert credential.json()["data"]["token"]

        manager_smtp = await manager.request(
            "PUT",
            f"/api/v1/domains/{domain_id}/smtp",
            json={
                "host": "smtp.example.net",
                "port": 587,
                "security": "starttls",
                "auth_type": "password",
                "username": "relay-user",
                "password": "top-secret",
            },
        )
        assert manager_smtp.status_code == 403
        owner_smtp = await owner.request(
            "PUT",
            f"/api/v1/domains/{domain_id}/smtp",
            json={
                "host": "smtp.example.net",
                "port": 587,
                "security": "starttls",
                "auth_type": "password",
                "username": "relay-user",
                "password": "top-secret",
            },
        )
        assert owner_smtp.status_code == 200
        assert owner_smtp.json()["data"]["password_set"] is True
        assert "top-secret" not in owner_smtp.text

        manager_detail = await manager.request(
            "GET", f"/api/v1/domains/{domain_id}"
        )
        assert manager_detail.status_code == 200
        assert manager_detail.json()["data"]["smtp_config"] is None
        sender_detail = await sender.request(
            "GET", f"/api/v1/domains/{domain_id}"
        )
        assert sender_detail.status_code == 200
        assert sender_detail.json()["data"]["addresses"] == []
        assert sender_detail.json()["data"]["admins"] == []
        assert sender_detail.json()["data"]["smtp_config"] is None
        assert len(sender_detail.json()["data"]["grants"]) == 1

        hidden = await outsider.request("GET", f"/api/v1/domains/{domain_id}")
        assert hidden.status_code == 403

        transfer = await owner.request(
            "PUT",
            f"/api/v1/domains/{domain_id}/owner",
            json={"username": "manager"},
        )
        assert transfer.status_code == 200
        assert transfer.json()["data"]["owner_user_id"] != owner_user.id
        old_owner_smtp = await owner.request(
            "GET", f"/api/v1/domains/{domain_id}/smtp"
        )
        assert old_owner_smtp.status_code == 403


@pytest.mark.asyncio
async def test_log_visibility_matches_operator_owner_and_sender_rules(
    application: Any, client_factory: Callable[[], httpx.AsyncClient]
) -> None:
    await add_user(application, "operator", operator=True)
    owner = await add_user(application, "owner")
    sender = await add_user(application, "sender")
    other = await add_user(application, "other")
    domain = Domain(
        id=new_id(),
        name="example.com",
        active_name="example.com",
        owner_user_id=owner.id,
        status="approved",
    )
    owner_attempt = SendAttempt(
        id=new_id(),
        user_id=sender.id,
        credential_id=None,
        domain_id=domain.id,
        sender="notice@example.com",
        status="accepted",
        error_code=None,
        error_stage=None,
        error_message=None,
    )
    unrelated_attempt = SendAttempt(
        id=new_id(),
        user_id=other.id,
        credential_id=None,
        domain_id=None,
        sender="other@example.net",
        status="failed",
        error_code="550",
        error_stage="upstream",
        error_message="Rejected",
    )
    async with application.state.session_factory.begin() as database:
        database.add_all(
            [
                domain,
                owner_attempt,
                unrelated_attempt,
                SendRecipient(
                    id=new_id(),
                    attempt_id=owner_attempt.id,
                    address="a@example.net",
                ),
            ]
        )

    async with (
        client_factory() as raw_operator,
        client_factory() as raw_owner,
        client_factory() as raw_sender,
        client_factory() as raw_other,
    ):
        clients = {
            "operator": APIClient(raw_operator),
            "owner": APIClient(raw_owner),
            "sender": APIClient(raw_sender),
            "other": APIClient(raw_other),
        }
        for username, api_client in clients.items():
            await api_client.login(username)

        operator_logs = await clients["operator"].request(
            "GET", "/api/v1/logs"
        )
        owner_logs = await clients["owner"].request("GET", "/api/v1/logs")
        sender_logs = await clients["sender"].request("GET", "/api/v1/logs")
        other_logs = await clients["other"].request("GET", "/api/v1/logs")

        assert operator_logs.json()["data"]["total"] == 2
        assert owner_logs.json()["data"]["total"] == 1
        assert sender_logs.json()["data"]["total"] == 1
        assert sender_logs.json()["data"]["items"][0]["recipients"] == [
            "a@example.net"
        ]
        assert other_logs.json()["data"]["total"] == 1


@pytest.mark.asyncio
async def test_maintenance_expires_security_state_and_stale_attempts(
    application: Any,
) -> None:
    user = await add_user(application, "maintenance-user")
    now = utc_now()
    stale_attempt = SendAttempt(
        id=new_id(),
        user_id=user.id,
        credential_id=None,
        domain_id=None,
        sender="sender@example.com",
        status="pending",
        error_code=None,
        error_stage=None,
        error_message=None,
        created_at=now - timedelta(hours=1),
        updated_at=now - timedelta(hours=1),
    )
    expired_session = WebSession(
        id=new_id(),
        user_id=user.id,
        token_hash=hash_secret("expired-session"),
        csrf_token="expired-csrf",
        expires_at=now - timedelta(seconds=1),
    )
    expired_invitation = Invitation(
        id=new_id(),
        user_id=user.id,
        token_hash=hash_secret("expired-invitation"),
        expires_at=now - timedelta(seconds=1),
        used_at=None,
    )
    expired_rate = RateLimit(
        key=hash_secret("expired-rate"),
        attempts=3,
        expires_at=now - timedelta(seconds=1),
    )
    async with application.state.session_factory.begin() as database:
        database.add_all(
            [stale_attempt, expired_session, expired_invitation, expired_rate]
        )

    await run_maintenance_once(
        application.state.session_factory, retention_days=30
    )

    async with application.state.session_factory() as database:
        refreshed_attempt = await database.get(SendAttempt, stale_attempt.id)
        assert refreshed_attempt is not None
        assert refreshed_attempt.status == "unknown"
        assert await database.get(WebSession, expired_session.id) is None
        assert await database.get(Invitation, expired_invitation.id) is None
        assert (
            await database.scalar(
                select(RateLimit).where(RateLimit.key == expired_rate.key)
            )
            is None
        )
