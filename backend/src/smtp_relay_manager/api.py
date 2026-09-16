"""HTTP management API for SMTP Relay Manager."""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Generic, Literal, TypeVar
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, Depends, FastAPI, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    field_validator,
    model_validator,
)
from sqlalchemy import and_, delete, func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from .errors import AppError
from .models import (
    CredentialScope,
    Domain,
    DomainAdmin,
    Invitation,
    SenderAddress,
    SenderGrant,
    SendAttempt,
    SendRecipient,
    SMTPConfig,
    SMTPCredential,
    User,
    WebSession,
    new_id,
    utc_now,
)
from .policy import (
    get_domain_role,
    normalize_address,
    normalize_domain,
    require_domain_role,
    validate_scope,
)
from .security import (
    consume_rate_limit,
    encrypt_password,
    generate_secret,
    hash_password,
    hash_secret,
    release_rate_limit,
)
from .upstream import UnsafeUpstreamHost, normalize_upstream_host, validate_upstream_host

T = TypeVar("T")
UTCDateTime = Annotated[
    datetime,
    PlainSerializer(
        lambda value: value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        if value.tzinfo is None
        else value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        return_type=str,
        when_used="json",
    ),
]
DomainRole = Literal["owner", "admin"]
DomainStatus = Literal["pending", "approved", "rejected"]
SMTPTransportSecurity = Literal["none", "starttls", "tls"]
SMTPAuth = Literal["none", "password"]

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
LOGGER = logging.getLogger(__name__)

COMMON_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status: {
        "description": description,
        "content": {
            "application/json": {
                "example": {"status": status, "message": description, "data": None}
            }
        },
    }
    for status, description in {
        400: "Invalid request",
        401: "Authentication required",
        403: "Permission denied",
        404: "Resource not found",
        409: "Resource conflict",
        422: "Request validation failed",
        429: "Too many requests",
        500: "Internal server error",
        503: "Service unavailable",
    }.items()
}


class APIEnvelope(BaseModel, Generic[T]):
    """Stable response envelope used by every API endpoint."""

    status: int
    message: str
    data: T | None


class UserDTO(BaseModel):
    id: str
    username: str
    active: bool
    is_operator: bool
    created_at: UTCDateTime


class InvitationDTO(BaseModel):
    id: str
    expires_at: UTCDateTime
    used_at: UTCDateTime | None
    invitation_url: str | None = None
    token: str | None = None


class UserListItemDTO(UserDTO):
    invitation: InvitationDTO | None


class AuthDTO(BaseModel):
    user: UserDTO
    csrf_token: str


class DomainDTO(BaseModel):
    id: str
    name: str
    status: DomainStatus
    owner_user_id: str
    owner_username: str
    created_at: UTCDateTime


class AddressDTO(BaseModel):
    id: str
    domain_id: str
    address: str


class AdminDTO(BaseModel):
    id: str
    username: str
    active: bool


class GrantDTO(BaseModel):
    id: str
    domain_id: str
    user_id: str
    username: str
    address: str


class SMTPConfigDTO(BaseModel):
    domain_id: str
    host: str
    port: int
    security: SMTPTransportSecurity
    auth_type: SMTPAuth
    username: str | None
    password_set: bool


class DomainDetailDTO(BaseModel):
    domain: DomainDTO
    role: DomainRole | None
    smtp_config: SMTPConfigDTO | None
    addresses: list[AddressDTO]
    admins: list[AdminDTO]
    grants: list[GrantDTO]


class ScopeDTO(BaseModel):
    domain_id: str
    address: str


class CredentialDTO(BaseModel):
    id: str
    user_id: str
    name: str
    scopes: list[ScopeDTO]
    expires_at: UTCDateTime | None
    revoked_at: UTCDateTime | None
    created_at: UTCDateTime


class CreatedCredentialDTO(BaseModel):
    credential: CredentialDTO
    username: str
    token: str


class LogDTO(BaseModel):
    id: str
    user_id: str | None
    credential_id: str | None
    domain_id: str | None
    sender: str
    recipients: list[str]
    status: Literal["pending", "accepted", "failed", "unknown"]
    error_code: str | None
    error_stage: str | None
    error_message: str | None
    created_at: UTCDateTime
    updated_at: UTCDateTime


class PageDTO(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class AcceptInvitationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=32, max_length=128)
    password: str = Field(min_length=12, max_length=1024)


class CreateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        """Normalize and validate a local username."""
        value = value.strip().lower()
        if not USERNAME_PATTERN.fullmatch(value):
            raise ValueError("Username may contain letters, numbers, dots, dashes, and underscores")
        return value


class UpdateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active: bool | None = None
    is_operator: bool | None = None

    @model_validator(mode="after")
    def require_update(self) -> UpdateUserRequest:
        """Reject empty user update documents."""
        if self.active is None and self.is_operator is None:
            raise ValueError("At least one user field must be updated")
        return self


class CreateDomainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=253)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        """Normalize a submitted DNS domain."""
        return normalize_domain(value)


class TransferOwnerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64)


class CreateAddressRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    address: str = Field(min_length=3, max_length=320)


class CreateGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64)
    address: str = Field(min_length=1, max_length=320)


class SMTPConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    security: SMTPTransportSecurity
    auth_type: SMTPAuth
    username: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, max_length=4096)

    @field_validator("host")
    @classmethod
    def normalize_host(cls, value: str) -> str:
        """Normalize an upstream hostname without resolving it."""
        try:
            return normalize_upstream_host(value)
        except UnsafeUpstreamHost as exc:
            raise ValueError("Invalid SMTP host") from exc

    @model_validator(mode="after")
    def validate_auth(self) -> SMTPConfigRequest:
        """Enforce safe transport and authentication combinations."""
        if self.auth_type == "password" and self.security == "none":
            raise ValueError("Password authentication requires STARTTLS or TLS")
        if self.auth_type == "password" and not self.username:
            raise ValueError("Username is required for password authentication")
        if self.username and any(character in self.username for character in "\r\n\x00"):
            raise ValueError("Username contains control characters")
        return self


class ScopeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain_id: str
    address: str = Field(min_length=1, max_length=320)


class CreateCredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    scopes: list[ScopeRequest] = Field(min_length=1, max_length=100)
    expires_at: datetime | None = None

    @field_validator("name")
    @classmethod
    def strip_name(cls, value: str) -> str:
        """Normalize a human-readable credential name."""
        if not (value := value.strip()):
            raise ValueError("Credential name is required")
        return value

    @field_validator("expires_at")
    @classmethod
    def future_expiry(cls, value: datetime | None) -> datetime | None:
        """Normalize an optional expiration to naive UTC."""
        if value is not None:
            if value.tzinfo is not None:
                value = value.astimezone(timezone.utc).replace(tzinfo=None)
            if value <= utc_now():
                raise ValueError("Expiration must be in the future")
        return value


class UpdateScopesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scopes: list[ScopeRequest] = Field(min_length=1, max_length=100)


@dataclass(frozen=True, slots=True)
class Principal:
    user: User
    session_id: str
    csrf_token: str


def domain_address(value: str, domain: Domain) -> str:
    """Validate that a normalized sender address belongs to a domain."""
    address = normalize_address(value)
    if address.rsplit("@", 1)[1] != domain.name:
        raise AppError(422, "Address must belong to the domain")
    return address


def envelope(status: int, message: str, data: Any = None) -> dict[str, Any]:
    """Build the standard JSON response shape."""
    return {"status": status, "message": message, "data": data}


def validate_origin(request: Request) -> None:
    """Reject browser requests sent from a different web origin."""
    supplied = request.headers.get("Origin")
    if supplied is None:
        return
    public_url = urlsplit(request.app.state.settings.public_base_url)
    expected = f"{public_url.scheme}://{public_url.netloc}"
    if supplied.rstrip("/") != expected:
        raise AppError(403, "Request origin is not allowed")


def client_address(request: Request) -> str:
    """Resolve a client address through only explicitly trusted proxy hops."""
    peer = request.client.host if request.client else "unknown"
    try:
        peer_address = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    configured = request.app.state.settings.trusted_proxy_cidrs
    trusted_networks = []
    try:
        trusted_networks = [
            ipaddress.ip_network(item.strip())
            for item in configured.split(",")
            if item.strip()
        ]
    except ValueError:
        LOGGER.error("TRUSTED_PROXY_CIDRS contains an invalid network")
        return peer
    if not any(peer_address in network for network in trusted_networks):
        return peer
    forwarded = request.headers.get("X-Forwarded-For")
    if not forwarded:
        return peer
    chain = [item.strip() for item in forwarded.split(",") if item.strip()]
    chain.append(peer)
    while len(chain) > 1:
        try:
            candidate = ipaddress.ip_address(chain[-1])
        except ValueError:
            return peer
        if not any(candidate in network for network in trusted_networks):
            break
        chain.pop()
    try:
        return str(ipaddress.ip_address(chain[-1]))
    except ValueError:
        return peer


def user_dto(user: User) -> UserDTO:
    """Convert a persistent user to its public representation."""
    return UserDTO(
        id=user.id,
        username=user.username,
        active=user.active,
        is_operator=user.is_operator,
        created_at=user.created_at,
    )


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield one request-scoped database session."""
    async with request.app.state.session_factory() as database:
        yield database


Database = Annotated[AsyncSession, Depends(get_db)]


async def current_principal(
    request: Request,
    database: Database,
) -> Principal:
    """Authenticate the session cookie and return its current identity."""
    session_token = request.cookies.get(request.app.state.settings.session_cookie_name)
    if not session_token:
        raise AppError(401, "Authentication required")
    now = utc_now()
    web_session = await database.scalar(
        select(WebSession).where(
            WebSession.token_hash == hash_secret(session_token),
            WebSession.expires_at > now,
        )
    )
    if web_session is None:
        raise AppError(401, "Invalid or expired session")
    user = await database.get(User, web_session.user_id)
    if user is None or not user.active:
        raise AppError(401, "Account is disabled")
    return Principal(
        user=user,
        session_id=web_session.id,
        csrf_token=web_session.csrf_token,
    )


PrincipalDependency = Annotated[Principal, Depends(current_principal)]


async def csrf_principal(request: Request, principal: PrincipalDependency) -> Principal:
    """Verify origin and CSRF state for an authenticated write."""
    validate_origin(request)
    supplied = request.headers.get("X-CSRF-Token")
    if not supplied or supplied != principal.csrf_token:
        raise AppError(403, "Invalid CSRF token")
    return principal


CSRFPrincipal = Annotated[Principal, Depends(csrf_principal)]


def require_operator(principal: Principal) -> None:
    """Require an active service operator."""
    if not principal.user.active or not principal.user.is_operator:
        raise AppError(403, "Operator permission required")


async def get_domain(database: AsyncSession, domain_id: str, *, include_deleted: bool = False) -> Domain:
    """Load a domain or raise a safe not-found error."""
    domain = await database.get(Domain, domain_id)
    if domain is None or (not include_deleted and domain.deleted_at is not None):
        raise AppError(404, "Domain not found")
    return domain


async def find_active_user(database: AsyncSession, username: str) -> User:
    """Lock and return an activated user by normalized username."""
    user = await database.scalar(
        select(User)
        .where(User.username == username.strip().lower())
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if user is None:
        raise AppError(404, "User not found")
    if not user.active or user.password_hash is None:
        raise AppError(409, "User has not activated an account")
    return user


async def domain_dto(database: AsyncSession, domain: Domain) -> DomainDTO:
    """Build a domain representation with its owner's username."""
    owner = await database.get(User, domain.owner_user_id)
    return DomainDTO(
        id=domain.id,
        name=domain.name,
        status=domain.status,
        owner_user_id=domain.owner_user_id,
        owner_username=owner.username if owner else "deleted-user",
        created_at=domain.created_at,
    )


def smtp_dto(config: SMTPConfig) -> SMTPConfigDTO:
    """Redact an upstream configuration for API output."""
    return SMTPConfigDTO(
        domain_id=config.domain_id,
        host=config.host,
        port=config.port,
        security=config.security,
        auth_type=config.auth,
        username=config.username,
        password_set=config.password_encrypted is not None,
    )


async def credential_dto(database: AsyncSession, credential: SMTPCredential) -> CredentialDTO:
    """Build a credential representation including its current scopes."""
    scopes = (
        await database.scalars(
            select(CredentialScope)
            .where(CredentialScope.credential_id == credential.id)
            .order_by(CredentialScope.domain_id, CredentialScope.address)
        )
    ).all()
    return CredentialDTO(
        id=credential.id,
        user_id=credential.user_id,
        name=credential.name,
        scopes=[ScopeDTO(domain_id=item.domain_id, address=item.address) for item in scopes],
        expires_at=credential.expires_at,
        revoked_at=credential.revoked_at,
        created_at=credential.created_at,
    )


def configure_api(app: FastAPI) -> None:
    """Install API exception handlers and versioned routes."""

    @app.exception_handler(AppError)
    async def handle_app_error(_request: Request, exc: AppError) -> JSONResponse:
        """Render an expected application error with the API envelope."""
        return JSONResponse(
            content=envelope(exc.status_code, exc.message), status_code=exc.status_code
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        """Render sanitized request validation details."""
        details = [
            {"loc": item["loc"], "msg": item["msg"], "type": item["type"]}
            for item in exc.errors()
        ]
        return JSONResponse(
            content=envelope(422, "Request validation failed", details), status_code=422
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(
        _request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        """Render framework routing and method errors consistently."""
        message = exc.detail if isinstance(exc.detail, str) else "HTTP request failed"
        return JSONResponse(
            content=envelope(exc.status_code, message),
            status_code=exc.status_code,
            headers=exc.headers,
        )

    @app.exception_handler(IntegrityError)
    async def handle_integrity_error(request: Request, _exc: IntegrityError) -> JSONResponse:
        """Map database uniqueness races to a safe conflict response."""
        LOGGER.info("Database constraint rejected an API write at %s", request.url.path)
        return JSONResponse(
            content=envelope(409, "Resource conflicts with existing data"),
            status_code=409,
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        """Hide internal failures and avoid logging request secrets."""
        LOGGER.error(
            "Unexpected management API failure type=%s path=%s",
            type(exc).__name__,
            request.url.path,
        )
        return JSONResponse(
            content=envelope(500, "Internal server error"), status_code=500
        )

    tag_names = {
        "health": "health",
        "auth": "authentication",
        "users": "users",
        "invitations": "users",
        "domains": "domains",
        "smtp-credentials": "SMTP credentials",
        "logs": "send logs",
    }
    for route in router.routes:
        if isinstance(route, APIRoute):
            resource = route.path.lstrip("/").split("/", 1)[0]
            route.tags = [tag_names.get(resource, resource)]
            route.responses.update(COMMON_ERROR_RESPONSES)

    app.include_router(router, prefix="/api/v1")


router = APIRouter()


@router.get("/health", response_model=APIEnvelope[dict[str, str]])
async def health(database: Database) -> dict[str, Any]:
    """Return readiness after a live database query."""
    try:
        await database.execute(text("SELECT 1"))
    except Exception as exc:
        raise AppError(503, "Database is unavailable") from exc
    return envelope(200, "Service is ready", {"status": "ready"})


@router.post("/auth/login", response_model=APIEnvelope[AuthDTO])
async def login(payload: LoginRequest, request: Request, response: Response, database: Database) -> dict[str, Any]:
    """Authenticate a management user and issue a server-side session."""
    validate_origin(request)
    username = payload.username.strip().lower()
    client_ip = client_address(request)
    rate_started_at = utc_now()
    rate_keys = [f"login-ip:{client_ip}", f"login-pair:{client_ip}:{username}"]
    allowed = await consume_rate_limit(
        request.app.state.session_factory,
        rate_keys,
        [20, 5],
        started_at=rate_started_at,
        window_seconds=900,
    )
    if not allowed:
        raise AppError(429, "Too many login attempts")
    user = await request.app.state.identity_provider.authenticate(
        database, username, payload.password
    )
    if user is None:
        raise AppError(401, "Invalid username or password")
    await release_rate_limit(
        request.app.state.session_factory,
        rate_keys,
        rate_started_at,
        window_seconds=900,
    )
    session_token = generate_secret()
    csrf_token = generate_secret()
    settings = request.app.state.settings
    max_age = settings.session_hours * 3600
    web_session = WebSession(
        id=new_id(),
        user_id=user.id,
        token_hash=hash_secret(session_token),
        csrf_token=csrf_token,
        expires_at=utc_now() + timedelta(seconds=max_age),
    )
    database.add(web_session)
    await database.commit()
    response.set_cookie(
        settings.session_cookie_name,
        session_token,
        max_age=max_age,
        secure=True,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return envelope(200, "Login successful", AuthDTO(user=user_dto(user), csrf_token=csrf_token))


@router.get("/auth/me", response_model=APIEnvelope[AuthDTO])
async def me(principal: PrincipalDependency) -> dict[str, Any]:
    """Return the authenticated management identity and CSRF token."""
    return envelope(200, "Current user", AuthDTO(user=user_dto(principal.user), csrf_token=principal.csrf_token))


@router.post("/auth/logout", response_model=APIEnvelope[None])
async def logout(
    request: Request, principal: CSRFPrincipal, response: Response, database: Database
) -> dict[str, Any]:
    """Destroy the current server-side session."""
    validate_origin(request)
    await database.execute(delete(WebSession).where(WebSession.id == principal.session_id))
    await database.commit()
    response.delete_cookie(request.app.state.settings.session_cookie_name, path="/")
    return envelope(200, "Logout successful")


@router.post("/auth/invitations/accept", response_model=APIEnvelope[AuthDTO])
async def accept_invitation(
    payload: AcceptInvitationRequest,
    request: Request,
    response: Response,
    database: Database,
) -> dict[str, Any]:
    """Activate an invited user and issue its first web session."""
    validate_origin(request)
    token_hash = hash_secret(payload.token)
    invitation = await database.scalar(
        select(Invitation).where(Invitation.token_hash == token_hash)
    )
    if invitation is None:
        raise AppError(400, "Invalid or expired invitation")
    user = await database.scalar(
        select(User)
        .where(User.id == invitation.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    invitation = await database.scalar(
        select(Invitation)
        .where(Invitation.id == invitation.id, Invitation.token_hash == token_hash)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if invitation is None or invitation.used_at is not None or invitation.expires_at <= utc_now():
        raise AppError(400, "Invalid or expired invitation")
    if user is None or user.password_hash is not None:
        raise AppError(400, "Invitation cannot be accepted")
    user.password_hash = await hash_password(payload.password)
    user.active = True
    invitation.used_at = utc_now()
    session_token = generate_secret()
    csrf_token = generate_secret()
    max_age = request.app.state.settings.session_hours * 3600
    database.add(
        WebSession(
            id=new_id(),
            user_id=user.id,
            token_hash=hash_secret(session_token),
            csrf_token=csrf_token,
            expires_at=utc_now() + timedelta(seconds=max_age),
        )
    )
    await database.commit()
    response.set_cookie(
        request.app.state.settings.session_cookie_name,
        session_token,
        max_age=max_age,
        secure=True,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return envelope(200, "Invitation accepted", AuthDTO(user=user_dto(user), csrf_token=csrf_token))


@router.get("/users", response_model=APIEnvelope[PageDTO[UserListItemDTO]])
async def list_users(
    principal: PrincipalDependency,
    database: Database,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    """List users and their latest invitation for an operator."""
    require_operator(principal)
    total = await database.scalar(select(func.count()).select_from(User)) or 0
    users = (await database.scalars(select(User).order_by(User.username).limit(limit).offset(offset))).all()
    items: list[UserListItemDTO] = []
    for user in users:
        invitation = await database.scalar(
            select(Invitation).where(Invitation.user_id == user.id).order_by(Invitation.created_at.desc()).limit(1)
        )
        invitation_data = None
        if invitation is not None:
            invitation_data = InvitationDTO(
                id=invitation.id,
                expires_at=invitation.expires_at,
                used_at=invitation.used_at,
            )
        items.append(UserListItemDTO(**user_dto(user).model_dump(), invitation=invitation_data))
    return envelope(200, "Users", PageDTO(items=items, total=total, limit=limit, offset=offset))


@router.post("/users", response_model=APIEnvelope[dict[str, Any]], status_code=201)
async def create_user(
    payload: CreateUserRequest,
    request: Request,
    principal: CSRFPrincipal,
    database: Database,
) -> dict[str, Any]:
    """Create a pending user and return a one-time invitation secret."""
    require_operator(principal)
    if await database.scalar(select(User.id).where(User.username == payload.username)):
        raise AppError(409, "Username already exists")
    user = User(id=new_id(), username=payload.username, password_hash=None, active=False, is_operator=False)
    raw_token = generate_secret()
    invitation = Invitation(
        id=new_id(),
        user_id=user.id,
        token_hash=hash_secret(raw_token),
        expires_at=utc_now() + timedelta(hours=request.app.state.settings.invitation_hours),
    )
    database.add(user)
    await database.flush()
    database.add(invitation)
    await database.commit()
    public_url = request.app.state.settings.public_base_url.rstrip("/")
    invitation_url = f"{public_url}/invite#token={quote(raw_token, safe='')}"
    invitation_data = InvitationDTO(
        id=invitation.id,
        expires_at=invitation.expires_at,
        used_at=None,
        invitation_url=invitation_url,
        token=raw_token,
    )
    return envelope(201, "User created", {"user": user_dto(user), "invitation": invitation_data})


@router.patch("/users/{user_id}", response_model=APIEnvelope[UserDTO])
async def update_user(
    user_id: str,
    payload: UpdateUserRequest,
    principal: CSRFPrincipal,
    database: Database,
) -> dict[str, Any]:
    """Change account activation or operator status with invariant locks."""
    require_operator(principal)
    locked_operators = list(
        (
            await database.scalars(
                select(User)
                .where(User.is_operator.is_(True))
                .order_by(User.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).all()
    )
    acting_user = await database.scalar(
        select(User)
        .where(User.id == principal.user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if acting_user is None:
        raise AppError(401, "Authentication required")
    require_operator(principal)
    user = await database.scalar(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if user is None:
        raise AppError(404, "User not found")
    disabling = payload.active is False and user.active
    removing_operator = payload.is_operator is False and user.is_operator
    if disabling or removing_operator:
        if user.is_operator:
            active_operator_count = sum(item.active for item in locked_operators)
            if active_operator_count <= 1:
                raise AppError(409, "The last active operator cannot be removed or disabled")
    if disabling:
        owned_domain = await database.scalar(
            select(Domain)
            .where(Domain.owner_user_id == user.id, Domain.deleted_at.is_(None))
            .order_by(Domain.id)
            .with_for_update()
            .execution_options(populate_existing=True)
            .limit(1)
        )
        if owned_domain:
            raise AppError(409, "Transfer owned domains before disabling the user")
    if payload.active is not None:
        user.active = payload.active
    if payload.is_operator is not None:
        user.is_operator = payload.is_operator
    if payload.active is False:
        await database.execute(delete(WebSession).where(WebSession.user_id == user.id))
        await database.execute(
            delete(Invitation).where(
                Invitation.user_id == user.id, Invitation.used_at.is_(None)
            )
        )
    await database.commit()
    return envelope(200, "User updated", user_dto(user))


async def issue_replacement_invitation(
    invitation_id: str,
    request: Request,
    principal: Principal,
    database: AsyncSession,
) -> dict[str, Any]:
    """Replace an unaccepted invitation and return its secret once."""
    require_operator(principal)
    old = await database.get(Invitation, invitation_id)
    if old is None:
        raise AppError(404, "Invitation not found")
    user = await database.scalar(
        select(User)
        .where(User.id == old.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    old = await database.scalar(
        select(Invitation)
        .where(Invitation.id == invitation_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if old is None:
        raise AppError(404, "Invitation not found")
    if user is None or user.password_hash is not None:
        raise AppError(409, "User no longer requires an invitation")
    await database.execute(delete(Invitation).where(Invitation.user_id == user.id))
    token = generate_secret()
    invitation = Invitation(
        id=new_id(),
        user_id=user.id,
        token_hash=hash_secret(token),
        expires_at=utc_now() + timedelta(hours=request.app.state.settings.invitation_hours),
    )
    database.add(invitation)
    await database.commit()
    public_url = request.app.state.settings.public_base_url.rstrip("/")
    data = InvitationDTO(
        id=invitation.id,
        expires_at=invitation.expires_at,
        used_at=None,
        invitation_url=f"{public_url}/invite#token={quote(token, safe='')}",
        token=token,
    )
    return envelope(200, "Invitation reissued", data)


@router.post("/invitations/{invitation_id}/reissue", response_model=APIEnvelope[InvitationDTO])
async def reissue_invitation(
    invitation_id: str, request: Request, principal: CSRFPrincipal, database: Database
) -> dict[str, Any]:
    """Reissue an invitation for a pending user."""
    return await issue_replacement_invitation(invitation_id, request, principal, database)


@router.delete("/invitations/{invitation_id}", response_model=APIEnvelope[None])
async def revoke_invitation(invitation_id: str, principal: CSRFPrincipal, database: Database) -> dict[str, Any]:
    """Expire an outstanding invitation."""
    require_operator(principal)
    invitation = await database.scalar(
        select(Invitation).where(Invitation.id == invitation_id).with_for_update()
    )
    if invitation is None:
        raise AppError(404, "Invitation not found")
    if invitation.used_at is not None:
        raise AppError(409, "Accepted invitations cannot be revoked")
    invitation.expires_at = utc_now()
    await database.commit()
    return envelope(200, "Invitation revoked")


@router.get("/domains", response_model=APIEnvelope[list[DomainDTO]])
async def list_domains(principal: PrincipalDependency, database: Database) -> dict[str, Any]:
    """List domains visible through management or sender rights."""
    query = select(Domain).where(Domain.deleted_at.is_(None))
    if not principal.user.is_operator:
        related_ids = (
            select(Domain.id)
            .outerjoin(DomainAdmin, DomainAdmin.domain_id == Domain.id)
            .outerjoin(SenderGrant, SenderGrant.domain_id == Domain.id)
            .where(
                or_(
                    Domain.owner_user_id == principal.user.id,
                    DomainAdmin.user_id == principal.user.id,
                    SenderGrant.user_id == principal.user.id,
                )
            )
        )
        query = query.where(Domain.id.in_(related_ids))
    domains = (await database.scalars(query.order_by(Domain.name))).unique().all()
    return envelope(200, "Domains", [await domain_dto(database, domain) for domain in domains])


@router.post("/domains", response_model=APIEnvelope[DomainDTO], status_code=201)
async def create_domain(
    payload: CreateDomainRequest, principal: CSRFPrincipal, database: Database
) -> dict[str, Any]:
    """Submit a normalized domain registration for operator approval."""
    existing = await database.scalar(select(Domain.id).where(Domain.active_name == payload.name))
    if existing:
        raise AppError(409, "Domain is already registered")
    domain = Domain(
        id=new_id(),
        name=payload.name,
        active_name=payload.name,
        owner_user_id=principal.user.id,
        status="pending",
    )
    database.add(domain)
    await database.commit()
    return envelope(201, "Domain registration requested", await domain_dto(database, domain))


async def ensure_domain_visible(database: AsyncSession, principal: Principal, domain: Domain) -> DomainRole | None:
    """Return a management role or verify a sender grant exists."""
    role = await get_domain_role(database, principal.user, domain)
    if principal.user.is_operator or role is not None:
        return role
    grant = await database.scalar(
        select(SenderGrant.id)
        .where(
            SenderGrant.domain_id == domain.id,
            SenderGrant.user_id == principal.user.id,
        )
        .limit(1)
    )
    if grant is None:
        raise AppError(403, "Domain access denied")
    return None


@router.get("/domains/{domain_id}", response_model=APIEnvelope[DomainDetailDTO])
async def domain_detail(domain_id: str, principal: PrincipalDependency, database: Database) -> dict[str, Any]:
    """Return domain details filtered to the caller's role."""
    domain = await get_domain(database, domain_id)
    role = await ensure_domain_visible(database, principal, domain)
    has_management_access = role is not None
    addresses: list[SenderAddress] = []
    admin_rows: list[User] = []
    config = None
    if has_management_access:
        addresses = list(
            (
                await database.scalars(
                    select(SenderAddress)
                    .where(SenderAddress.domain_id == domain.id)
                    .order_by(SenderAddress.address)
                )
            ).all()
        )
        admin_rows = list(
            (
                await database.scalars(
                    select(User)
                    .join(DomainAdmin, DomainAdmin.user_id == User.id)
                    .where(DomainAdmin.domain_id == domain.id)
                )
            ).all()
        )
        if role == "owner":
            config = await database.get(SMTPConfig, domain.id)
    grant_query = (
        select(SenderGrant, User)
        .join(User, User.id == SenderGrant.user_id)
        .where(SenderGrant.domain_id == domain.id)
        .order_by(User.username, SenderGrant.address)
    )
    if not has_management_access:
        grant_query = grant_query.where(SenderGrant.user_id == principal.user.id)
    grant_rows = (await database.execute(grant_query)).all()
    data = DomainDetailDTO(
        domain=await domain_dto(database, domain),
        role=role,
        smtp_config=smtp_dto(config) if config else None,
        addresses=[AddressDTO(id=item.id, domain_id=item.domain_id, address=item.address) for item in addresses],
        admins=[AdminDTO(id=user.id, username=user.username, active=user.active) for user in admin_rows],
        grants=[
            GrantDTO(
                id=grant.id,
                domain_id=grant.domain_id,
                user_id=user.id,
                username=user.username,
                address=grant.address,
            )
            for grant, user in grant_rows
        ],
    )
    return envelope(200, "Domain", data)


async def set_domain_status(
    domain_id: str, status: DomainStatus, principal: Principal, database: AsyncSession
) -> dict[str, Any]:
    """Set a live domain's operator-controlled approval status."""
    require_operator(principal)
    domain = await get_domain(database, domain_id)
    if status == "approved" and domain.status == "approved":
        raise AppError(409, "Domain is already approved")
    domain.status = status
    await database.commit()
    return envelope(200, f"Domain {status}", await domain_dto(database, domain))


@router.post("/domains/{domain_id}/approve", response_model=APIEnvelope[DomainDTO])
async def approve_domain(domain_id: str, principal: CSRFPrincipal, database: Database) -> dict[str, Any]:
    """Approve a domain registration as an operator."""
    return await set_domain_status(domain_id, "approved", principal, database)


@router.post("/domains/{domain_id}/reject", response_model=APIEnvelope[DomainDTO])
async def reject_domain(domain_id: str, principal: CSRFPrincipal, database: Database) -> dict[str, Any]:
    """Reject or suspend a domain registration as an operator."""
    return await set_domain_status(domain_id, "rejected", principal, database)


@router.put("/domains/{domain_id}/owner", response_model=APIEnvelope[DomainDTO])
async def transfer_owner(
    domain_id: str,
    payload: TransferOwnerRequest,
    principal: CSRFPrincipal,
    database: Database,
) -> dict[str, Any]:
    """Transfer domain ownership using locked current user state."""
    domain = await get_domain(database, domain_id)
    await require_domain_role(database, principal.user, domain, ("owner",))
    new_owner = await find_active_user(database, payload.username)
    domain = await database.scalar(
        select(Domain)
        .where(Domain.id == domain_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if domain is None or domain.deleted_at is not None:
        raise AppError(404, "Domain not found")
    await require_domain_role(database, principal.user, domain, ("owner",))
    if new_owner.id == domain.owner_user_id:
        raise AppError(409, "User already owns the domain")
    domain.owner_user_id = new_owner.id
    await database.execute(
        delete(DomainAdmin).where(DomainAdmin.domain_id == domain.id, DomainAdmin.user_id == new_owner.id)
    )
    await database.commit()
    return envelope(200, "Domain ownership transferred", await domain_dto(database, domain))


@router.put("/domains/{domain_id}/admins/{username}", response_model=APIEnvelope[AdminDTO])
async def add_admin(domain_id: str, username: str, principal: CSRFPrincipal, database: Database) -> dict[str, Any]:
    """Grant domain administration to an activated user."""
    domain = await get_domain(database, domain_id)
    await require_domain_role(database, principal.user, domain, ("owner",))
    user = await find_active_user(database, username)
    if user.id == domain.owner_user_id:
        raise AppError(409, "Domain owner already has full access")
    existing = await database.get(DomainAdmin, (domain.id, user.id))
    if existing is not None:
        raise AppError(409, "User is already a domain administrator")
    database.add(DomainAdmin(domain_id=domain.id, user_id=user.id))
    await database.commit()
    return envelope(
        200,
        "Domain administrator added",
        AdminDTO(id=user.id, username=user.username, active=user.active),
    )


@router.delete("/domains/{domain_id}/admins/{username}", response_model=APIEnvelope[None])
async def remove_admin(domain_id: str, username: str, principal: CSRFPrincipal, database: Database) -> dict[str, Any]:
    """Remove a user's domain administration role."""
    domain = await get_domain(database, domain_id)
    await require_domain_role(database, principal.user, domain, ("owner",))
    user = await database.scalar(select(User).where(User.username == username.strip().lower()))
    if user is None:
        raise AppError(404, "User not found")
    result = await database.execute(
        delete(DomainAdmin).where(DomainAdmin.domain_id == domain.id, DomainAdmin.user_id == user.id)
    )
    if result.rowcount == 0:
        raise AppError(404, "Domain administrator not found")
    await database.commit()
    return envelope(200, "Domain administrator removed")


@router.delete("/domains/{domain_id}", response_model=APIEnvelope[DomainDTO])
async def delete_domain(domain_id: str, principal: CSRFPrincipal, database: Database) -> dict[str, Any]:
    """Soft-delete an owned domain without reusing its identity."""
    domain = await get_domain(database, domain_id)
    await require_domain_role(database, principal.user, domain, ("owner",))
    result = await domain_dto(database, domain)
    domain.active_name = None
    domain.deleted_at = utc_now()
    await database.commit()
    return envelope(200, "Domain deleted", result)


@router.get("/domains/{domain_id}/addresses", response_model=APIEnvelope[list[AddressDTO]])
async def list_addresses(domain_id: str, principal: PrincipalDependency, database: Database) -> dict[str, Any]:
    """List registered addresses for a managed domain."""
    domain = await get_domain(database, domain_id)
    await require_domain_role(database, principal.user, domain, ("owner", "admin"))
    rows = (
        await database.scalars(
            select(SenderAddress)
            .where(SenderAddress.domain_id == domain.id)
            .order_by(SenderAddress.address)
        )
    ).all()
    return envelope(
        200,
        "Sender addresses",
        [
            AddressDTO(id=row.id, domain_id=row.domain_id, address=row.address)
            for row in rows
        ],
    )


@router.post("/domains/{domain_id}/addresses", response_model=APIEnvelope[AddressDTO], status_code=201)
async def create_address(
    domain_id: str, payload: CreateAddressRequest, principal: CSRFPrincipal, database: Database
) -> dict[str, Any]:
    """Register an exact sender address in a managed domain."""
    domain = await get_domain(database, domain_id)
    await require_domain_role(database, principal.user, domain, ("owner", "admin"))
    address = domain_address(payload.address, domain)
    existing = await database.scalar(
        select(SenderAddress.id).where(SenderAddress.domain_id == domain.id, SenderAddress.address == address)
    )
    if existing:
        raise AppError(409, "Sender address already exists")
    item = SenderAddress(id=new_id(), domain_id=domain.id, address=address)
    database.add(item)
    await database.commit()
    return envelope(
        201,
        "Sender address created",
        AddressDTO(id=item.id, domain_id=item.domain_id, address=item.address),
    )


@router.delete("/domains/{domain_id}/addresses/{address_id}", response_model=APIEnvelope[None])
async def delete_address(
    domain_id: str, address_id: str, principal: CSRFPrincipal, database: Database
) -> dict[str, Any]:
    """Delete an address and exact grants and scopes tied to it."""
    domain = await get_domain(database, domain_id)
    await require_domain_role(database, principal.user, domain, ("owner", "admin"))
    address = await database.get(SenderAddress, address_id)
    if address is None or address.domain_id != domain.id:
        raise AppError(404, "Sender address not found")
    await database.execute(
        delete(SenderGrant).where(SenderGrant.domain_id == domain.id, SenderGrant.address == address.address)
    )
    await database.execute(
        delete(CredentialScope).where(
            CredentialScope.domain_id == domain.id,
            CredentialScope.address == address.address,
        )
    )
    await database.delete(address)
    await database.commit()
    return envelope(200, "Sender address deleted")


@router.get("/domains/{domain_id}/grants", response_model=APIEnvelope[list[GrantDTO]])
async def list_grants(domain_id: str, principal: PrincipalDependency, database: Database) -> dict[str, Any]:
    """List sender grants for a managed domain."""
    domain = await get_domain(database, domain_id)
    await require_domain_role(database, principal.user, domain, ("owner", "admin"))
    rows = (
        await database.execute(
            select(SenderGrant, User)
            .join(User, User.id == SenderGrant.user_id)
            .where(SenderGrant.domain_id == domain.id)
            .order_by(User.username, SenderGrant.address)
        )
    ).all()
    return envelope(
        200,
        "Sender grants",
        [
            GrantDTO(
                id=grant.id,
                domain_id=grant.domain_id,
                user_id=user.id,
                username=user.username,
                address=grant.address,
            )
            for grant, user in rows
        ],
    )


@router.post("/domains/{domain_id}/grants", response_model=APIEnvelope[GrantDTO], status_code=201)
async def create_grant(
    domain_id: str, payload: CreateGrantRequest, principal: CSRFPrincipal, database: Database
) -> dict[str, Any]:
    """Grant an activated user an exact address or whole domain."""
    domain = await get_domain(database, domain_id)
    await require_domain_role(database, principal.user, domain, ("owner", "admin"))
    user = await find_active_user(database, payload.username)
    address = payload.address
    if address != "*":
        address = domain_address(address, domain)
        exists = await database.scalar(
            select(SenderAddress.id).where(SenderAddress.domain_id == domain.id, SenderAddress.address == address)
        )
        if not exists:
            raise AppError(422, "Register the sender address before granting it")
    existing = await database.scalar(
        select(SenderGrant.id).where(
            SenderGrant.domain_id == domain.id,
            SenderGrant.user_id == user.id,
            SenderGrant.address == address,
        )
    )
    if existing:
        raise AppError(409, "Sender grant already exists")
    grant = SenderGrant(id=new_id(), domain_id=domain.id, user_id=user.id, address=address)
    database.add(grant)
    await database.commit()
    return envelope(
        201,
        "Sender grant created",
        GrantDTO(id=grant.id, domain_id=domain.id, user_id=user.id, username=user.username, address=address),
    )


@router.delete("/domains/{domain_id}/grants/{grant_id}", response_model=APIEnvelope[None])
async def delete_grant(domain_id: str, grant_id: str, principal: CSRFPrincipal, database: Database) -> dict[str, Any]:
    """Revoke a sender grant immediately."""
    domain = await get_domain(database, domain_id)
    await require_domain_role(database, principal.user, domain, ("owner", "admin"))
    grant = await database.get(SenderGrant, grant_id)
    if grant is None or grant.domain_id != domain.id:
        raise AppError(404, "Sender grant not found")
    await database.delete(grant)
    await database.commit()
    return envelope(200, "Sender grant deleted")


@router.get("/domains/{domain_id}/smtp", response_model=APIEnvelope[SMTPConfigDTO | None])
async def get_smtp_config(domain_id: str, principal: PrincipalDependency, database: Database) -> dict[str, Any]:
    """Return an owner's redacted upstream SMTP configuration."""
    domain = await get_domain(database, domain_id)
    await require_domain_role(database, principal.user, domain, ("owner",))
    config = await database.get(SMTPConfig, domain.id)
    return envelope(200, "SMTP configuration", smtp_dto(config) if config else None)


@router.put("/domains/{domain_id}/smtp", response_model=APIEnvelope[SMTPConfigDTO])
async def put_smtp_config(
    domain_id: str,
    payload: SMTPConfigRequest,
    request: Request,
    principal: CSRFPrincipal,
    database: Database,
) -> dict[str, Any]:
    """Validate and save one domain's upstream SMTP configuration."""
    domain = await get_domain(database, domain_id)
    await require_domain_role(database, principal.user, domain, ("owner",))
    try:
        await validate_upstream_host(payload.host, payload.port)
    except UnsafeUpstreamHost as exc:
        raise AppError(422, "SMTP host must resolve only to public IP addresses") from exc
    config = await database.get(SMTPConfig, domain.id)
    if config is None:
        config = SMTPConfig(
            domain_id=domain.id,
            host=payload.host,
            port=payload.port,
            security=payload.security,
            auth=payload.auth_type,
            username=None,
            password_encrypted=None,
        )
        database.add(config)
    config.host = payload.host
    config.port = payload.port
    config.security = payload.security
    config.auth = payload.auth_type
    if payload.auth_type == "none":
        config.username = None
        config.password_encrypted = None
    else:
        config.username = payload.username
        if payload.password:
            config.password_encrypted = encrypt_password(payload.password, request.app.state.settings.encryption_key)
        elif config.password_encrypted is None:
            raise AppError(422, "Password is required for password authentication")
    await database.commit()
    return envelope(200, "SMTP configuration updated", smtp_dto(config))


async def validated_scopes(
    database: AsyncSession, user_id: str, scopes: list[ScopeRequest]
) -> list[tuple[str, str]]:
    """Normalize unique scopes and verify current grants."""
    unique_scopes: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in scopes:
        domain = await get_domain(database, item.domain_id)
        address = item.address if item.address == "*" else domain_address(item.address, domain)
        key = (domain.id, address)
        if key in seen:
            raise AppError(422, "Credential scopes must be unique")
        seen.add(key)
        await validate_scope(database, user_id, domain.id, address)
        unique_scopes.append(key)
    return unique_scopes


@router.get("/smtp-credentials", response_model=APIEnvelope[list[CredentialDTO]])
async def list_credentials(principal: PrincipalDependency, database: Database) -> dict[str, Any]:
    """List the authenticated user's SMTP credentials."""
    credentials = (
        await database.scalars(
            select(SMTPCredential)
            .where(SMTPCredential.user_id == principal.user.id)
            .order_by(SMTPCredential.created_at.desc())
        )
    ).all()
    return envelope(200, "SMTP credentials", [await credential_dto(database, item) for item in credentials])


@router.post("/smtp-credentials", response_model=APIEnvelope[CreatedCredentialDTO], status_code=201)
async def create_credential(
    payload: CreateCredentialRequest, principal: CSRFPrincipal, database: Database
) -> dict[str, Any]:
    """Issue a scoped SMTP password and reveal it once."""
    scopes = await validated_scopes(database, principal.user.id, payload.scopes)
    token = generate_secret()
    credential = SMTPCredential(
        id=new_id(),
        user_id=principal.user.id,
        name=payload.name,
        secret_hash=hash_secret(token),
        expires_at=payload.expires_at,
    )
    database.add(credential)
    await database.flush()
    for domain_id, address in scopes:
        database.add(
            CredentialScope(id=new_id(), credential_id=credential.id, domain_id=domain_id, address=address)
        )
    await database.commit()
    data = CreatedCredentialDTO(
        credential=await credential_dto(database, credential),
        username=credential.id,
        token=token,
    )
    return envelope(201, "SMTP credential created", data)


async def owned_credential(database: AsyncSession, principal: Principal, credential_id: str) -> SMTPCredential:
    """Return a credential only when it belongs to the caller."""
    credential = await database.get(SMTPCredential, credential_id)
    if credential is None or credential.user_id != principal.user.id:
        raise AppError(404, "SMTP credential not found")
    return credential


@router.put("/smtp-credentials/{credential_id}/scopes", response_model=APIEnvelope[CredentialDTO])
async def update_credential_scopes(
    credential_id: str,
    payload: UpdateScopesRequest,
    principal: CSRFPrincipal,
    database: Database,
) -> dict[str, Any]:
    """Replace the scopes of an active owned credential."""
    credential = await owned_credential(database, principal, credential_id)
    if credential.revoked_at is not None:
        raise AppError(409, "Revoked credentials cannot be changed")
    scopes = await validated_scopes(database, principal.user.id, payload.scopes)
    await database.execute(delete(CredentialScope).where(CredentialScope.credential_id == credential.id))
    database.add_all(
        [
            CredentialScope(id=new_id(), credential_id=credential.id, domain_id=domain_id, address=address)
            for domain_id, address in scopes
        ]
    )
    await database.commit()
    return envelope(200, "Credential scopes updated", await credential_dto(database, credential))


@router.post("/smtp-credentials/{credential_id}/revoke", response_model=APIEnvelope[CredentialDTO])
async def revoke_credential(
    credential_id: str, principal: CSRFPrincipal, database: Database
) -> dict[str, Any]:
    """Irreversibly revoke an owned SMTP credential."""
    credential = await owned_credential(database, principal, credential_id)
    if credential.revoked_at is None:
        credential.revoked_at = utc_now()
        await database.commit()
    return envelope(200, "SMTP credential revoked", await credential_dto(database, credential))


@router.get("/logs", response_model=APIEnvelope[PageDTO[LogDTO]])
async def list_logs(
    principal: PrincipalDependency,
    database: Database,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    domain_id: str | None = None,
    status: Literal["pending", "accepted", "failed", "unknown"] | None = None,
    sender: str | None = None,
    recipient: str | None = None,
) -> dict[str, Any]:
    """Return role-filtered and paginated delivery metadata."""
    conditions: list[Any] = []
    if not principal.user.is_operator:
        owned_domains = select(Domain.id).where(
            Domain.owner_user_id == principal.user.id,
            Domain.deleted_at.is_(None),
        )
        conditions.append(or_(SendAttempt.user_id == principal.user.id, SendAttempt.domain_id.in_(owned_domains)))
    if domain_id:
        conditions.append(SendAttempt.domain_id == domain_id)
    if status:
        conditions.append(SendAttempt.status == status)
    if sender:
        conditions.append(SendAttempt.sender == sender.strip().lower())
    if recipient:
        attempt_ids = select(SendRecipient.attempt_id).where(SendRecipient.address == recipient.strip().lower())
        conditions.append(SendAttempt.id.in_(attempt_ids))
    base = select(SendAttempt)
    count_query = select(func.count()).select_from(SendAttempt)
    if conditions:
        base = base.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))
    total = await database.scalar(count_query) or 0
    attempts = (
        await database.scalars(base.order_by(SendAttempt.created_at.desc()).limit(limit).offset(offset))
    ).all()
    items: list[LogDTO] = []
    for attempt in attempts:
        recipients = (
            await database.scalars(
                select(SendRecipient.address)
                .where(SendRecipient.attempt_id == attempt.id)
                .order_by(SendRecipient.address)
            )
        ).all()
        items.append(
            LogDTO(
                id=attempt.id,
                user_id=attempt.user_id,
                credential_id=attempt.credential_id,
                domain_id=attempt.domain_id,
                sender=attempt.sender,
                recipients=list(recipients),
                status=attempt.status,
                error_code=attempt.error_code,
                error_stage=attempt.error_stage,
                error_message=attempt.error_message,
                created_at=attempt.created_at,
                updated_at=attempt.updated_at,
            )
        )
    return envelope(200, "Send logs", PageDTO(items=items, total=total, limit=limit, offset=offset))
