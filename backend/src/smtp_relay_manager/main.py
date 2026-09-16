"""FastAPI application entrypoint."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI

from .api import configure_api
from .config import Settings, get_settings
from .db import create_database
from .identity import IdentityProvider, LocalIdentityProvider
from .maintenance import maintenance_loop


def create_app(
    settings: Settings | None = None,
    identity_provider: IdentityProvider | None = None,
) -> FastAPI:
    """Create an isolated application instance.

    Args:
        settings: Explicit settings for tests or embedding.
            Environment settings are loaded when omitted.
        identity_provider: Authentication implementation. Local passwords are
            used when omitted.

    Returns:
        A configured FastAPI application.
    """
    app_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        """Own database and maintenance resources for one app lifetime."""
        app_settings.validate_secrets()
        engine, session_factory = create_database(app_settings)
        application.state.settings = app_settings
        application.state.engine = engine
        application.state.session_factory = session_factory
        maintenance_task = asyncio.create_task(
            maintenance_loop(session_factory, app_settings.log_retention_days),
            name="send-log-maintenance",
        )
        try:
            yield
        finally:
            maintenance_task.cancel()
            with suppress(asyncio.CancelledError):
                await maintenance_task
            await engine.dispose()

    application = FastAPI(
        title="SMTP Relay Manager",
        version="1.0.0",
        lifespan=lifespan,
    )
    application.state.settings = app_settings
    application.state.identity_provider = (
        identity_provider or LocalIdentityProvider()
    )
    configure_api(application)
    return application


app = create_app()
