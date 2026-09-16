"""Process entrypoint for the inbound SMTP service."""

from __future__ import annotations

import asyncio
import logging
import signal

from smtp_relay_manager.config import get_settings
from smtp_relay_manager.db import create_database

from .certificates import CertificateManager
from .server import SMTPRelayServer
from .service import RelayService


async def main() -> None:
    """Validate configuration, start both listeners, and watch certificates."""

    settings = get_settings()
    settings.validate_secrets()
    engine, session_factory = create_database(settings)
    certificates = CertificateManager(settings.smtp_cert_dir, settings.smtp_hostname)
    certificates.reload(required=True)
    service = RelayService(
        session_factory,
        settings.encryption_key,
        connect_timeout=settings.smtp_connect_timeout,
        command_timeout=settings.smtp_command_timeout,
    )
    server = SMTPRelayServer(
        service,
        certificates,
        host=settings.smtp_host,
        tls_port=settings.smtp_tls_port,
        starttls_port=settings.smtp_starttls_port,
        max_message_bytes=settings.smtp_max_message_bytes,
        max_recipients=settings.smtp_max_recipients,
        max_connections=settings.smtp_max_connections,
        max_data_connections=settings.smtp_max_data_connections,
        idle_timeout=settings.smtp_idle_timeout,
        transaction_timeout=settings.smtp_transaction_timeout,
    )
    stop = asyncio.Event()
    watcher = asyncio.create_task(
        certificates.watch(settings.smtp_cert_reload_seconds, stop),
        name="smtp-certificate-watcher",
    )
    current_task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    if current_task is not None:
        for caught_signal in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(caught_signal, current_task.cancel)
    try:
        await server.serve_forever()
    finally:
        stop.set()
        watcher.cancel()
        await asyncio.gather(watcher, return_exceptions=True)
        await server.shutdown(
            max(settings.smtp_idle_timeout, settings.smtp_transaction_timeout) + 1
        )
        await engine.dispose()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(main())
