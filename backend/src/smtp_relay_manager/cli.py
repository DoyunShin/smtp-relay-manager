"""Administrative command line utilities."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import re
from collections.abc import Sequence

from sqlalchemy import select

from .config import get_settings
from .db import create_database
from .models import User, new_id
from .security import hash_password

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Build the management command parser."""
    parser = argparse.ArgumentParser(
        description="SMTP Relay Manager administration"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create_operator = commands.add_parser(
        "create-operator", help="Create the initial service operator"
    )
    create_operator.add_argument("username")
    return parser


async def create_operator(username: str, password: str) -> None:
    """Create an active operator without shipping default credentials."""
    normalized_username = username.strip().lower()
    if not USERNAME_PATTERN.fullmatch(normalized_username):
        raise ValueError("Invalid username")
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")
    settings = get_settings()
    settings.validate_secrets()
    engine, session_factory = create_database(settings)
    try:
        async with session_factory.begin() as database:
            existing = await database.scalar(
                select(User.id).where(User.username == normalized_username)
            )
            if existing:
                raise ValueError("Username already exists")
            database.add(
                User(
                    id=new_id(),
                    username=normalized_username,
                    password_hash=await hash_password(password),
                    active=True,
                    is_operator=True,
                )
            )
    finally:
        await engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    """Execute an administrative command."""
    arguments = build_parser().parse_args(argv)
    if arguments.command == "create-operator":
        password = getpass.getpass("Password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise ValueError("Passwords do not match")
        asyncio.run(create_operator(arguments.username, password))
        logging.basicConfig(level=logging.INFO, format="%(message)s")
        LOGGER.info("Created operator %s", arguments.username.strip().lower())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
