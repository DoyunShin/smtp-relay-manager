"""Atomic TLS certificate loading for inbound SMTP listeners."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import ssl
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.x509.oid import NameOID

LOGGER = logging.getLogger(__name__)


class CertificateError(RuntimeError):
    """Raised when an SMTP certificate cannot safely be activated."""


def _certificate_names(
    certificate: x509.Certificate,
) -> tuple[list[str], list[str]]:
    dns_names: list[str] = []
    ip_names: list[str] = []
    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        common_names = certificate.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )
        if common_names:
            dns_names.append(cast(str, common_names[-1].value))
    else:
        dns_names.extend(san.get_values_for_type(x509.DNSName))
        ip_names.extend(
            str(value) for value in san.get_values_for_type(x509.IPAddress)
        )
    return dns_names, ip_names


def _matches_hostname(certificate: x509.Certificate, hostname: str) -> None:
    dns_names, ip_names = _certificate_names(certificate)
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        normalized = (
            hostname.rstrip(".").encode("idna").decode("ascii").lower()
        )
        for pattern in dns_names:
            pattern = (
                pattern.rstrip(".").encode("idna").decode("ascii").lower()
            )
            if pattern == normalized:
                return
            if pattern.startswith("*.") and normalized.count(
                "."
            ) == pattern.count("."):
                if normalized.endswith(pattern[1:]):
                    return
    else:
        if any(
            ipaddress.ip_address(candidate) == address
            for candidate in ip_names
        ):
            return
    raise CertificateError(f"certificate is not valid for {hostname}")


class CertificateManager:
    """Update an SSL context without interrupting established sessions."""

    def __init__(self, directory: Path, hostname: str) -> None:
        self.directory = directory
        self.hostname = (
            hostname.rstrip(".").encode("idna").decode("ascii").lower()
        )
        self.cert_path = directory / "fullchain.pem"
        self.key_path = directory / "privkey.pem"
        self.context = self._new_context(with_router=True)
        self._active_context: ssl.SSLContext | None = None
        self._fingerprint: bytes | None = None
        self._not_after: datetime | None = None

    def _new_context(self, *, with_router: bool = False) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        if with_router:
            context.set_servername_callback(self._check_sni)
        return context

    @property
    def usable(self) -> bool:
        """Return whether the active certificate is currently valid."""

        return self._not_after is not None and self._not_after > datetime.now(
            UTC
        )

    def _check_sni(
        self,
        ssl_object: ssl.SSLSocket | ssl.SSLObject,
        server_name: str | None,
        context: object,
    ) -> None:
        del context
        if not self.usable:
            raise ssl.SSLError("SMTP TLS certificate is expired")
        if (
            server_name is not None
            and server_name.rstrip(".").lower() != self.hostname
        ):
            raise ssl.SSLError("unexpected SMTP TLS server name")
        if self._active_context is None:
            raise ssl.SSLError("SMTP TLS certificate is unavailable")
        ssl_object.context = self._active_context

    def _read_files(self) -> tuple[bytes, bytes, bytes]:
        try:
            certificate = self.cert_path.read_bytes()
            private_key = self.key_path.read_bytes()
        except OSError as exc:
            raise CertificateError(
                "could not read SMTP certificate files"
            ) from exc
        fingerprint = hashlib.sha256(
            certificate + b"\x00" + private_key
        ).digest()
        return certificate, private_key, fingerprint

    def reload(self, *, required: bool = False) -> bool:
        """Activate changed files while preserving a valid old certificate."""

        try:
            certificate_bytes, private_key_bytes, fingerprint = (
                self._read_files()
            )
            if fingerprint == self._fingerprint:
                if required and not self.usable:
                    raise CertificateError("SMTP certificate is expired")
                return False
            certificate = x509.load_pem_x509_certificate(certificate_bytes)
            not_before = certificate.not_valid_before_utc
            not_after = certificate.not_valid_after_utc
            now = datetime.now(UTC)
            if now < not_before or now >= not_after:
                raise CertificateError(
                    "SMTP certificate is not currently valid"
                )
            _matches_hostname(certificate, self.hostname)

            # SSLContext only accepts paths. Materialize the exact validated
            # snapshot in private files so mounted symlinks cannot change
            # between validation and activation.
            with (
                tempfile.NamedTemporaryFile(
                    prefix="smtp-cert-", suffix=".pem"
                ) as cert,
                tempfile.NamedTemporaryFile(
                    prefix="smtp-key-", suffix=".pem"
                ) as key,
            ):
                cert.write(certificate_bytes)
                cert.flush()
                key.write(private_key_bytes)
                key.flush()
                candidate = self._new_context()
                candidate.load_cert_chain(cert.name, key.name)
        except (OSError, ValueError, ssl.SSLError, CertificateError) as exc:
            if required or not self.usable:
                if isinstance(exc, CertificateError):
                    raise
                raise CertificateError(
                    "invalid SMTP certificate or private key"
                ) from exc
            LOGGER.error(
                "SMTP certificate reload rejected (%s)", type(exc).__name__
            )
            return False
        self._fingerprint = fingerprint
        self._not_after = not_after
        self._active_context = candidate
        LOGGER.info(
            "SMTP certificate loaded; expires at %s", not_after.isoformat()
        )
        return True

    async def watch(self, interval: float, stop: asyncio.Event) -> None:
        """Reload changed certificate files until asked to stop."""

        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except TimeoutError:
                try:
                    self.reload()
                except CertificateError as error:
                    LOGGER.warning(
                        "SMTP certificate remains unavailable (%s)",
                        type(error).__name__,
                    )


__all__ = ["CertificateError", "CertificateManager"]
