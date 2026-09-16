"""Errors shared by management and SMTP policy adapters."""


class AppError(Exception):
    """Represent an expected, safe-to-display application failure."""

    def __init__(self, status_code: int, message: str) -> None:
        """Initialize a transport-independent application error.

        Args:
            status_code: HTTP-style status for adaptation by each entrypoint.
            message: A safe message that contains no secrets or raw protocol data.
        """
        super().__init__(message)
        self.status_code = status_code
        self.message = message
