"""Base application exception contract."""


class ThreatModelerError(Exception):
    """Represent an expected application failure with safe diagnostic metadata.

    Subclasses identify failure categories while this contract carries an optional stable
    code, retryability decision, and structured context for CLI logging.
    """

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        retryable: bool | None = None,
        context: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.retryable = retryable
        self.context = dict(context) if context is not None else None

    def to_log_context(self) -> dict[str, object]:
        """Build metadata suitable for a structured log record.

        Returns:
            Fresh dictionary containing the error type and configured diagnostics.
        """
        details: dict[str, object] = {
            "error_type": type(self).__name__,
            "message": self.message,
        }
        if self.error_code is not None:
            details["error_code"] = self.error_code
        if self.retryable is not None:
            details["retryable"] = self.retryable
        if self.context is not None:
            details["context"] = dict(self.context)
        return details
