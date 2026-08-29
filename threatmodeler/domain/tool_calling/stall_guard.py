"""Abort tool-calling loops that keep hitting the same finish rejection."""

from __future__ import annotations


class RepeatedFinishRejectionGuard:
    """Track identical finish rejections and signal when the loop has stalled.

    The first occurrence of a violation message is recorded. A later finish rejection
    with the exact same message means the model made no net progress despite having
    replace/remove tools available.
    """

    def __init__(self, *, stall_after_repeats: int = 2) -> None:
        if stall_after_repeats < 1:
            raise ValueError("stall_after_repeats must be at least one")
        self._stall_after_repeats = stall_after_repeats
        self._last_message: str | None = None
        self._repeat_count = 0

    def record(self, message: str) -> bool:
        """Record one finish rejection and return whether the loop should abort.

        Args:
            message: Violation text returned by the finish tool.

        Returns:
            True when the same message has now been seen ``stall_after_repeats`` times
            in a row (including the first occurrence), signalling a stalled loop.
        """
        if message == self._last_message:
            self._repeat_count += 1
        else:
            self._last_message = message
            self._repeat_count = 1
        return self._repeat_count >= self._stall_after_repeats
