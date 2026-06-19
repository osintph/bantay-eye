"""Abstract base class for engine adapters."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Iterable

from bantay_eye.models import Finding


class EngineError(Exception):
    """Raised when an engine call fails in a recoverable way."""


class EngineAdapter(ABC):
    """Base class for engine adapters.

    Subclasses implement :meth:`_search` to talk to their provider. The base
    class handles polite-mode rate limiting between calls.
    """

    name: str = "base"

    def __init__(self, min_delay_seconds: float = 1.0) -> None:
        self.min_delay_seconds = min_delay_seconds
        self._last_call: float | None = None

    def _wait(self) -> None:
        """Block until at least :attr:`min_delay_seconds` since last call."""

        if self._last_call is None:
            return
        elapsed = time.monotonic() - self._last_call
        remaining = self.min_delay_seconds - elapsed
        if remaining > 0:
            time.sleep(remaining)

    def _mark_call(self) -> None:
        self._last_call = time.monotonic()

    def search(self, query: str, category: str, max_results: int = 100) -> list[Finding]:
        """Run a single query and return normalised Findings.

        Wraps the subclass's :meth:`_search` with rate limiting and
        category tagging.
        """

        self._wait()
        try:
            results = list(self._search(query=query, max_results=max_results))
        finally:
            self._mark_call()

        for finding in results:
            finding.category = category
        return results

    @abstractmethod
    def _search(self, query: str, max_results: int) -> Iterable[Finding]:
        """Engine-specific search implementation."""
