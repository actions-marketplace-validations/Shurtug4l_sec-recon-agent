"""In-process denial-of-wallet guard.

A rolling-window ceiling on estimated LLM spend across triage runs. The
per-request round cap (`settings.agent_request_limit`) already bounds a single
run's cost; this bounds the *aggregate* an attacker can drive by repeating
requests against a reachable endpoint.

The window is held in memory (a deque of `(monotonic_ts, usd)` events), so it
resets on process restart. That is a deliberate, documented tradeoff: it bounds
spend *between* restarts, and forcing a restart is itself a much higher bar than
hammering an unbounded endpoint. Persisting the counter (e.g. in the audit DB)
is the production evolution if the deployment needs restart-durable budgets.

The ceiling is read live from `settings` on every call, so a test (or a config
reload) that changes `denial_of_wallet_usd_per_day` takes effect without
rebuilding the tracker.

Concurrency note: `would_block()` (pre-run) and `record()` (post-run) are
separate steps, so N concurrent in-flight runs can overshoot the ceiling by at
most N times the per-run cost. The round cap bounds that per-run cost, so the
overshoot is bounded and acceptable for a rail; it is not a billing ledger.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque

from sec_recon_agent.config import settings

_WINDOW_SECONDS = 24 * 3600


class BudgetTracker:
    def __init__(self, window_seconds: float = _WINDOW_SECONDS) -> None:
        self._window = window_seconds
        self._events: deque[tuple[float, float]] = deque()
        self._lock = asyncio.Lock()

    @staticmethod
    def _ceiling() -> float | None:
        return settings.denial_of_wallet_usd_per_day

    @property
    def enabled(self) -> bool:
        return self._ceiling() is not None

    def _prune(self, now: float) -> None:
        cutoff = now - self._window
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    async def spent_usd(self) -> float:
        """Estimated USD spent within the rolling window (0.0 when empty)."""
        async with self._lock:
            self._prune(time.monotonic())
            return sum(usd for _, usd in self._events)

    async def would_block(self) -> bool:
        """True when a new run must be refused because the window is at/over the
        ceiling. Always False when the guard is disabled."""
        ceiling = self._ceiling()
        if ceiling is None:
            return False
        return await self.spent_usd() >= ceiling

    def record_now(self, usd: float | None) -> None:
        """Add a run's estimated cost to the window, synchronously.

        The triage generator charges the run from its `finally`, which after
        a client disconnect executes inside a cancelled anyio scope where
        every `await` re-raises CancelledError: an awaited record would never
        land, and the rail would be defeated by the cheapest client behaviour
        there is. No lock is needed: nothing awaits between prune and append,
        and the event loop is single-threaded. No-ops when the guard is
        disabled or the cost is unknown/non-positive (an unpriced model
        yields None, and must not silently count as zero-forever).
        """
        if self._ceiling() is None or usd is None or usd <= 0:
            return
        now = time.monotonic()
        self._prune(now)
        self._events.append((now, usd))

    async def record(self, usd: float | None) -> None:
        """Awaitable form of `record_now`, for callers on a live scope."""
        async with self._lock:
            self.record_now(usd)

    def reset(self) -> None:
        """Test-only: drop the accumulated window."""
        self._events.clear()


# Module-level singleton shared by the triage endpoint.
budget_tracker = BudgetTracker()
