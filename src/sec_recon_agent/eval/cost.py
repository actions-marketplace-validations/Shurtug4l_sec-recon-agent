"""Per-model token pricing for the eval scorecard.

Cost is estimated locally from token counts (the API does not return a price),
so the scorecard can report $/triage without a billing call. Prices are USD per
million tokens, keyed by the exact model identifiers on the backend allowlist
(agent/triage.py::ALLOWED_MODELS) plus the short aliases the eval CLI accepts.

Source: Anthropic published API pricing per tier as of 2026-06-24
(Haiku 4.5 $1.00 / $5.00, Sonnet tier $3.00 / $15.00, Opus tier $5.00 / $25.00
per MTok input / output). Prompt-cache tokens follow Anthropic's published
multipliers on the input price: a cache write (5-minute TTL) costs 1.25x, a
cache read 0.1x. pydantic-ai reports them inside `input_tokens`, so they are
carved out of the total before the plain price applies. Update the table and
the stamped date if pricing moves. Unknown models return None rather than a
fabricated cost -- an honest "n/a" beats a wrong number on a portfolio
scorecard.
"""

from dataclasses import dataclass

PRICING_SOURCE_DATE = "2026-06-24"
# Multipliers on the input price for prompt-cache tokens (5-minute TTL).
CACHE_WRITE_MULTIPLIER = 1.25
CACHE_READ_MULTIPLIER = 0.1


@dataclass(frozen=True)
class ModelPrice:
    """USD per million tokens, input and output."""

    input_usd_per_mtok: float
    output_usd_per_mtok: float


# Keyed by the full model identifiers the backend allows, so a cost lookup can
# not silently attribute a price to a model the deployment never runs.
MODEL_PRICING: dict[str, ModelPrice] = {
    "claude-haiku-4-5-20251001": ModelPrice(1.0, 5.0),
    "claude-sonnet-4-6": ModelPrice(3.0, 15.0),
    "claude-opus-4-7": ModelPrice(5.0, 25.0),
}

# Short aliases the eval CLI passes in place of the full identifier, mirroring
# agent/triage.py::MODEL_ALIASES so the two never drift silently.
_ALIASES: dict[str, str] = {
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-4-6",
    "opus": "claude-opus-4-7",
    "default": "claude-haiku-4-5-20251001",
}


def _normalize_model(model: str) -> str:
    """Resolve aliases and strip a provider prefix (`anthropic:claude-...`)."""
    candidate = model.strip()
    if ":" in candidate:
        candidate = candidate.split(":", 1)[1]
    return _ALIASES.get(candidate, candidate)


def price_for(model: str) -> ModelPrice | None:
    """Look up the price for a model id / alias, or None if unpriced."""
    return MODEL_PRICING.get(_normalize_model(model))


def estimate_cost_usd(
    model: str,
    input_tokens: int | None,
    output_tokens: int | None,
    *,
    cache_read_tokens: int | None = None,
    cache_write_tokens: int | None = None,
) -> float | None:
    """Estimate USD cost for one triage from its token counts.

    `input_tokens` is the TOTAL input as pydantic-ai reports it, cache
    traffic included (on the recorded runs it equals cache reads plus cache
    writes plus a few dozen uncached tokens). Cache reads and writes are
    carved out and priced at their multipliers; the remainder is billed at
    the plain input price. Returns None when the model is unpriced or both
    primary token counts are missing, so the caller renders "n/a" rather
    than a misleading $0.00.
    """
    price = price_for(model)
    if price is None:
        return None
    if input_tokens is None and output_tokens is None:
        return None
    inp = input_tokens or 0
    out = output_tokens or 0
    reads = cache_read_tokens or 0
    writes = cache_write_tokens or 0
    uncached = max(inp - reads - writes, 0)
    per_input = price.input_usd_per_mtok / 1_000_000
    return (
        uncached * per_input
        + reads * per_input * CACHE_READ_MULTIPLIER
        + writes * per_input * CACHE_WRITE_MULTIPLIER
        + (out / 1_000_000) * price.output_usd_per_mtok
    )
