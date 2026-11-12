"""Advisory cost / time budgets for ``vf ci``.

VulnForge records token counts (``llm_usage_summary.json``), not dollars. The
CI cost cap therefore needs a price table. Estimates are deliberately
conservative: cache discounts are ignored, so the estimate is an upper bound
on what the provider bills for the recorded tokens.

Caps are advisory. Ralph checks them before leasing each task; a task already
running is never killed by a budget (only by ``--task-timeout``).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from vulnforge.usage import SUMMARY_NAME, load_usage_summary

_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([hms]?)", re.IGNORECASE)
_UNIT_SECONDS = {"h": 3600.0, "m": 60.0, "s": 1.0, "": 1.0}


def parse_duration(raw: Union[str, float, int, None]) -> Optional[float]:
    """Parse ``3600``, ``90s``, ``45m``, ``2h`` or ``1h30m`` into seconds.

    Returns None for None / blank. Raises ValueError for anything else that
    is not a positive duration.
    """
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        val = float(raw)
        if val <= 0:
            raise ValueError(f"duration must be positive: {raw!r}")
        return val
    s = str(raw).strip().lower().replace(" ", "")
    if not s:
        return None
    pos = 0
    total = 0.0
    units_seen: set[str] = set()
    for m in _DURATION_RE.finditer(s):
        if m.start() != pos:
            break
        unit = m.group(2)
        bare_mixed = unit == "" and (units_seen or m.end() != len(s))
        if unit in units_seen or bare_mixed:
            raise ValueError(f"invalid duration: {raw!r}")
        units_seen.add(unit)
        total += float(m.group(1)) * _UNIT_SECONDS[unit]
        pos = m.end()
    if pos != len(s) or total <= 0:
        raise ValueError(
            f"invalid duration: {raw!r} (use seconds, or e.g. 90s, 45m, 2h, 1h30m)"
        )
    return total


@dataclass(frozen=True)
class Price:
    """USD per million tokens."""

    input_per_mtok: float
    output_per_mtok: float

    def cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        return (
            max(0, int(prompt_tokens)) * self.input_per_mtok
            + max(0, int(completion_tokens)) * self.output_per_mtok
        ) / 1_000_000.0


def _price_from(raw: Any) -> Optional[Price]:
    if not isinstance(raw, dict):
        return None
    try:
        inp = float(raw.get("input_per_mtok"))
        out = float(raw.get("output_per_mtok"))
    except (TypeError, ValueError):
        return None
    if inp < 0 or out < 0:
        return None
    return Price(inp, out)


@dataclass
class PriceTable:
    """Per-model prices plus an optional default for any other model."""

    by_model: dict[str, Price] = field(default_factory=dict)
    default: Optional[Price] = None

    @property
    def empty(self) -> bool:
        return not self.by_model and self.default is None

    def for_model(self, model_id: Optional[str]) -> Optional[Price]:
        if model_id and model_id in self.by_model:
            return self.by_model[model_id]
        return self.default

    @classmethod
    def from_sources(
        cls,
        cfg: dict,
        *,
        default_input: Optional[float] = None,
        default_output: Optional[float] = None,
    ) -> "PriceTable":
        """Config ``ci.pricing`` (per model id) wins; CLI defaults cover the rest.

        ``ci.pricing.default`` in config is also honored when no CLI default
        is given. Both CLI defaults must be set together.
        """
        if (default_input is None) != (default_output is None):
            raise ValueError(
                "--price-input-per-mtok and --price-output-per-mtok must be given together"
            )
        ci = (cfg or {}).get("ci") or {}
        pricing = ci.get("pricing") if isinstance(ci, dict) else None
        by_model: dict[str, Price] = {}
        cfg_default: Optional[Price] = None
        if isinstance(pricing, dict):
            for model_id, row in pricing.items():
                price = _price_from(row)
                if price is None:
                    raise ValueError(
                        f"ci.pricing.{model_id}: need non-negative "
                        "input_per_mtok and output_per_mtok"
                    )
                if str(model_id) == "default":
                    cfg_default = price
                else:
                    by_model[str(model_id)] = price
        default = cfg_default
        if default_input is not None and default_output is not None:
            if default_input < 0 or default_output < 0:
                raise ValueError("prices must be non-negative")
            default = Price(float(default_input), float(default_output))
        return cls(by_model=by_model, default=default)


@dataclass
class CostEstimate:
    usd: float
    unpriced_models: list[str]
    unpriced_tokens: int
    # True when LLM calls were recorded with no token counts, or the usage
    # summary is unreadable: spend cannot be measured, so a cap cannot hold.
    unmeasured: bool = False
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "estimate_usd": round(self.usd, 6),
            "unpriced_models": list(self.unpriced_models),
            "unpriced_tokens": int(self.unpriced_tokens),
            "unmeasured": bool(self.unmeasured),
            "detail": self.detail,
        }


_UNATTRIBUTED = "(unattributed)"


def _tokens(row: Any) -> tuple[int, int, int]:
    """(billable input, completion, llm_calls) for one usage row.

    Billable input is prompt + cache_read + cache_creation. Anthropic reports
    cache tokens outside ``input_tokens``; OpenAI's cached tokens sit inside
    ``prompt_tokens`` and are counted twice here. Over-counting only stops
    leasing early, so the cap stays conservative.
    """
    if not isinstance(row, dict):
        return 0, 0, 0
    inp = (
        int(row.get("prompt_tokens") or 0)
        + int(row.get("cache_read_tokens") or 0)
        + int(row.get("cache_creation_tokens") or 0)
    )
    return inp, int(row.get("completion_tokens") or 0), int(row.get("llm_calls") or 0)


def _delta(cur: tuple[int, int, int], base: tuple[int, int, int]) -> tuple[int, int, int]:
    return tuple(max(0, c - b) for c, b in zip(cur, base))  # type: ignore[return-value]


def estimate_cost(
    summary: dict[str, Any],
    prices: PriceTable,
    *,
    baseline: Optional[dict[str, Any]] = None,
) -> CostEstimate:
    """Estimate USD for a usage summary (see ``vulnforge.usage``).

    With ``baseline`` (the summary when ``vf ci`` started), only spend since
    then is counted, so a resumed run is not over its cap before it leases.
    Tokens recorded without a model id (summary total minus the per-model
    sum) are priced at the default price, or reported as unpriced.
    """
    summary = summary if isinstance(summary, dict) else {}
    baseline = baseline if isinstance(baseline, dict) else {}
    by_model = summary.get("by_model") if isinstance(summary.get("by_model"), dict) else {}
    base_by_model = (
        baseline.get("by_model") if isinstance(baseline.get("by_model"), dict) else {}
    )
    usd = 0.0
    unpriced: list[str] = []
    unpriced_tokens = 0
    attributed = (0, 0, 0)
    for model_id, row in sorted(by_model.items()):
        inp, out, calls = _delta(_tokens(row), _tokens(base_by_model.get(model_id)))
        attributed = (attributed[0] + inp, attributed[1] + out, attributed[2] + calls)
        if inp == 0 and out == 0:
            continue
        price = prices.for_model(str(model_id))
        if price is None:
            unpriced.append(str(model_id))
            unpriced_tokens += inp + out
            continue
        usd += price.cost(inp, out)
    total_inp, total_out, total_calls = _delta(_tokens(summary), _tokens(baseline))
    rest_inp = max(0, total_inp - attributed[0])
    rest_out = max(0, total_out - attributed[1])
    if rest_inp or rest_out:
        if prices.default is None:
            unpriced.append(_UNATTRIBUTED)
            unpriced_tokens += rest_inp + rest_out
        else:
            usd += prices.default.cost(rest_inp, rest_out)
    unmeasured = total_calls > 0 and total_inp == 0 and total_out == 0
    return CostEstimate(
        usd=usd,
        unpriced_models=unpriced,
        unpriced_tokens=unpriced_tokens,
        unmeasured=unmeasured,
        detail=(
            f"{total_calls} LLM call(s) recorded without token counts"
            if unmeasured
            else ""
        ),
    )


def read_usage_summary(run_dir: Union[str, Path]) -> tuple[dict[str, Any], Optional[str]]:
    """Load the usage summary; second item is an error when the file is unreadable.

    ``load_usage_summary`` returns zeros on a corrupt file. A cost cap must
    not read that as "no spend", so the error is surfaced here.
    """
    path = Path(run_dir) / SUMMARY_NAME
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            return {}, f"{SUMMARY_NAME} unreadable: {e}"
        if not isinstance(data, dict):
            return {}, f"{SUMMARY_NAME} is not an object"
    return load_usage_summary(run_dir), None


class CostGuard:
    """Ralph ``budget_check`` callback: returns a stop record once over the cap.

    Counts spend since construction (the baseline snapshot). Fails closed:
    tokens from a model with no price, calls with no token counts, or an
    unreadable usage file stop leasing too, because the cap can no longer be
    enforced (reason ``cost_unpriced`` / ``cost_unmeasured``; ``vf ci`` exits 2).
    """

    def __init__(self, run_dir: Union[str, Path], max_usd: float, prices: PriceTable):
        if max_usd < 0:
            raise ValueError("--max-cost-usd must be non-negative")
        self.run_dir = Path(run_dir)
        self.max_usd = float(max_usd)
        self.prices = prices
        self.baseline, err = read_usage_summary(self.run_dir)
        self.baseline_error = err
        self.last: CostEstimate = CostEstimate(0.0, [], 0)
        self.stop_reason: Optional[str] = None

    def estimate(self) -> CostEstimate:
        summary, err = read_usage_summary(self.run_dir)
        if err or self.baseline_error:
            return CostEstimate(
                0.0, [], 0, unmeasured=True, detail=err or str(self.baseline_error)
            )
        return estimate_cost(summary, self.prices, baseline=self.baseline)

    def __call__(self) -> Optional[dict[str, Any]]:
        est = self.estimate()
        self.last = est
        reason: Optional[str] = None
        if est.unmeasured:
            reason = "cost_unmeasured"
        elif est.unpriced_models:
            reason = "cost_unpriced"
        elif est.usd >= self.max_usd:
            reason = "budget_cost"
        if reason is None:
            return None
        self.stop_reason = reason
        return {
            "event": "budget_cost",
            "reason": reason,
            "max_usd": self.max_usd,
            **est.to_dict(),
        }
