from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping


TWOPLACES = Decimal("0.01")


@dataclass(frozen=True)
class UsageEvent:
    hotel_id: str
    customer_id: str
    api_calls: int
    tokens: int
    cost_per_1k_tokens: Decimal

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "UsageEvent":
        return cls(
            hotel_id=str(raw["hotel_id"]),
            customer_id=str(raw["customer_id"]),
            api_calls=int(raw.get("api_calls", 0)),
            tokens=int(raw.get("tokens", 0)),
            cost_per_1k_tokens=Decimal(str(raw.get("cost_per_1k_tokens", "0"))),
        )


def _money(value: Decimal) -> Decimal:
    return value.quantize(TWOPLACES, rounding=ROUND_HALF_UP)


def aggregate_usage(events: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    hotel_api_calls: Dict[str, int] = defaultdict(int)
    customer_token_burn: Dict[str, int] = defaultdict(int)
    customer_costs: Dict[str, Decimal] = defaultdict(lambda: Decimal("0"))

    normalized: List[UsageEvent] = [UsageEvent.from_mapping(event) for event in events]

    for event in normalized:
        if event.api_calls < 0 or event.tokens < 0 or event.cost_per_1k_tokens < 0:
            raise ValueError("Usage values must be non-negative")

        hotel_api_calls[event.hotel_id] += event.api_calls
        customer_token_burn[event.customer_id] += event.tokens
        customer_costs[event.customer_id] += (
            Decimal(event.tokens) / Decimal("1000")
        ) * event.cost_per_1k_tokens

    return {
        "totals": {
            "events": len(normalized),
            "api_calls": sum(hotel_api_calls.values()),
            "tokens": sum(customer_token_burn.values()),
            "cost": str(_money(sum(customer_costs.values(), Decimal("0")))),
        },
        "api_calls_per_hotel": dict(sorted(hotel_api_calls.items())),
        "token_burn_per_customer": dict(sorted(customer_token_burn.items())),
        "cost_per_customer": {
            customer_id: str(_money(cost))
            for customer_id, cost in sorted(customer_costs.items())
        },
        "billing_mode": "read_only",
    }


def build_report(events: Iterable[Mapping[str, Any]], report_date: str | None = None) -> Dict[str, Any]:
    effective_date = report_date or date.today().isoformat()
    report = aggregate_usage(events)
    report["report_date"] = effective_date
    return report


def write_report(
    events: Iterable[Mapping[str, Any]],
    report_dir: str | Path = "reports",
    report_date: str | None = None,
) -> Path:
    report = build_report(events, report_date=report_date)
    output_dir = Path(report_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"df-146-{report['report_date']}.json"
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return output_path
# [CRUX-MK]
