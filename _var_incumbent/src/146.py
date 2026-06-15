from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Iterable, Mapping, Any


TWOPLACES = Decimal("0.01")


def _to_decimal(value: Any) -> Decimal:
    return Decimal(str(value))


def _money(value: Decimal) -> Decimal:
    return value.quantize(TWOPLACES, rounding=ROUND_HALF_UP)


@dataclass(frozen=True)
class UsageEvent:
    hotel_id: str
    customer_id: str
    api_calls: int
    tokens: int
    cost_eur: Decimal

    @classmethod
    def from_mapping(cls, row: Mapping[str, Any]) -> "UsageEvent":
        hotel_id = str(row["hotel_id"])
        customer_id = str(row["customer_id"])
        api_calls = int(row.get("api_calls", 0))
        tokens = int(row.get("tokens", 0))
        cost_eur = _to_decimal(row.get("cost_eur", "0"))

        if api_calls < 0 or tokens < 0 or cost_eur < 0:
            raise ValueError("usage values must be non-negative")

        return cls(
            hotel_id=hotel_id,
            customer_id=customer_id,
            api_calls=api_calls,
            tokens=tokens,
            cost_eur=cost_eur,
        )


def aggregate_usage(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    hotel_api_calls: dict[str, int] = defaultdict(int)
    customer_tokens: dict[str, int] = defaultdict(int)
    customer_costs: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))

    total_api_calls = 0
    total_tokens = 0
    total_cost = Decimal("0")

    for raw_event in events:
        event = UsageEvent.from_mapping(raw_event)

        hotel_api_calls[event.hotel_id] += event.api_calls
        customer_tokens[event.customer_id] += event.tokens
        customer_costs[event.customer_id] += event.cost_eur

        total_api_calls += event.api_calls
        total_tokens += event.tokens
        total_cost += event.cost_eur

    return {
        "billing_mode": "report_only",
        "hotels": {
            hotel_id: {"api_calls": api_calls}
            for hotel_id, api_calls in sorted(hotel_api_calls.items())
        },
        "customers": {
            customer_id: {
                "token_burn": customer_tokens[customer_id],
                "cost_eur": str(_money(customer_costs[customer_id])),
            }
            for customer_id in sorted(customer_tokens)
        },
        "summary": {
            "total_api_calls": total_api_calls,
            "total_tokens": total_tokens,
            "total_cost_eur": str(_money(total_cost)),
            "hotel_count": len(hotel_api_calls),
            "customer_count": len(customer_tokens),
        },
    }


def build_report(events: Iterable[Mapping[str, Any]], report_date: str | None = None) -> dict[str, Any]:
    payload = aggregate_usage(events)
    payload["report_date"] = report_date or date.today().isoformat()
    return payload


def write_report(
    events: Iterable[Mapping[str, Any]],
    output_dir: str | Path = "reports",
    report_date: str | None = None,
) -> Path:
    payload = build_report(events, report_date=report_date)
    output_path = Path(output_dir) / f"df-146-{payload['report_date']}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return output_path
# [CRUX-MK]
