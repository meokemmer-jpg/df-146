from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import date
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional


@dataclass(frozen=True)
class UsageEvent:
    hotel_id: str
    customer_id: str
    api_calls: int = 0
    tokens: int = 0
    model: str = "default"
    unit_cost_per_1k_tokens: float = 0.0

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "UsageEvent":
        return cls(
            hotel_id=str(raw["hotel_id"]),
            customer_id=str(raw["customer_id"]),
            api_calls=int(raw.get("api_calls", 0)),
            tokens=int(raw.get("tokens", 0)),
            model=str(raw.get("model", "default")),
            unit_cost_per_1k_tokens=float(raw.get("unit_cost_per_1k_tokens", 0.0)),
        )


def _round_money(value: float) -> float:
    return round(value + 1e-12, 6)


def aggregate_usage(events: Iterable[Mapping[str, Any] | UsageEvent]) -> Dict[str, Any]:
    by_hotel: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"api_calls": 0, "tokens": 0, "customers": set(), "cost": 0.0}
    )
    by_customer: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"api_calls": 0, "tokens": 0, "hotels": set(), "cost": 0.0}
    )

    total_api_calls = 0
    total_tokens = 0
    total_cost = 0.0

    for item in events:
        event = item if isinstance(item, UsageEvent) else UsageEvent.from_mapping(item)

        if event.api_calls < 0 or event.tokens < 0 or event.unit_cost_per_1k_tokens < 0:
            raise ValueError("Usage values must be non-negative.")

        event_cost = (event.tokens / 1000.0) * event.unit_cost_per_1k_tokens

        hotel = by_hotel[event.hotel_id]
        hotel["api_calls"] += event.api_calls
        hotel["tokens"] += event.tokens
        hotel["customers"].add(event.customer_id)
        hotel["cost"] += event_cost

        customer = by_customer[event.customer_id]
        customer["api_calls"] += event.api_calls
        customer["tokens"] += event.tokens
        customer["hotels"].add(event.hotel_id)
        customer["cost"] += event_cost

        total_api_calls += event.api_calls
        total_tokens += event.tokens
        total_cost += event_cost

    hotels = {
        hotel_id: {
            "api_calls": data["api_calls"],
            "tokens": data["tokens"],
            "customer_count": len(data["customers"]),
            "cost": _round_money(data["cost"]),
        }
        for hotel_id, data in sorted(by_hotel.items())
    }

    customers = {
        customer_id: {
            "api_calls": data["api_calls"],
            "tokens": data["tokens"],
            "hotel_count": len(data["hotels"]),
            "cost": _round_money(data["cost"]),
        }
        for customer_id, data in sorted(by_customer.items())
    }

    return {
        "summary": {
            "hotel_count": len(hotels),
            "customer_count": len(customers),
            "total_api_calls": total_api_calls,
            "total_tokens": total_tokens,
            "total_cost": _round_money(total_cost),
            "auto_billing": False,
        },
        "hotels": hotels,
        "customers": customers,
    }


def build_report(
    events: Iterable[Mapping[str, Any] | UsageEvent],
    report_date: Optional[str] = None,
) -> Dict[str, Any]:
    payload = aggregate_usage(events)
    payload["report_date"] = report_date or date.today().isoformat()
    payload["report_type"] = "read_only_usage_report"
    return payload


def write_report(
    events: Iterable[Mapping[str, Any] | UsageEvent],
    output_dir: str | Path = "reports",
    report_date: Optional[str] = None,
) -> Path:
    report = build_report(events, report_date=report_date)
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / f"df-146-{report['report_date']}.json"
    target_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return target_path


__all__ = ["UsageEvent", "aggregate_usage", "build_report", "write_report"]
# [CRUX-MK]
