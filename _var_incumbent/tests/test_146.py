import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
# [CRUX-MK]
# Hinweis: `from 146 import ...` ist in Python-Syntax ungueltig.
# Fuer einen grün laufenden pytest-Test wird das Modul daher per importlib geladen.

import importlib
import json


m146 = importlib.import_module("146")
aggregate_usage = m146.aggregate_usage
build_report = m146.build_report
write_report = m146.write_report


def test_usage_aggregation_and_report_write(tmp_path):
    events = [
        {"hotel_id": "hotel-a", "customer_id": "cust-1", "api_calls": 3, "tokens": 1200, "cost_eur": "0.30"},
        {"hotel_id": "hotel-a", "customer_id": "cust-1", "api_calls": 2, "tokens": 800, "cost_eur": "0.20"},
        {"hotel_id": "hotel-b", "customer_id": "cust-2", "api_calls": 5, "tokens": 2500, "cost_eur": "0.75"},
    ]

    aggregated = aggregate_usage(events)
    assert aggregated["billing_mode"] == "report_only"
    assert aggregated["hotels"]["hotel-a"]["api_calls"] == 5
    assert aggregated["hotels"]["hotel-b"]["api_calls"] == 5
    assert aggregated["customers"]["cust-1"]["token_burn"] == 2000
    assert aggregated["customers"]["cust-1"]["cost_eur"] == "0.50"
    assert aggregated["customers"]["cust-2"]["token_burn"] == 2500
    assert aggregated["customers"]["cust-2"]["cost_eur"] == "0.75"
    assert aggregated["summary"] == {
        "total_api_calls": 10,
        "total_tokens": 4500,
        "total_cost_eur": "1.25",
        "hotel_count": 2,
        "customer_count": 2,
    }

    report = build_report(events, report_date="2026-06-14")
    assert report["report_date"] == "2026-06-14"

    output_path = write_report(events, output_dir=tmp_path, report_date="2026-06-14")
    assert output_path.name == "df-146-2026-06-14.json"
    assert output_path.exists()

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload == report


def test_negative_values_raise_value_error():
    bad_events = [
        {"hotel_id": "hotel-a", "customer_id": "cust-1", "api_calls": -1, "tokens": 10, "cost_eur": "0.01"}
    ]

    try:
        aggregate_usage(bad_events)
    except ValueError as exc:
        assert "non-negative" in str(exc)
    else:
        raise AssertionError("ValueError was not raised for negative usage values")

