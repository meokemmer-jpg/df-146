import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
# [CRUX-MK]
import importlib

m = importlib.import_module("146")
aggregate_usage = m.aggregate_usage
build_report = m.build_report
write_report = m.write_report


def test_aggregate_usage_and_report_output(tmp_path):
    events = [
        {
            "hotel_id": "hotel-a",
            "customer_id": "cust-1",
            "api_calls": 3,
            "tokens": 1500,
            "cost_per_1k_tokens": "0.50",
        },
        {
            "hotel_id": "hotel-a",
            "customer_id": "cust-1",
            "api_calls": 2,
            "tokens": 500,
            "cost_per_1k_tokens": "0.50",
        },
        {
            "hotel_id": "hotel-b",
            "customer_id": "cust-2",
            "api_calls": 7,
            "tokens": 2500,
            "cost_per_1k_tokens": "1.20",
        },
    ]

    summary = aggregate_usage(events)

    assert summary["billing_mode"] == "read_only"
    assert summary["api_calls_per_hotel"] == {"hotel-a": 5, "hotel-b": 7}
    assert summary["token_burn_per_customer"] == {"cust-1": 2000, "cust-2": 2500}
    assert summary["cost_per_customer"] == {"cust-1": "1.00", "cust-2": "3.00"}
    assert summary["totals"] == {
        "events": 3,
        "api_calls": 12,
        "tokens": 4500,
        "cost": "4.00",
    }

    report = build_report(events, report_date="2026-06-09")
    assert report["report_date"] == "2026-06-09"

    output_path = write_report(events, report_dir=tmp_path, report_date="2026-06-09")
    assert output_path.name == "df-146-2026-06-09.json"
    assert output_path.exists()

    content = output_path.read_text(encoding="utf-8")
    assert '"billing_mode": "read_only"' in content
    assert '"hotel-a": 5' in content
    assert '"cust-2": "3.00"' in content


def test_negative_values_raise():
    bad_events = [
        {
            "hotel_id": "hotel-a",
            "customer_id": "cust-1",
            "api_calls": -1,
            "tokens": 100,
            "cost_per_1k_tokens": "0.25",
        }
    ]

    try:
        aggregate_usage(bad_events)
    except ValueError as exc:
        assert "non-negative" in str(exc)
    else:
        raise AssertionError("aggregate_usage should reject negative values")

