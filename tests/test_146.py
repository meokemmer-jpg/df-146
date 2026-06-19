import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
# [CRUX-MK]
import importlib

m146 = importlib.import_module("146")
aggregate_usage = m146.aggregate_usage
build_report = m146.build_report
write_report = m146.write_report


def test_aggregate_usage_and_write_report(tmp_path):
    events = [
        {
            "hotel_id": "hotel-a",
            "customer_id": "cust-1",
            "api_calls": 3,
            "tokens": 1500,
            "unit_cost_per_1k_tokens": 0.02,
        },
        {
            "hotel_id": "hotel-a",
            "customer_id": "cust-2",
            "api_calls": 2,
            "tokens": 500,
            "unit_cost_per_1k_tokens": 0.02,
        },
        {
            "hotel_id": "hotel-b",
            "customer_id": "cust-1",
            "api_calls": 1,
            "tokens": 250,
            "unit_cost_per_1k_tokens": 0.04,
        },
    ]

    aggregated = aggregate_usage(events)

    assert aggregated["summary"]["hotel_count"] == 2
    assert aggregated["summary"]["customer_count"] == 2
    assert aggregated["summary"]["total_api_calls"] == 6
    assert aggregated["summary"]["total_tokens"] == 2250
    assert aggregated["summary"]["total_cost"] == 0.05
    assert aggregated["summary"]["auto_billing"] is False

    assert aggregated["hotels"]["hotel-a"]["api_calls"] == 5
    assert aggregated["hotels"]["hotel-a"]["tokens"] == 2000
    assert aggregated["hotels"]["hotel-a"]["customer_count"] == 2
    assert aggregated["hotels"]["hotel-a"]["cost"] == 0.04

    assert aggregated["hotels"]["hotel-b"]["api_calls"] == 1
    assert aggregated["hotels"]["hotel-b"]["tokens"] == 250
    assert aggregated["hotels"]["hotel-b"]["customer_count"] == 1
    assert aggregated["hotels"]["hotel-b"]["cost"] == 0.01

    assert aggregated["customers"]["cust-1"]["api_calls"] == 4
    assert aggregated["customers"]["cust-1"]["tokens"] == 1750
    assert aggregated["customers"]["cust-1"]["hotel_count"] == 2
    assert aggregated["customers"]["cust-1"]["cost"] == 0.04

    assert aggregated["customers"]["cust-2"]["api_calls"] == 2
    assert aggregated["customers"]["cust-2"]["tokens"] == 500
    assert aggregated["customers"]["cust-2"]["hotel_count"] == 1
    assert aggregated["customers"]["cust-2"]["cost"] == 0.01

    report = build_report(events, report_date="2026-06-18")
    assert report["report_date"] == "2026-06-18"
    assert report["report_type"] == "read_only_usage_report"

    report_path = write_report(events, output_dir=tmp_path, report_date="2026-06-18")
    assert report_path.name == "df-146-2026-06-18.json"
    assert report_path.exists()

    content = report_path.read_text(encoding="utf-8")
    assert '"auto_billing": false' in content
    assert '"report_type": "read_only_usage_report"' in content
