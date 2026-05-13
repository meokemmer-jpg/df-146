"""DF-146 engine for 9dots API usage aggregation."""

import re
import os
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import datetime, timezone


DF_DIR = Path(__file__).parent
LOCK_DIR = Path("/tmp/df-146.lock")
DF_ID = "146"
DECISION_KEYWORDS_REGEX = re.compile(
    r"\b(entscheid[a-z]*|empfehl(?:e|en|t|st)|sollt(?:e|en|est)|recommend[a-z]*|decid[a-z]*|advis[a-z]*|propos[a-z]*)\b",
    re.IGNORECASE,
)


@dataclass
class TrackerOutput:
    welle: str = "25"
    df: str = "DF-146"
    iso_timestamp: str = ""
    source: str = "mock"
    api_calls_total: int = 0
    top_endpoints: list = field(default_factory=list)
    error_rate_pct: float = 0
    p99_latency_ms: float = 0
    throttled_clients: list = field(default_factory=list)


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _file_stable(path, min_age_sec=300) -> bool:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return False
    try:
        age = time.time() - p.stat().st_mtime
    except OSError:
        return False
    return age >= min_age_sec


def acquire_lock_with_identity() -> bool:
    stale_after_sec = 6 * 60 * 60

    try:
        LOCK_DIR.mkdir(mode=0o700)
    except FileExistsError:
        try:
            age = time.time() - LOCK_DIR.stat().st_mtime
        except OSError:
            return False

        if age <= stale_after_sec:
            return False

        try:
            for child in LOCK_DIR.iterdir():
                if child.is_file() or child.is_symlink():
                    child.unlink()
                elif child.is_dir():
                    child.rmdir()
            LOCK_DIR.rmdir()
            LOCK_DIR.mkdir(mode=0o700)
        except OSError:
            return False
    except OSError:
        return False

    identity = {
        "df_id": DF_ID,
        "pid": os.getpid(),
        "created_at": iso_now(),
        "cwd": str(Path.cwd()),
    }

    try:
        (LOCK_DIR / "identity.json").write_text(
            json.dumps(identity, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    except OSError:
        release_lock()
        return False

    return True


def release_lock() -> None:
    try:
        identity = LOCK_DIR / "identity.json"
        if identity.exists():
            identity.unlink()
        LOCK_DIR.rmdir()
    except OSError:
        pass


def k17_pre_action_verification(anchors) -> dict:
    missing = []
    for anchor in anchors or []:
        if not Path(anchor).exists():
            missing.append(str(anchor))

    env_tag = os.environ.get("DF_146_ENV_TAG", "default")
    return {
        "ok": len(missing) == 0,
        "missing_anchors": missing,
        "env_tag": env_tag,
    }


def _is_real_api_enabled() -> bool:
    value = os.environ.get("DF_146_REAL_API_ENABLED", "false")
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def scan_output_for_decision_keywords(text) -> list:
    if text is None:
        return []
    return sorted({match.group(0) for match in DECISION_KEYWORDS_REGEX.finditer(str(text))})


def assert_no_decision_keywords(output) -> None:
    if isinstance(output, str):
        text = output
    else:
        text = json.dumps(output, ensure_ascii=False, sort_keys=True)

    hits = scan_output_for_decision_keywords(text)
    if hits:
        raise ValueError("Q_0/K_0 blocked terms found: " + ", ".join(hits))


def collect_tracker_output() -> TrackerOutput:
    now = iso_now()

    if _is_real_api_enabled():
        data_path = Path(os.environ.get("DF_146_REAL_API_FILE", DF_DIR / "df-146-input.json"))
        if not _file_stable(data_path, min_age_sec=300):
            raise ValueError("real api input file is missing or not stable")

        raw = json.loads(data_path.read_text(encoding="utf-8"))
        output = TrackerOutput(
            iso_timestamp=now,
            source="real",
            api_calls_total=int(raw.get("api_calls_total", 0)),
            top_endpoints=list(raw.get("top_endpoints", [])),
            error_rate_pct=float(raw.get("error_rate_pct", 0)),
            p99_latency_ms=float(raw.get("p99_latency_ms", 0)),
            throttled_clients=list(raw.get("throttled_clients", [])),
        )
    else:
        output = TrackerOutput(
            iso_timestamp=now,
            source="mock",
            api_calls_total=18420,
            top_endpoints=[
                {"endpoint": "/v1/events", "calls": 7420},
                {"endpoint": "/v1/usage", "calls": 5110},
                {"endpoint": "/v1/accounts", "calls": 2840},
                {"endpoint": "/v1/health", "calls": 1830},
                {"endpoint": "/v1/tokens", "calls": 1220},
            ],
            error_rate_pct=1.7,
            p99_latency_ms=842.0,
            throttled_clients=[
                {"client_id": "client_017", "throttles": 42},
                {"client_id": "client_044", "throttles": 18},
            ],
        )

    assert_no_decision_keywords(asdict(output))
    return output


def main() -> int:
    if not acquire_lock_with_identity():
        return 3

    try:
        anchors_env = os.environ.get("DF_146_ANCHORS", "")
        anchors = [item for item in anchors_env.split(os.pathsep) if item]
        pav = k17_pre_action_verification(anchors)
        if not pav.get("ok"):
            return 3

        tracker_output = collect_tracker_output()
        report = asdict(tracker_output)
        report["k17_pre_action_verification"] = pav

        assert_no_decision_keywords(report)

        reports_dir = DF_DIR / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        date_tag = datetime.now(timezone.utc).date().isoformat()
        report_path = reports_dir / f"df-146-{date_tag}.json"
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return 0
    except Exception as exc:
        sys.stderr.write(f"DF-146 failed: {exc}\n")
        return 3
    finally:
        release_lock()


if __name__ == "__main__":
    sys.exit(main())