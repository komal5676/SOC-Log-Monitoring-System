
from datetime import datetime, timedelta

from modules.risk_engine import (
    calculate_risk,
    calculate_incident_score,
    get_risk_level,
)


HOST = "TEST-WINDOWS-PC"
USER = "test_user"
BASE_TIME = datetime(2026, 10, 20, 10, 0, 0)


def make_event(event_id, seconds, severity="Medium"):
    """Create a synthetic event for risk testing."""
    return {
        "record_id": 2000 + seconds,
        "event_id": event_id,
        "hostname": HOST,
        "user": USER,
        "time": (
            BASE_TIME + timedelta(seconds=seconds)
        ).strftime("%Y-%m-%d %H:%M:%S"),
        "name": "Synthetic test event",
        "severity": severity,
    }


def check(name, actual, expected):
    passed = actual == expected
    print(f"\nTest: {name}")
    print(f"Expected: {expected}")
    print(f"Actual:   {actual}")
    print(f"Result:   {'PASS' if passed else 'FAIL'}")
    return passed


def main():
    results = []

    # TEST 1: Three failed logins -> +5 repetition points.
    events = [
        make_event(4625, 0),
        make_event(4625, 30),
        make_event(4625, 60),
    ]
    summary = calculate_risk(events, [])
    results.append(check(
        "3 failed logins: score is 40 + 5",
        summary["events"][-1]["risk_score"],
        45,
    ))

    # TEST 2: Five failed logins -> +10 repetition points.
    events = [
        make_event(4625, i * 30)
        for i in range(5)
    ]
    summary = calculate_risk(events, [])
    results.append(check(
        "5 failed logins: score is 40 + 10",
        summary["events"][-1]["risk_score"],
        50,
    ))

    # TEST 3: Ten failed logins -> +15 repetition points.
    events = [
        make_event(4625, i * 30)
        for i in range(10)
    ]
    summary = calculate_risk(events, [])
    results.append(check(
        "10 failed logins: score is 40 + 15",
        summary["events"][-1]["risk_score"],
        55,
    ))

    # TEST 4: Critical and High incident scores.
    results.append(check(
        "Critical incident score",
        calculate_incident_score({"severity": "Critical"}),
        90,
    ))

    results.append(check(
        "High incident score",
        calculate_incident_score({"severity": "High"}),
        70,
    ))

    # TEST 5: Info events remain score 0.
    info_event = make_event(9999, 0, severity="Info")
    summary = calculate_risk([info_event], [])

    results.append(check(
        "Info event score",
        summary["events"][0]["risk_score"],
        0,
    ))

    results.append(check(
        "Info event risk level",
        summary["events"][0]["risk_level"],
        "Info",
    ))

    results.append(check(
        "Overall risk for Info-only activity",
        summary["overall_score"],
        0,
    ))

    # TEST 6: Overall risk is the highest event/incident score.
    events = [
        make_event(4624, 0, severity="High"),
    ]
    incidents = [
        {
            "type": "pattern",
            "name": "Synthetic Critical incident",
            "severity": "Critical",
            "event_count": 1,
            "events": [],
        }
    ]
        # TEST: Privilege assignment has a lower standalone risk score.
    privilege_event = make_event(
        4672, 0, severity="High"
    )
    summary = calculate_risk([privilege_event], [])

    results.append(check(
        "4672 standalone event score",
        summary["events"][0]["risk_score"],
        20,
    ))
    summary = calculate_risk(events, incidents)

    results.append(check(
        "Overall score uses highest risk",
        summary["overall_score"],
        90,
    ))

    results.append(check(
        "Overall risk level is Critical",
        summary["overall_level"],
        "Critical",
    ))

    print("\n" + "=" * 42)
    print(f"Tests passed: {sum(results)}/{len(results)}")
    print("=" * 42)

    if not all(results):
        raise SystemExit("One or more risk-scoring tests failed.")


if __name__ == "__main__":
    main()

