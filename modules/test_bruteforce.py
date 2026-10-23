
from datetime import datetime, timedelta

from modules.correlation_engine import correlate_events


HOST = "TEST-WINDOWS-PC"
USER = "test_user"
BASE_TIME = datetime(2026, 10, 20, 10, 0, 0)


def make_event(event_id, seconds, hostname=HOST, username=USER):
    """Create a synthetic Windows event for testing."""
    return {
        "record_id": 1000 + seconds + event_id,
        "event_id": event_id,
        "hostname": hostname,
        "host": hostname,
        "user": username,
        "time": (
            BASE_TIME + timedelta(seconds=seconds)
        ).strftime("%Y-%m-%d %H:%M:%S"),
        "name": {
            4625: "Failed Login",
            4624: "Successful Login",
        }.get(event_id, "Windows Event"),
        "severity": "Medium",
        "logon_id": "0x12345",
    }


def run_test(name, events, expected_detection):
    """Run correlation and check for a brute-force incident."""
    incidents = correlate_events(events)

    brute_force = [
        incident
        for incident in incidents
        if "Brute Force" in incident.get("name", "")
    ]

    detected = bool(brute_force)
    passed = detected == expected_detection

    print(f"\nTest: {name}")
    print(f"Expected detection: {expected_detection}")
    print(f"Actual detection:   {detected}")
    print(f"Result:             {'PASS' if passed else 'FAIL'}")

    for incident in brute_force:
        print(f"Incident: {incident.get('name')}")
        print(f"Severity: {incident.get('severity')}")
        print(f"Event count: {incident.get('event_count')}")
        print(
            "Event IDs:",
            [event.get("event_id") for event in incident.get("events", [])],
        )

    return passed


def main():
    tests = []

    # Test 1: Three failed logins followed by success,
    # same host and user, within five minutes.
    tests.append(run_test(
        "Three failures followed by success",
        [
            make_event(4625, 0),
            make_event(4625, 30),
            make_event(4625, 60),
            make_event(4624, 90),
        ],
        True,
    ))

    # Test 2: Only two failures before success.
    tests.append(run_test(
        "Only two failures followed by success",
        [
            make_event(4625, 0),
            make_event(4625, 30),
            make_event(4624, 60),
        ],
        False,
    ))

    # Test 3: Three failures but no successful login.
    tests.append(run_test(
        "Failures without a successful login",
        [
            make_event(4625, 0),
            make_event(4625, 30),
            make_event(4625, 60),
        ],
        False,
    ))

    # Test 4: Failures and success on different hosts.
    tests.append(run_test(
        "Events from different hosts",
        [
            make_event(4625, 0),
            make_event(4625, 30),
            make_event(4625, 60),
            make_event(4624, 90, hostname="OTHER-PC"),
        ],
        False,
    ))

    # Test 5: Success occurs outside the five-minute window.
    tests.append(run_test(
        "Success outside the correlation window",
        [
            make_event(4625, 0),
            make_event(4625, 30),
            make_event(4625, 60),
            make_event(4624, 6 * 60),
        ],
        False,
    ))

    print("\n" + "=" * 40)
    print(f"Tests passed: {sum(tests)}/{len(tests)}")
    print("=" * 40)

    if not all(tests):
        raise SystemExit(
            "One or more tests failed. Review the correlation logic."
        )


if __name__ == "__main__":
    main()
