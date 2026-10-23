
from types import SimpleNamespace

from modules.security_monitor import _extract_username


def make_event(string_inserts=None, xml=None):
    """Create a fake Windows event record."""
    return SimpleNamespace(
        StringInserts=string_inserts or [],
        Xml=xml,
    )


def run_test(name, event, event_id, expected):
    actual = _extract_username(event, event_id)
    passed = actual == expected

    print(f"\nTest: {name}")
    print(f"Expected username: {expected}")
    print(f"Actual username:   {actual}")
    print(f"Result: {'PASS' if passed else 'FAIL'}")

    return passed


def main():
    results = []

    # Test 1: Event 4624, named XML fields take priority.
    xml_4624 = """
    <Event>
      <EventData>
        <Data Name="TargetUserName">alice</Data>
        <Data Name="SubjectUserName">SYSTEM</Data>
      </EventData>
    </Event>
    """
    results.append(run_test(
        "4624 XML target account",
        make_event(["SYSTEM", "alice"], xml_4624),
        4624,
        "alice",
    ))

    # Test 2: Event 4625, failed-login target account.
    xml_4625 = """
    <Event>
      <EventData>
        <Data Name="TargetUserName">bob</Data>
        <Data Name="SubjectUserName">SYSTEM</Data>
      </EventData>
    </Event>
    """
    results.append(run_test(
        "4625 XML target account",
        make_event(["SYSTEM", "bob"], xml_4625),
        4625,
        "bob",
    ))

    # Test 3: Event 4672, account receiving special privileges.
    xml_4672 = """
    <Event>
      <EventData>
        <Data Name="SubjectUserName">administrator</Data>
      </EventData>
    </Event>
    """
    results.append(run_test(
        "4672 XML subject account",
        make_event(["administrator"], xml_4672),
        4672,
        "administrator",
    ))

    # Test 4: Event 4688, process creator.
    xml_4688 = """
    <Event>
      <EventData>
        <Data Name="SubjectUserName">alice</Data>
        <Data Name="TargetUserName">SYSTEM</Data>
      </EventData>
    </Event>
    """
    results.append(run_test(
        "4688 XML subject account",
        make_event(["alice", "SYSTEM"], xml_4688),
        4688,
        "alice",
    ))

    # Test 5: Fallback for 4624 using current index mapping.
    results.append(run_test(
        "4624 StringInserts fallback",
        make_event(["SYSTEM", "alice", "DOMAIN", "0x123"]),
        4624,
        "alice",
    ))

    # Test 6: Fallback for 4625 using current index mapping.
    results.append(run_test(
        "4625 StringInserts fallback",
        make_event(["SYSTEM", "DOMAIN", "0x123", "unused",
                    "unused", "bob"]),
        4625,
        "bob",
    ))

    # Test 7: Missing account should safely return Unknown.
    results.append(run_test(
        "Missing username",
        make_event([]),
        4672,
        "Unknown",
    ))

    print("\n" + "=" * 40)
    print(f"Tests passed: {sum(results)}/{len(results)}")
    print("=" * 40)


if __name__ == "__main__":
    main()
