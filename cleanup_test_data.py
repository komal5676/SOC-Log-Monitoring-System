import os
import sqlite3

# ============================================================
# SENTINELX TEST DATA CLEANUP
# ============================================================
# Removes only the test hosts used during SentinelX testing.
# Real endpoint data such as "komal" is NOT removed.

PROJECT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DB_PATH = os.path.join(
    PROJECT_DIR,
    "database.db"
)

TEST_HOSTS = (
    "SOC-TEST-PC",
    "SOC-TEST-ACCOUNT",
)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

print("SentinelX test-data cleanup")
print("-" * 50)

# Show what will be removed first.
placeholders = ",".join("?" for _ in TEST_HOSTS)

cursor.execute(
    f"""
    SELECT hostname, COUNT(*)
    FROM events
    WHERE hostname IN ({placeholders})
    GROUP BY hostname
    """,
    TEST_HOSTS
)

rows = cursor.fetchall()

if not rows:
    print("No matching test-host events were found.")
else:
    total = sum(row[1] for row in rows)

    for hostname, count in rows:
        print(f"{hostname}: {count} events")

    print(f"Total test events to remove: {total}")

    cursor.execute(
        f"""
        DELETE FROM events
        WHERE hostname IN ({placeholders})
        """,
        TEST_HOSTS
    )

    deleted = cursor.rowcount
    conn.commit()

    print(f"Deleted: {deleted} events")

conn.close()

print("-" * 50)
print("Cleanup complete.")
print("Only the known SentinelX test hosts were targeted.")

