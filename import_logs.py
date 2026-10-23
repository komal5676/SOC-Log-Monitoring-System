import sqlite3

# Connect to the database
conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# Open the log file
with open("logs.txt", "r") as file:
    logs = file.readlines()

# Insert each log into the database
for log in logs:
    cursor.execute(
        "INSERT INTO logs (log_message) VALUES (?)",
        (log.strip(),)
    )

# Save changes and close
conn.commit()
conn.close()

print("Logs imported successfully!")
