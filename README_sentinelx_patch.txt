SentinelX pagination + full-database search patch

Files in this patch:
- app.py
- modules/database.py
- templates/logs.html
- templates/soc.html
- templates/search.html (new/replacement template for full-database search pagination)

Install:
1. Stop Flask (Ctrl+C).
2. Back up your current app.py, modules/database.py, templates/logs.html, templates/soc.html, and templates/search.html.
3. Extract this ZIP into your existing SOC_Project folder, preserving folders and allowing overwrite.
4. Do NOT delete database.db; existing events are preserved.
5. Run: python app.py
6. Open /logs, /search, and /soc. Try 25/50/100 rows per page and use Next/Previous.

Notes:
- SQLite performs search across stored fields and counts all matches.
- The event feed is paginated. Correlation/risk analysis remains bounded to the latest 5,000 events for predictable response time; the event feed can browse older stored events too.
- Flask debug mode remains enabled to preserve your current local-development behavior. Do not expose the development server to an untrusted network.
- This patch does not change event collection checkpoints or add retention/cleanup yet.
