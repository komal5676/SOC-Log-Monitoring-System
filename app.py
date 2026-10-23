
from asyncio import events
from flask import redirect, url_for
from flask import Flask, render_template, request, jsonify, abort , Response
from functools import wraps
from config import API_KEY, ALERT_RISK_THRESHOLD
from modules.alert_history import (
    claim_new_alerts,
    _incident_fingerprint,
)
from modules.database import (
    read_logs,
    insert_events,
    read_events,
    count_events,
    search_events,
    count_search_events,
    list_hostnames,
    record_heartbeat,
    list_endpoints,
    get_incident_workflow,
    save_incident_workflow,
)
from modules.security_monitor import get_security_events
from modules.correlation_engine import correlate_events
from modules.risk_engine import calculate_risk
from modules.validation import validate_payload
from modules.alerting import check_and_alert, get_recommended_action
from modules.logger import get_logger
import time
import csv
import io

app = Flask(__name__)
logger = get_logger("app")


# ============================================================
# API KEY DECORATOR
# ============================================================

def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-API-Key")

        if key != API_KEY:
            logger.warning(
                "Rejected /ingest request with invalid API key from %s",
                request.remote_addr,
            )
            return jsonify({"error": "Unauthorized"}), 401

        return f(*args, **kwargs)

    return wrapper


# ============================================================
# MAIN DASHBOARD
# ============================================================

@app.route("/")
def home():
    logs = read_logs()
    events = get_security_events()

    total_logs = len(logs)
    success = sum("Login Success" in log for log in logs)
    failed = sum("Failed Login" in log for log in logs)

    alert = (
        "Possible Brute Force Attack Detected"
        if failed >= 5 else ""
    )

    return render_template(
        "index.html",
        total=total_logs,
        success=success,
        failed=failed,
        alert=alert,
        events=events,
    )


# ============================================================
# LOGS
# ============================================================

@app.route("/logs")
def logs():
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1

    try:
        page_size = int(request.args.get("page_size", 50))
    except (TypeError, ValueError):
        page_size = 50

    if page_size not in {25, 50, 100}:
        page_size = 50

    hostname_filter = request.args.get("host", "").strip() or None
    total_events = count_events(hostname=hostname_filter)
    total_pages = max(1, (total_events + page_size - 1) // page_size)
    page = min(page, total_pages)

    events = read_events(
        hostname=hostname_filter,
        limit=page_size,
        offset=(page - 1) * page_size,
    )

    return render_template(
        "logs.html",
        events=events,
        hosts=list_hostnames(),
        hostname_filter=hostname_filter or "",
        total_events=total_events,
        page=page,
        total_pages=total_pages,
        page_size=page_size,
    )
#
# duplicate_alerts function is used to remove duplicate alerts based on their identity and event evidence. It creates a unique identity for each incident by considering its type, name, hostname, user, and sorted event keys. If an incident with the same identity has already been encountered, it is skipped; otherwise, it is added to the result list. This ensures that only unique incidents are retained in the final output.
#

def deduplicate_alerts(incidents):
    """Remove alerts with identical identity and event evidence."""

    unique = {}
    result = []

    for incident in incidents:
        event_keys = []

        for event in incident.get("events", []):
            event_keys.append((
                str(event.get("record_id", event.get("id", ""))),
                str(event.get("event_id", "")),
                str(event.get("time", event.get("timestamp", ""))),
            ))

        identity = (
            incident.get("type", ""),
            incident.get("name", ""),
            str(incident.get("hostname", incident.get("host", ""))).lower(),
            str(incident.get("user", "")).lower(),
            tuple(sorted(event_keys)),
        )

        if identity in unique:
            continue

        unique[identity] = True
        result.append(incident)

    return result
# incident workflow

@app.route("/incident-workflow", methods=["POST"])
def update_incident_workflow():
    incident_key = request.form.get("incident_key", "").strip()
    status = request.form.get("status", "").strip()
    notes = request.form.get("notes", "")

    allowed_statuses = {
        "New",
        "Investigating",
        "Resolved",
        "False Positive",
    }

    if not incident_key:
        abort(400, description="Missing incident key.")

    if status not in allowed_statuses:
        abort(400, description="Invalid workflow status.")

    if len(notes) > 5000:
        abort(400, description="Notes must be 5000 characters or fewer.")

    # Rebuild the current incident list and validate the submitted key.
    events = read_events(limit=5000)
    incidents = deduplicate_alerts(correlate_events(events))
    summary = calculate_risk(events, incidents)

    valid_keys = {
        _incident_fingerprint(incident)
        for incident in summary["incidents"]
        if isinstance(incident, dict)
        and incident.get("risk_score", 0) > 0
    }

    if incident_key not in valid_keys:
        abort(404, description="Incident not found or its evidence changed.")

    save_incident_workflow(incident_key, status, notes)

    return redirect(url_for("alerts", workflow_saved="1"))

# ============================================================
# ALERTS
# ============================================================


@app.route("/alerts")
def alerts():
    hostname_filter = request.args.get("hostname") or None

    # Load events for the requested host or the latest 5,000 events.
    if hostname_filter:
        events = read_events(hostname=hostname_filter, limit=5000)
    else:
        events = read_events(limit=5000)

        # Include test-host events for the demonstration.
        test_events = read_events(
            hostname="SOC-TEST-ACCOUNT",
            limit=100,
        )

        existing_ids = {
            (
                e.get("hostname"),
                e.get("record_id"),
                e.get("event_id"),
            )
            for e in events
        }

        for event in test_events:
            event_id = (
                event.get("hostname"),
                event.get("record_id"),
                event.get("event_id"),
            )

            if event_id not in existing_ids:
                events.append(event)
                existing_ids.add(event_id)

    # Correlate events into incidents.
    incidents = correlate_events(events)

    print("\n===== ALERT DEBUG =====")
    print("Total events:", len(events))
    print("Incidents before deduplication:", len(incidents))

    for i, incident in enumerate(incidents):
        if "Repeated Event ID 4688" in incident.get("name", ""):
            print(
                "Incident:", i,
                "| Host:", incident.get("hostname"),
                "| User:", incident.get("user"),
                "| Start:", incident.get("start_time"),
                "| End:", incident.get("end_time"),
                "| Event records:", [
                    event.get("record_id")
                    for event in incident.get("events", [])
                ],
            )

    print("=======================\n")

    # Remove incidents with identical underlying evidence.
    incidents = deduplicate_alerts(incidents)

    # Calculate incident risk.
    summary = calculate_risk(events, incidents)
    alerts_data = []

    for incident_index, incident in enumerate(summary["incidents"]):
        incident["recommended_action"] = get_recommended_action(
            incident
        )

        if incident.get("risk_score", 0) > 0:
            incident["incident_index"] = incident_index

            # Create a persistent key for this incident's evidence.
            incident["incident_key"] = _incident_fingerprint(
                incident
            )

            # Load the analyst's saved investigation workflow.
            workflow = get_incident_workflow(
                incident["incident_key"]
            )

            incident["workflow_status"] = workflow["status"]
            incident["workflow_notes"] = workflow["notes"]
            incident["workflow_updated_at"] = workflow["updated_at"]

            alerts_data.append(incident)

    # Render once, after processing all incidents.
    return render_template(
        "alerts.html",
        alerts=alerts_data,
        overall_score=summary["overall_score"],
        overall_level=summary["overall_level"],
    )

# ============================================================
# EXPORT INCIDENT REPORTS TO CSV
# ============================================================

@app.route("/alerts/export")
def export_alerts_csv():
    # Use the same analysis pipeline as the Alerts page.
    events = read_events(limit=5000)
    incidents = correlate_events(events)
    incidents = deduplicate_alerts(incidents)

    summary = calculate_risk(events, incidents)

    output = io.StringIO(newline="")
    writer = csv.writer(output)

    # Report columns.
    writer.writerow([
        "Incident Name",
        "Severity",
        "Risk Score",
        "Risk Level",
        "Hostname",
        "Username",
        "Event Count",
        "Start Time",
        "End Time",
        "Event Timeline",
        "Recommended Action",
    ])

    def safe_csv_value(value):
        """Reduce spreadsheet formula-injection risk."""
        value = "" if value is None else str(value)
        if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
            return "'" + value
        return value

    for incident in summary["incidents"]:
        # Include only incidents with a meaningful risk score,
        # matching the existing Alerts page.
        if incident.get("risk_score", 0) <= 0:
            continue

        timeline = []
        for event in incident.get("events", []):
            event_id = event.get("event_id", "Unknown")
            event_name = event.get("name", "Unknown event")
            event_time = event.get("time", "Unknown time")

            timeline.append(
                f"{event_time}: Event ID {event_id} - {event_name}"
            )

        recommended_action = get_recommended_action(incident)

        writer.writerow([
            safe_csv_value(incident.get("name")),
            safe_csv_value(incident.get("severity")),
            incident.get("risk_score", 0),
            safe_csv_value(incident.get("risk_level", "")),
            safe_csv_value(incident.get("hostname")),
            safe_csv_value(incident.get("user")),
            incident.get("event_count", len(incident.get("events", []))),
            safe_csv_value(incident.get("start_time")),
            safe_csv_value(incident.get("end_time")),
            safe_csv_value(" | ".join(timeline)),
            safe_csv_value(recommended_action),
        ])

    response = Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
    )
    response.headers["Content-Disposition"] = (
        'attachment; filename="sentinelx_incident_report.csv"'
    )
    response.headers["Cache-Control"] = "no-store"

    return response


# ============================================================
# SEARCH
# ============================================================


@app.route("/search", methods=["GET", "POST"])
def search():
    keyword = request.values.get("keyword", "").strip()
    hostname_filter = request.values.get("host", "").strip() or None
    event_id_filter = request.values.get("event_id", "").strip() or None
    severity_filter = request.values.get("severity", "").strip() or None
    username_filter = request.values.get("username", "").strip() or None
    start_time_filter = request.values.get("start_time", "").strip() or None
    end_time_filter = request.values.get("end_time", "").strip() or None

    valid_severities = {"Critical", "High", "Medium", "Low", "Info"}
    if severity_filter not in valid_severities:
        severity_filter = None

    if event_id_filter and not event_id_filter.isdigit():
        event_id_filter = None

    # Validate date/time filters.
    from datetime import datetime

    def valid_datetime(value):
        if not value:
            return None
        try:
            return datetime.strptime(
                value, "%Y-%m-%dT%H:%M"
            ).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None

    start_time_filter = valid_datetime(start_time_filter)
    end_time_filter = valid_datetime(end_time_filter)

    try:
        page = max(1, int(request.values.get("page", 1)))
    except (TypeError, ValueError):
        page = 1

    try:
        page_size = int(request.values.get("page_size", 50))
    except (TypeError, ValueError):
        page_size = 50

    if page_size not in {25, 50, 100}:
        page_size = 50

    filters = {
        "hostname": hostname_filter,
        "event_id": event_id_filter,
        "severity": severity_filter,
        "username": username_filter,
        "start_time": start_time_filter,
        "end_time": end_time_filter,
    }

    has_filters = bool(
        keyword or any(filters.values())
    )

    total_results = (
        count_search_events(keyword, **filters)
        if has_filters else 0
    )

    total_pages = max(
        1, (total_results + page_size - 1) // page_size
    )
    page = min(page, total_pages)

    results = (
        search_events(
            keyword,
            limit=page_size,
            offset=(page - 1) * page_size,
            **filters,
        )
        if has_filters else []
    )

    return render_template(
        "search.html",
        results=results,
        keyword=keyword,
        hosts=list_hostnames(),
        hostname_filter=hostname_filter or "",
        event_id_filter=event_id_filter or "",
        severity_filter=severity_filter or "",
        username_filter=username_filter or "",
        start_time_filter=request.values.get("start_time", ""),
        end_time_filter=request.values.get("end_time", ""),
        total_results=total_results,
        page=page,
        total_pages=total_pages,
        page_size=page_size,
        has_filters=has_filters,
    )


# ============================================================
# REPORT
# ============================================================

@app.route("/report")
def report():
    events = read_events(limit=1000)
    daily_data = {}

    for event in events:
        event_time = event.get("time", "")
        if not event_time:
            continue

        date_value = str(event_time)[:10]

        if date_value not in daily_data:
            daily_data[date_value] = {
                "total": 0,
                "counts": {
                    "Critical": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0,
                    "Info": 0,
                },
            }

        daily_data[date_value]["total"] += 1
        severity = event.get("severity", "Info")

        if severity in daily_data[date_value]["counts"]:
            daily_data[date_value]["counts"][severity] += 1

    sorted_dates = sorted(daily_data.keys(), reverse=True)[:14]
    sorted_dates.reverse()

    days = [
        {
            "date": date_value,
            "total": daily_data[date_value]["total"],
            "counts": daily_data[date_value]["counts"],
        }
        for date_value in sorted_dates
    ]

    max_total = max((day["total"] for day in days), default=0)

    technique_data = {}

    for event in events:
        mitre_id = event.get("mitre_id")
        if not mitre_id:
            continue

        if mitre_id not in technique_data:
            technique_data[mitre_id] = {
                "mitre_id": mitre_id,
                "mitre_tactic": event.get("mitre_tactic") or "Unknown",
                "count": 0,
            }

        technique_data[mitre_id]["count"] += 1

    techniques = sorted(
        technique_data.values(),
        key=lambda item: item["count"],
        reverse=True,
    )

    return render_template(
        "report.html",
        days=days,
        max_total=max_total,
        techniques=techniques,
    )


# ============================================================
# SECURE EVENT INGESTION
# ============================================================



@app.route("/ingest", methods=["POST"])
@require_api_key
def ingest():
    request_start = time.perf_counter()

    # 1. Validate incoming data
    stage_start = time.perf_counter()
    data = request.get_json(silent=True)
    is_valid, error = validate_payload(data)

    if not is_valid:
        logger.warning(
            "Rejected malformed /ingest payload: %s",
            error,
        )
        return jsonify({"error": error}), 400

    logger.info(
        "INGEST PERF | validation=%.3fs",
        time.perf_counter() - stage_start,
    )

    hostname = data["hostname"]
    events = data["events"]

    # 2. Store incoming events
    stage_start = time.perf_counter()
    insert_events(hostname, events)

    logger.info(
        "INGEST PERF | database_insert=%.3fs | batch=%d | host=%s",
        time.perf_counter() - stage_start,
        len(events),
        hostname,
    )

    # 3. Read events for analysis
    stage_start = time.perf_counter()
    host_events = read_events(
        hostname=hostname,
        limit=1000,
    )

    logger.info(
        "INGEST PERF | event_read=%.3fs | analyzed_events=%d",
        time.perf_counter() - stage_start,
        len(host_events),
    )

    # 4. Correlate incidents
    stage_start = time.perf_counter()
    host_incidents = correlate_events(host_events)

    logger.info(
        "INGEST PERF | correlation=%.3fs | incidents=%d",
        time.perf_counter() - stage_start,
        len(host_incidents),
    )

    # 5. Calculate risk
    stage_start = time.perf_counter()
    summary = calculate_risk(
        host_events,
        host_incidents,
    )

    logger.info(
        "INGEST PERF | risk_calculation=%.3fs",
        time.perf_counter() - stage_start,
    )

    # 6. Check and process new alerts
    stage_start = time.perf_counter()
    new_alerts = claim_new_alerts(
        summary["incidents"],
        ALERT_RISK_THRESHOLD,
    )

    if new_alerts:
        check_and_alert(new_alerts)
    else:
        logger.info(
            "No new incidents met the alert threshold for %s.",
            hostname,
        )

    logger.info(
        "INGEST PERF | alert_processing=%.3fs",
        time.perf_counter() - stage_start,
    )

    # 7. Total request time
    logger.info(
        "INGEST PERF | TOTAL=%.3fs | host=%s | batch=%d",
        time.perf_counter() - request_start,
        hostname,
        len(events),
    )

    return jsonify({
        "status": "ok",
        "received": len(events),
    }), 200


# ============================================================
# SOC DASHBOARD
# ============================================================

@app.route("/soc")
def soc_dashboard():
    hostname_filter = request.args.get("host", "").strip() or None

    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1

    try:
        page_size = int(request.args.get("page_size", 25))
    except (TypeError, ValueError):
        page_size = 25

    if page_size not in {25, 50, 100}:
        page_size = 25

    analysis_events = read_events(
        hostname=hostname_filter,
        limit=5000,
    )
    incidents = correlate_events(analysis_events)
    summary = calculate_risk(analysis_events, incidents)

    for incident in summary["incidents"]:
        incident["recommended_action"] = get_recommended_action(incident)

    total_events = count_events(hostname=hostname_filter)
    total_pages = max(1, (total_events + page_size - 1) // page_size)
    page = min(page, total_pages)

    feed_events = read_events(
        hostname=hostname_filter,
        limit=page_size,
        offset=(page - 1) * page_size,
    )

    risk_by_key = {}

    for analyzed in summary.get("events", []):
        key = (
            analyzed.get("hostname"),
            analyzed.get("record_id"),
            analyzed.get("event_id"),
            analyzed.get("time"),
        )
        risk_by_key[key] = analyzed.get("risk_score", 0)

    for event in feed_events:
        key = (
            event.get("hostname"),
            event.get("record_id"),
            event.get("event_id"),
            event.get("time"),
        )
        event["risk_score"] = risk_by_key.get(key, 0)

    return render_template(
        "soc.html",
        hosts=list_hostnames(),
        selected_host=hostname_filter or "",
        events=feed_events,
        incidents=summary["incidents"],
        overall_score=summary["overall_score"],
        overall_level=summary["overall_level"],
        total_events=total_events,
        page=page,
        total_pages=total_pages,
        page_size=page_size,
    )


# ============================================================
# INCIDENT DETAILS
# ============================================================


@app.route("/incident/<int:incident_id>")
def incident_details(incident_id):
    print("DEBUG: incident_details route reached!")
    # Load the same event set used by the Alerts page.
    events = read_events(limit=5000)
    test_events = read_events(
        hostname="SOC-TEST-ACCOUNT",
        limit=100,
    )

    existing_ids = {
        (
            event.get("hostname"),
            event.get("record_id"),
            event.get("event_id"),
        )
        for event in events
    }

    for event in test_events:
        event_key = (
            event.get("hostname"),
            event.get("record_id"),
            event.get("event_id"),
        )

        if event_key not in existing_ids:
            events.append(event)
            existing_ids.add(event_key)

    # Build incidents in the same order as the Alerts page.
    incidents = correlate_events(events)
    incidents = deduplicate_alerts(incidents)
    summary = calculate_risk(events, incidents)

    incidents = [
        incident
        for incident in summary["incidents"]
        if incident.get("risk_score", 0) > 0
    ]
    print("Requested incident ID:", incident_id)
    print("Available incidents:", len(incidents))
    print("Incident names:", [i.get("name") for i in incidents])

    if incident_id < 0 or incident_id >= len(incidents):
     abort(404, description="Incident not found.")

    incident = dict(incidents[incident_id])

    incident_events = sorted(
        incident.get("events", []),
        key=lambda event: event.get("time") or "",
    )

    events_by_logon = {}
    for event in incident_events:
        logon_id = str(event.get("logon_id") or "Unknown")
        events_by_logon.setdefault(logon_id, []).append(event)

    incident["events"] = incident_events
    incident["event_count"] = len(incident_events)
    incident["events_by_logon"] = events_by_logon
    incident["recommended_action"] = get_recommended_action(incident)

    # Load saved investigation status and notes.
    incident["incident_key"] = _incident_fingerprint(incident)
    workflow = get_incident_workflow(incident["incident_key"])
    incident["workflow_status"] = workflow["status"]
    incident["workflow_notes"] = workflow["notes"]
    incident["workflow_updated_at"] = workflow["updated_at"]

    return render_template("incident.html", incident=incident)

# ============================================================
# EVENT DETAILS
# ============================================================

@app.route("/event/<int:record_id>")
def event_details(record_id):
    hostname = request.args.get("host", "").strip()

    if not hostname:
        abort(400, description="Host is required to identify this event.")

    total = count_events(hostname=hostname)
    page_size = 1000
    event = None

    for offset in range(0, total, page_size):
        batch = read_events(
            hostname=hostname,
            limit=page_size,
            offset=offset,
        )

        event = next(
            (
                item for item in batch
                if item.get("record_id") is not None
                and str(item.get("record_id")) == str(record_id)
            ),
            None,
        )

        if event is not None:
            break

    if event is None:
        abort(
            404,
            description=(
                "Event not found. It may have been removed "
                "or its record ID may be unavailable."
            ),
        )

    return render_template("event.html", event=event)

# ============================================================
# ENDPOINT HEARTBEAT API
# ============================================================

@app.route("/heartbeat", methods=["POST"])
@require_api_key
def endpoint_heartbeat_api():

    data = request.get_json(silent=True) or {}
    hostname = data.get("hostname")

    if not isinstance(hostname, str) or not hostname.strip():
        return jsonify({
            "error": "Valid hostname is required"
        }), 400

    record_heartbeat(hostname.strip())

    return jsonify({
        "status": "ok"
    }), 200


# ============================================================
# ENDPOINT MONITORING PAGE
# ============================================================

@app.route("/endpoints")
def endpoints():

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    endpoint_rows = list_endpoints()

    for endpoint in endpoint_rows:

        last_seen = endpoint.get("last_seen")

        if not last_seen:
            endpoint["status"] = "No heartbeat"
            continue

        try:
            timestamp = datetime.fromisoformat(
                last_seen.replace("Z", "+00:00")
            )

            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(
                    tzinfo=timezone.utc
                )

            elapsed = (now - timestamp).total_seconds()

            endpoint["status"] = (
                "Online" if elapsed <= 90 else "Offline"
            )

        except (ValueError, TypeError):
            endpoint["status"] = "Unknown"

    return render_template(
        "endpoints.html",
        endpoints=endpoint_rows
    )
# ============================================================
# START FLASK
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)
