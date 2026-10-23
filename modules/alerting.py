
# ============================================================
# SENTINELX - EXPLAINABLE ALERTING ENGINE
# ============================================================

import requests

from config import ALERT_WEBHOOK_URL, ALERT_RISK_THRESHOLD
from modules.logger import get_logger


logger = get_logger("alerting")


# ============================================================
# RECOMMENDED RESPONSE ACTIONS
# ============================================================

def get_recommended_action(incident):
    """Suggest an investigation step based on incident details."""

    text = (
        str(incident.get("name", "")) + " " +
        str(incident.get("description", "")) + " " +
        str(incident.get("category", ""))
    ).lower()

    if "failed login" in text or "brute force" in text:
        return (
            "Review failed-login timestamps, account names, and "
            "source hosts. Check whether the activity is legitimate."
        )

    if "privilege" in text or "administrator group" in text:
        return (
            "Verify the account and administrative change against "
            "approved access requests."
        )

    if "account created" in text or "account creation" in text:
        return (
            "Confirm that the account creation was authorized "
            "and identify who performed the change."
        )

    if "log cleared" in text or "log management" in text:
        return (
            "Investigate why the security log was cleared and "
            "preserve any available related evidence."
        )

    if "credential" in text:
        return (
            "Review the process and account associated with the "
            "credential activity and confirm whether it was expected."
        )

    if "process" in text:
        return (
            "Review the process name, parent process, account, "
            "and execution time if those details are available."
        )

    return (
        "Review the incident details, related events, affected "
        "host, and account before deciding on a response."
    )


# ============================================================
# RISK EXPLANATION
# ============================================================

def _format_reasons(incident):
    """Return explainable risk reasons when available."""

    reasons = incident.get("risk_reasons", [])

    if isinstance(reasons, str):
        reasons = [reasons]

    if not isinstance(reasons, (list, tuple)):
        reasons = []

    reasons = [
        str(reason)
        for reason in reasons
        if reason is not None and str(reason).strip()
    ]

    if not reasons:
        description = incident.get("description")

        if description:
            reasons = [str(description)]
        else:
            reasons = [
                "The incident met the configured risk threshold."
            ]

    return reasons


# ============================================================
# ALERT THRESHOLD CHECK
# ============================================================

def check_and_alert(scored_incidents):
    """
    Generate alerts for incidents meeting the configured
    risk threshold.
    """

    for incident in scored_incidents:
        if not isinstance(incident, dict):
            logger.warning("Skipping invalid incident entry.")
            continue

        risk_score = incident.get("risk_score", 0)

        try:
            risk_score = float(risk_score)
        except (TypeError, ValueError):
            logger.warning(
                "Skipping incident with invalid risk score."
            )
            continue

        if risk_score >= ALERT_RISK_THRESHOLD:
            # Pass a copy so alert formatting doesn't mutate
            # the incident supplied by the caller.
            alert_incident = dict(incident)
            alert_incident["risk_score"] = risk_score

            _send_alert(alert_incident)


# ============================================================
# SEND EXPLAINABLE ALERT
# ============================================================

def _send_alert(incident):
    """Log an explainable alert and optionally send a webhook."""

    risk_level = incident.get("risk_level", "Unknown")
    name = incident.get("name", "Unknown Incident")
    hostname = incident.get(
        "hostname",
        incident.get("host", "unknown host")
    )
    user = incident.get("user", "Unknown")
    risk_score = incident.get("risk_score", 0)

    reasons = _format_reasons(incident)
    recommendation = get_recommended_action(incident)

    evidence = incident.get("evidence", [])

    if isinstance(evidence, str):
        evidence = [evidence]

    if not isinstance(evidence, (list, tuple)):
        evidence = []

    lines = [
        f"[{risk_level}] {name}",
        f"Risk score: {risk_score}/100",
        f"Host: {hostname}",
        f"User: {user}",
        "",
        "Why this alert was raised:",
    ]

    for reason in reasons:
        lines.append(f"- {reason}")

    if evidence:
        lines.extend(["", "Evidence:"])

        for item in evidence:
            if isinstance(item, dict):
                lines.append(
                    "- " + ", ".join(
                        f"{key}: {value}"
                        for key, value in item.items()
                    )
                )
            else:
                lines.append(f"- {item}")

    lines.extend([
        "",
        f"Recommended investigation: {recommendation}",
    ])

    message = "\n".join(lines)

    # Improve compatibility with common Windows terminals.
    safe_message = (
        message
        .replace("→", "->")
        .replace("—", "-")
        .replace("←", "<-")
        .replace("–", "-")
    )

    logger.warning("ALERT:\n%s", safe_message)

    # Webhook delivery is optional.
    if not ALERT_WEBHOOK_URL:
        return

    try:
        response = requests.post(
            ALERT_WEBHOOK_URL,
            json={"text": message},
            timeout=5,
        )
        response.raise_for_status()

        logger.info(
            "Alert webhook delivered for incident: %s",
            name,
        )

    except requests.exceptions.RequestException as exc:
        logger.error(
            "Failed to deliver alert webhook: %s",
            exc,
        )
