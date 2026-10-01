def triage_alert(alert):
    """
    Alert Triage Agent
    Classifies an incoming security alert.
    """

    failed_attempts = alert.get("failed_attempts", 0)
    user = alert.get("user", "unknown")
    ip = alert.get("ip", "unknown")

    reasons = []

    if failed_attempts >= 5:
        reasons.append("Multiple failed login attempts")

    if user.lower() == "admin":
        reasons.append("Privileged/admin account involved")

    if ip != "unknown":
        reasons.append(f"Source IP identified: {ip}")

    if failed_attempts >= 5:
        severity = "HIGH"
        alert_type = "Suspicious Authentication"
    elif failed_attempts > 0:
        severity = "MEDIUM"
        alert_type = "Authentication Anomaly"
    else:
        severity = "LOW"
        alert_type = "Normal Authentication"

    return {
        "agent": "Alert Triage Agent",
        "alert_type": alert_type,
        "severity": severity,
        "user": user,
        "ip": ip,
        "reasons": reasons,
        "next_action": "Investigate authentication logs"
    }