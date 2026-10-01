def investigate_threat(triage_result, log_result, correlation_result):
    """
    Investigation Agent

    Combines triage, log analysis and correlation results
    into a structured SOC investigation.
    """

    timeline = []

    # Build evidence timeline
    if log_result["failed_logins"] > 0:
        timeline.append(
            f"{log_result['failed_logins']} failed login attempts detected"
        )

    if log_result["successful_logins"] > 0:
        timeline.append(
            "Successful authentication detected after failed attempts"
        )

    if log_result["new_devices"] > 0:
        timeline.append(
            "Previously unseen device detected"
        )

    if log_result["privileged_access"] > 0:
        timeline.append(
            "Privileged/admin access detected"
        )

    # Investigation summary
    investigation_summary = (
        f"The alert involves user '{triage_result['user']}' "
        f"and source IP '{triage_result['ip']}'. "
        f"The correlated events indicate a "
        f"{correlation_result['pattern'].lower()} pattern."
    )

    # Investigation steps
    investigation_steps = [
        "Review authentication logs for the affected account",
        "Verify whether the successful login was legitimate",
        "Investigate the newly detected device",
        "Review privileged actions after authentication",
        "Check the source IP using threat intelligence"
    ]

    return {
        "agent": "Investigation Agent",
        "incident": correlation_result["pattern"],
        "severity": triage_result["severity"],
        "user": triage_result["user"],
        "ip": triage_result["ip"],
        "summary": investigation_summary,
        "timeline": timeline,
        "evidence": correlation_result["evidence"],
        "investigation_steps": investigation_steps
    }