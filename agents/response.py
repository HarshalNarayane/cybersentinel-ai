def generate_response(triage_result, investigation_result, risk_result):
    """
    Response Recommendation Agent

    Generates recommended SOC actions based on observed
    evidence and calculated risk.
    """

    risk_level = risk_result["risk_level"]

    immediate_actions = []
    investigation_actions = []
    follow_up_actions = []

    # ========================================================
    # CRITICAL / HIGH RISK
    # ========================================================

    if risk_level in ["CRITICAL", "HIGH"]:

        immediate_actions = [
            "Temporarily lock or disable the affected account",
            "Revoke active sessions for the affected account",
            "Investigate the source IP and authentication activity"
        ]

        investigation_actions = [
            "Verify whether the successful login was legitimate",
            "Investigate the previously unseen device",
            "Review privileged/admin activity",
            "Review recent authentication history"
        ]

        follow_up_actions = [
            "Reset credentials if compromise is confirmed",
            "Enable or verify multi-factor authentication",
            "Continue monitoring the affected account"
        ]

    # ========================================================
    # MEDIUM RISK
    # ========================================================

    elif risk_level == "MEDIUM":

        immediate_actions = [
            "Increase monitoring of the affected account",
            "Review recent authentication activity"
        ]

        investigation_actions = [
            "Verify the source IP",
            "Verify the device involved",
            "Check whether the login activity was expected"
        ]

        follow_up_actions = [
            "Enable additional authentication controls if required",
            "Continue monitoring for repeated suspicious activity"
        ]

    # ========================================================
    # LOW RISK
    # ========================================================

    elif risk_level == "LOW":

        immediate_actions = [
            "Continue monitoring the affected account"
        ]

        investigation_actions = [
            "Review the authentication event",
            "Verify whether the activity was expected"
        ]

        follow_up_actions = [
            "Close the alert if no additional suspicious activity is found"
        ]

    # ========================================================
    # UNKNOWN / INSUFFICIENT EVIDENCE
    # ========================================================

    else:

        immediate_actions = [
            "Do not automatically classify the activity as an attack"
        ]

        investigation_actions = [
            "Collect additional authentication evidence",
            "Retry unavailable security tools",
            "Verify the affected user's activity"
        ]

        follow_up_actions = [
            "Reassess the incident when additional evidence becomes available"
        ]

    # ========================================================
    # RESPONSE SUMMARY
    # ========================================================

    response_summary = (
        f"Recommended response for a {risk_level} risk incident "
        f"involving user '{triage_result['user']}'. "
        f"Actions are based on the evidence currently available."
    )

    return {
        "agent": "Response Recommendation Agent",
        "risk_level": risk_level,
        "summary": response_summary,
        "immediate_actions": immediate_actions,
        "investigation_actions": investigation_actions,
        "follow_up_actions": follow_up_actions
    }