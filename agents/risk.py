def assess_risk(triage_result, log_result, correlation_result):
    """
    Risk Assessment Agent

    Calculates risk from observed evidence.
    Does not assume an attack when evidence is insufficient.
    """

    score = 0
    risk_factors = []

    # Severity from triage
    severity = triage_result["severity"]

    if severity == "HIGH":
        score += 3
        risk_factors.append("High-severity security alert")

    elif severity == "MEDIUM":
        score += 2
        risk_factors.append("Medium-severity security alert")

    else:
        score += 1

    # Correlation evidence
    correlation_level = correlation_result["correlation_level"]

    if correlation_level == "HIGH":
        score += 3
        risk_factors.append("High-confidence correlated activity")

    elif correlation_level == "MEDIUM":
        score += 2
        risk_factors.append("Moderate correlated activity")

    # Failed logins
    if log_result["failed_logins"] >= 3:
        score += 1
        risk_factors.append(
            f"{log_result['failed_logins']} failed login attempts"
        )

    # New device
    if log_result["new_devices"] > 0:
        score += 1
        risk_factors.append("Previously unseen device")

    # Privileged access
    if log_result["privileged_access"] > 0:
        score += 2
        risk_factors.append("Privileged/admin access detected")

    # ------------------------------------------------
    # Risk classification
    # ------------------------------------------------

    if score >= 8:
        risk_level = "CRITICAL"

    elif score >= 6:
        risk_level = "HIGH"

    elif score >= 3:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    # ------------------------------------------------
    # Confidence
    # ------------------------------------------------

    evidence_count = len(correlation_result["evidence"])

    if evidence_count >= 4:
        confidence = "HIGH"

    elif evidence_count >= 2:
        confidence = "MEDIUM"

    else:
        confidence = "LOW"

    # ------------------------------------------------
    # Guard against insufficient evidence
    # ------------------------------------------------

    if evidence_count == 0:
        risk_level = "UNKNOWN"
        confidence = "LOW"

        risk_factors.append(
            "Insufficient evidence to determine attack risk"
        )

    return {
        "agent": "Risk Assessment Agent",
        "risk_level": risk_level,
        "risk_score": score,
        "confidence": confidence,
        "risk_factors": risk_factors
    }