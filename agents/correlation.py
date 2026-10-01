def correlate_threat(log_result):
    """
    Threat Correlation Agent

    Correlates multiple security events to identify
    suspicious attack patterns.
    """

    failed_logins = log_result["failed_logins"]
    successful_logins = log_result["successful_logins"]
    new_devices = log_result["new_devices"]
    privileged_access = log_result["privileged_access"]

    evidence = []
    score = 0

    # Pattern 1: Multiple failed logins
    if failed_logins >= 3:
        evidence.append(
            f"{failed_logins} failed login attempts detected"
        )
        score += 2

    # Pattern 2: Successful login after failures
    if failed_logins >= 3 and successful_logins >= 1:
        evidence.append(
            "Successful login occurred after multiple failed attempts"
        )
        score += 2

    # Pattern 3: New device
    if new_devices >= 1:
        evidence.append(
            "Previously unseen device detected"
        )
        score += 2

    # Pattern 4: Privileged access
    if privileged_access >= 1:
        evidence.append(
            "Privileged/admin access detected"
        )
        score += 2

    # Determine correlation level
    if score >= 6:
        correlation_level = "HIGH"
        pattern = "Possible Account Takeover"
    elif score >= 3:
        correlation_level = "MEDIUM"
        pattern = "Suspicious Authentication Activity"
    else:
        correlation_level = "LOW"
        pattern = "No Strong Attack Pattern"

    return {
        "agent": "Threat Correlation Agent",
        "pattern": pattern,
        "correlation_level": correlation_level,
        "score": score,
        "evidence": evidence
    }