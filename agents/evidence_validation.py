def validate_evidence(log_result, correlation_result):
    """
    Evidence Validation Layer

    Checks whether available evidence supports or
    contradicts the suspected attack pattern.
    """

    contradictions = []

    # Known/legitimate device information
    known_device_events = [
        log for log in log_result["events"]
        if log.get("event") == "known_device"
    ]

    # Known/legitimate IP information
    known_ip_events = [
        log for log in log_result["events"]
        if log.get("event") == "known_ip"
    ]

    # Explicitly verified legitimate login
    legitimate_events = [
        log for log in log_result["events"]
        if log.get("event") == "verified_legitimate_login"
    ]

    if known_device_events:
        contradictions.append(
            "Login originated from a previously trusted device"
        )

    if known_ip_events:
        contradictions.append(
            "Source IP is known/trusted"
        )

    if legitimate_events:
        contradictions.append(
            "Successful login was independently verified as legitimate"
        )

    # ------------------------------------------------
    # Determine evidence status
    # ------------------------------------------------

    if len(contradictions) >= 2:
        evidence_status = "CONFLICTING"
        confidence_adjustment = "LOW"
        attack_confirmation = "UNCONFIRMED"

    elif len(contradictions) == 1:
        evidence_status = "MIXED"
        confidence_adjustment = "MEDIUM"
        attack_confirmation = "REQUIRES_REVIEW"

    else:
        evidence_status = "SUPPORTS_SUSPICION"
        confidence_adjustment = "HIGH"
        attack_confirmation = "SUPPORTED_BY_AVAILABLE_EVIDENCE"

    return {
        "agent": "Evidence Validation Layer",
        "evidence_status": evidence_status,
        "attack_confirmation": attack_confirmation,
        "confidence": confidence_adjustment,
        "contradictions": contradictions,
        "original_pattern": correlation_result["pattern"]
    }