def check_threat_intelligence(ip, simulate_failure=False):
    """
    Simulated Threat Intelligence tool.

    In a real SOC this would query an external threat-intelligence
    service. For the hackathon demo we simulate both success and
    failure.
    """

    if simulate_failure:
        return {
            "tool": "Threat Intelligence",
            "status": "FAILED",
            "ip": ip,
            "result": None,
            "message": (
                "Threat intelligence lookup failed. "
                "IP reputation could not be verified."
            ),
            "safe_action": (
                "Do not assume the IP is malicious. "
                "Continue investigation using available evidence."
            )
        }

    return {
        "tool": "Threat Intelligence",
        "status": "SUCCESS",
        "ip": ip,
        "result": "No confirmed malicious reputation in simulated database.",
        "message": "Threat intelligence lookup completed successfully.",
        "safe_action": (
            "Use this result together with authentication and "
            "endpoint evidence."
        )
    }