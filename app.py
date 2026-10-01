from agents.triage import triage_alert
from agents.log_analysis import analyze_logs
from agents.correlation import correlate_threat
from agents.investigation import investigate_threat
from agents.risk import assess_risk
from agents.response import generate_response
from agents.evidence_validation import validate_evidence
from agents.tool_failure import check_threat_intelligence


# ============================================================
# CYBERSENTINEL AI
# ============================================================

print("=" * 60)
print("           CYBERSENTINEL AI - SOC INVESTIGATION")
print("=" * 60)


# ============================================================
# DEMO CONFIGURATION
# ============================================================

# Change this to:
#
# "normal"
# "contradictory"
# "tool_failure"
#
SCENARIO = "normal"


# ============================================================
# SECURITY ALERT
# ============================================================

alert = {
    "type": "authentication",
    "user": "admin",
    "failed_attempts": 8,
    "ip": "185.22.91.44"
}


# ============================================================
# AGENT 1 - ALERT TRIAGE
# ============================================================

triage_result = triage_alert(alert)

triage_result["incident"] = (
    triage_result.get("incident")
    or triage_result.get("classification")
    or triage_result.get("alert_type")
    or "Security Alert"
)

triage_result["severity"] = triage_result.get(
    "severity",
    "UNKNOWN"
)

triage_result["user"] = triage_result.get(
    "user",
    alert["user"]
)

triage_result["ip"] = triage_result.get(
    "ip",
    alert["ip"]
)

triage_result["reasons"] = triage_result.get(
    "reasons",
    []
)

print("\n[AGENT 1 - ALERT TRIAGE]")
print("-" * 50)

print("Incident:", triage_result["incident"])
print("Severity:", triage_result["severity"])
print("User:", triage_result["user"])
print("Source IP:", triage_result["ip"])

print("Reasons:")

for reason in triage_result["reasons"]:
    print(" -", reason)


# ============================================================
# AGENT 2 - LOG ANALYSIS
# ============================================================

log_result = analyze_logs()

print("\n[AGENT 2 - LOG ANALYSIS]")
print("-" * 50)

print("Total Events:", log_result.get("total_events", 0))
print("Failed Logins:", log_result.get("failed_logins", 0))
print("Successful Logins:", log_result.get("successful_logins", 0))
print("New Devices:", log_result.get("new_devices", 0))
print("Privileged Access:", log_result.get("privileged_access", 0))


# ============================================================
# AGENT 3 - THREAT CORRELATION
# ============================================================

correlation_result = correlate_threat(log_result)

print("\n[AGENT 3 - THREAT CORRELATION]")
print("-" * 50)

print(
    "Pattern:",
    correlation_result.get("pattern", "Unknown")
)

print(
    "Correlation Level:",
    correlation_result.get(
        "correlation_level",
        "UNKNOWN"
    )
)

print(
    "Correlation Score:",
    correlation_result.get(
        "score",
        0
    )
)

print("Evidence:")

for evidence in correlation_result.get(
    "evidence",
    []
):
    print(" -", evidence)


# ============================================================
# AGENT 4 - SECURITY INVESTIGATION
# ============================================================

investigation_result = investigate_threat(
    triage_result,
    log_result,
    correlation_result
)

print("\n[AGENT 4 - SECURITY INVESTIGATION]")
print("-" * 50)

print(
    "Incident:",
    investigation_result.get(
        "incident",
        triage_result["incident"]
    )
)

print(
    "Severity:",
    investigation_result.get(
        "severity",
        triage_result["severity"]
    )
)

print(
    "User:",
    investigation_result.get(
        "user",
        triage_result["user"]
    )
)

print(
    "Source IP:",
    investigation_result.get(
        "ip",
        triage_result["ip"]
    )
)

print("\nSummary:")

print(
    investigation_result.get(
        "summary",
        "Investigation summary unavailable."
    )
)

print("\nTimeline:")

for event in investigation_result.get(
    "timeline",
    []
):
    print(" -", event)

print("\nInvestigation Steps:")

for step in investigation_result.get(
    "investigation_steps",
    []
):
    print(" -", step)


# ============================================================
# AGENT 5 - RISK ASSESSMENT
# ============================================================

risk_result = assess_risk(
    triage_result,
    log_result,
    correlation_result
)

risk_result["risk_level"] = risk_result.get(
    "risk_level",
    "UNKNOWN"
)

risk_result["risk_score"] = risk_result.get(
    "risk_score",
    0
)

risk_result["confidence"] = risk_result.get(
    "confidence",
    "LOW"
)

risk_result["risk_factors"] = risk_result.get(
    "risk_factors",
    []
)

print("\n[AGENT 5 - RISK ASSESSMENT]")
print("-" * 50)

print(
    "Risk Level:",
    risk_result["risk_level"]
)

print(
    "Risk Score:",
    risk_result["risk_score"]
)

print(
    "Confidence:",
    risk_result["confidence"]
)

print("Risk Factors:")

for factor in risk_result["risk_factors"]:
    print(" -", factor)


# ============================================================
# EVIDENCE VALIDATION
# ============================================================

evidence_result = validate_evidence(
    log_result,
    correlation_result
)

print("\n[EVIDENCE VALIDATION LAYER]")
print("-" * 50)

print(
    "Evidence Status:",
    evidence_result.get(
        "evidence_status",
        "UNKNOWN"
    )
)

print(
    "Attack Confirmation:",
    evidence_result.get(
        "attack_confirmation",
        "UNKNOWN"
    )
)

print(
    "Confidence:",
    evidence_result.get(
        "confidence",
        "LOW"
    )
)

contradictions = evidence_result.get(
    "contradictions",
    []
)

if contradictions:

    print("\nContradictory Evidence:")

    for contradiction in contradictions:
        print(
            " ⚠",
            contradiction
        )

else:

    print(
        "\nNo contradictory evidence detected."
    )


# ============================================================
# TOOL FAILURE HANDLING
# ============================================================

simulate_tool_failure = (
    SCENARIO == "tool_failure"
)

tool_result = check_threat_intelligence(
    triage_result["ip"],
    simulate_failure=simulate_tool_failure
)

print("\n[THREAT INTELLIGENCE TOOL]")
print("-" * 50)

print(
    "Tool:",
    tool_result["tool"]
)

print(
    "Status:",
    tool_result["status"]
)

print(
    "IP:",
    tool_result["ip"]
)

print(
    "Message:",
    tool_result["message"]
)

if tool_result["status"] == "FAILED":

    print(
        "⚠ Safety:",
        tool_result["safe_action"]
    )


# ============================================================
# SAFETY CHECK
# ============================================================

evidence_status = evidence_result.get(
    "evidence_status",
    "UNKNOWN"
)

if evidence_status == "CONFLICTING":

    risk_result["risk_level"] = "UNKNOWN"

    risk_result["confidence"] = "LOW"

    risk_result["risk_factors"].append(
        "Contradictory evidence detected - "
        "attack cannot be confirmed"
    )

elif evidence_status == "MIXED":

    risk_result["confidence"] = "MEDIUM"

    risk_result["risk_factors"].append(
        "Mixed evidence detected - "
        "additional investigation required"
    )


# Tool failure should NOT create fake malicious evidence.

if tool_result["status"] == "FAILED":

    risk_result["risk_factors"].append(
        "Threat intelligence unavailable - "
        "IP reputation could not be verified"
    )


# ============================================================
# AGENT 6 - RESPONSE
# ============================================================

response_result = generate_response(
    triage_result,
    investigation_result,
    risk_result
)

print("\n[AGENT 6 - RESPONSE RECOMMENDATION]")
print("-" * 50)

print(
    "Response Level:",
    response_result.get(
        "response_level",
        risk_result["risk_level"]
    )
)

response_summary = (
    response_result.get("response_summary")
    or response_result.get("summary")
    or response_result.get("response")
    or response_result.get("recommendation")
    or "Response recommendation generated."
)

print("\nResponse Summary:")
print(response_summary)


print("\nImmediate Actions:")

for action in response_result.get(
    "immediate_actions",
    []
):
    print(" -", action)


print("\nInvestigation Actions:")

for action in response_result.get(
    "investigation_actions",
    []
):
    print(" -", action)


print("\nFollow-up Actions:")

for action in response_result.get(
    "follow_up_actions",
    []
):
    print(" -", action)


# ============================================================
# FINAL SOC RESULT
# ============================================================

print("\n" + "=" * 60)
print("                 FINAL SOC RESULT")
print("=" * 60)

print(
    "Scenario:",
    SCENARIO
)

print(
    "Incident:",
    investigation_result.get(
        "incident",
        triage_result["incident"]
    )
)

print(
    "Attack Pattern:",
    correlation_result.get(
        "pattern",
        "Unknown"
    )
)

print(
    "Risk Level:",
    risk_result["risk_level"]
)

print(
    "Confidence:",
    risk_result["confidence"]
)

print(
    "Evidence Status:",
    evidence_status
)

print(
    "Attack Confirmation:",
    evidence_result.get(
        "attack_confirmation",
        "UNKNOWN"
    )
)

print(
    "Threat Intelligence:",
    tool_result["status"]
)


# ============================================================
# PIPELINE STATUS
# ============================================================

print("\n" + "=" * 60)
print("              PIPELINE STATUS")
print("=" * 60)

print("✓ Agent 1 - Alert Triage")
print("✓ Agent 2 - Log Analysis")
print("✓ Agent 3 - Threat Correlation")
print("✓ Agent 4 - Security Investigation")
print("✓ Agent 5 - Risk Assessment")
print("✓ Evidence Validation")
print("✓ Threat Intelligence Tool")
print("✓ Agent 6 - Response Recommendation")

print(
    "\n✓ CyberSentinel AI pipeline completed successfully."
)

print("=" * 60)