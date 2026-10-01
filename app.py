from agents.triage import triage_alert
from agents.log_analysis import analyze_logs
from agents.correlation import correlate_threat
from agents.investigation import investigate_threat


# ============================================================
# CYBERSENTINEL AI
# AI Cybersecurity SOC Investigation Agent
# ============================================================


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
# AGENT 1: ALERT TRIAGE
# ============================================================

triage_result = triage_alert(alert)


# ============================================================
# AGENT 2: LOG ANALYSIS
# ============================================================

log_result = analyze_logs()


# ============================================================
# AGENT 3: THREAT CORRELATION
# ============================================================

correlation_result = correlate_threat(log_result)


# ============================================================
# AGENT 4: INVESTIGATION
# ============================================================

investigation_result = investigate_threat(
    triage_result,
    log_result,
    correlation_result
)


# ============================================================
# CYBERSENTINEL AI HEADER
# ============================================================

print("\n")
print("==============================================")
print("          CYBERSENTINEL AI")
print("     SOC INVESTIGATION SYSTEM")
print("==============================================")


# ============================================================
# AGENT 1 OUTPUT — ALERT TRIAGE
# ============================================================

print("\n[AGENT 1] ALERT TRIAGE")
print("----------------------------------------------")

print("Alert Type:", triage_result["alert_type"])
print("Severity:", triage_result["severity"])
print("User:", triage_result["user"])
print("IP:", triage_result["ip"])

print("\nReasons:")

for reason in triage_result["reasons"]:
    print("•", reason)


# ============================================================
# AGENT 2 OUTPUT — LOG ANALYSIS
# ============================================================

print("\n[AGENT 2] LOG ANALYSIS")
print("----------------------------------------------")

print("Total Events:", log_result["total_events"])
print("Failed Logins:", log_result["failed_logins"])
print("Successful Logins:", log_result["successful_logins"])
print("New Devices:", log_result["new_devices"])
print("Privileged Access:", log_result["privileged_access"])


# ============================================================
# AGENT 3 OUTPUT — THREAT CORRELATION
# ============================================================

print("\n[AGENT 3] THREAT CORRELATION")
print("----------------------------------------------")

print("Pattern:", correlation_result["pattern"])
print(
    "Correlation Level:",
    correlation_result["correlation_level"]
)
print(
    "Correlation Score:",
    correlation_result["score"]
)

print("\nEvidence:")

for item in correlation_result["evidence"]:
    print("✓", item)


# ============================================================
# AGENT 4 OUTPUT — INVESTIGATION
# ============================================================

print("\n[AGENT 4] SECURITY INVESTIGATION")
print("----------------------------------------------")

print("Incident:", investigation_result["incident"])
print("Severity:", investigation_result["severity"])
print("User:", investigation_result["user"])
print("IP:", investigation_result["ip"])


# ============================================================
# INVESTIGATION SUMMARY
# ============================================================

print("\nInvestigation Summary:")

print(investigation_result["summary"])


# ============================================================
# EVIDENCE TIMELINE
# ============================================================

print("\nEvidence Timeline:")

for event in investigation_result["timeline"]:
    print("→", event)


# ============================================================
# INVESTIGATION STEPS
# ============================================================

print("\nRecommended Investigation Steps:")

for step in investigation_result["investigation_steps"]:
    print("•", step)


# ============================================================
# CURRENT NEXT ACTION
# ============================================================

print("\nNext Action:")
print(triage_result["next_action"])


# ============================================================
# PIPELINE STATUS
# ============================================================

print("\n==============================================")
print("             AGENT PIPELINE")
print("==============================================")

print("✅ Alert Triage")
print("✅ Log Analysis")
print("✅ Threat Correlation")
print("✅ Investigation")
print("⏳ Risk Assessment")
print("⏳ Response Recommendation")

print("\n==============================================")
print("          INVESTIGATION COMPLETE")
print("==============================================")