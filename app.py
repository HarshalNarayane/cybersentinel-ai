from agents.triage import triage_alert
from agents.log_analysis import analyze_logs
from agents.correlation import correlate_threat


# =========================
# SECURITY ALERT
# =========================

alert = {
    "type": "authentication",
    "user": "admin",
    "failed_attempts": 8,
    "ip": "185.22.91.44"
}


# =========================
# AGENT 1: ALERT TRIAGE
# =========================

triage_result = triage_alert(alert)


# =========================
# AGENT 2: LOG ANALYSIS
# =========================

log_result = analyze_logs()


# =========================
# AGENT 3: THREAT CORRELATION
# =========================

correlation_result = correlate_threat(log_result)


# =========================
# DISPLAY RESULTS
# =========================

print("\n================================")
print("       CYBERSENTINEL AI")
print("================================")


# =========================
# AGENT 1 OUTPUT
# =========================

print("\n[AGENT 1] ALERT TRIAGE")
print("--------------------------------")

print("Alert Type:", triage_result["alert_type"])
print("Severity:", triage_result["severity"])
print("User:", triage_result["user"])
print("IP:", triage_result["ip"])

print("\nReasons:")

for reason in triage_result["reasons"]:
    print("•", reason)


# =========================
# AGENT 2 OUTPUT
# =========================

print("\n[AGENT 2] LOG ANALYSIS")
print("--------------------------------")

print("Total Events:", log_result["total_events"])
print("Failed Logins:", log_result["failed_logins"])
print("Successful Logins:", log_result["successful_logins"])
print("New Devices:", log_result["new_devices"])
print("Privileged Access:", log_result["privileged_access"])


# =========================
# AGENT 3 OUTPUT
# =========================

print("\n[AGENT 3] THREAT CORRELATION")
print("--------------------------------")

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


# =========================
# NEXT ACTION
# =========================

print("\nNext Action:")
print(triage_result["next_action"])