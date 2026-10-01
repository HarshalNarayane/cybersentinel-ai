from agents.triage import triage_alert
from agents.log_analysis import analyze_logs


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
# DISPLAY RESULTS
# =========================

print("\n================================")
print("       CYBERSENTINEL AI")
print("================================")

print("\n[AGENT 1] ALERT TRIAGE")
print("--------------------------------")
print("Alert Type:", triage_result["alert_type"])
print("Severity:", triage_result["severity"])
print("User:", triage_result["user"])
print("IP:", triage_result["ip"])

print("\nReasons:")
for reason in triage_result["reasons"]:
    print("•", reason)


print("\n[AGENT 2] LOG ANALYSIS")
print("--------------------------------")
print("Total Events:", log_result["total_events"])
print("Failed Logins:", log_result["failed_logins"])
print("Successful Logins:", log_result["successful_logins"])
print("New Devices:", log_result["new_devices"])
print("Privileged Access:", log_result["privileged_access"])


print("\nNext Action:")
print(triage_result["next_action"])