from agents.triage import triage_alert


alert = {
    "type": "authentication",
    "user": "admin",
    "failed_attempts": 8,
    "ip": "185.22.91.44"
}

result = triage_alert(alert)

print("\n===== CYBERSENTINEL AI =====")
print("Agent:", result["agent"])
print("Alert Type:", result["alert_type"])
print("Severity:", result["severity"])
print("User:", result["user"])
print("IP:", result["ip"])

print("\nReasons:")
for reason in result["reasons"]:
    print("•", reason)

print("\nNext Action:")
print(result["next_action"])