import json


def analyze_logs(log_file="data/security_logs.json"):
    """
    Log Analysis Agent
    Reads security logs and identifies important events.
    """

    with open(log_file, "r") as file:
        logs = json.load(file)

    failed_logins = [
        log for log in logs
        if log["event"] == "failed_login"
    ]

    successful_logins = [
        log for log in logs
        if log["event"] == "successful_login"
    ]

    new_devices = [
        log for log in logs
        if log["event"] == "new_device"
    ]

    privileged_access = [
        log for log in logs
        if log["event"] == "privileged_access"
    ]

    return {
        "agent": "Log Analysis Agent",
        "total_events": len(logs),
        "failed_logins": len(failed_logins),
        "successful_logins": len(successful_logins),
        "new_devices": len(new_devices),
        "privileged_access": len(privileged_access),
        "events": logs
    }