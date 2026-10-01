import streamlit as st

from agents.triage import triage_alert
from agents.log_analysis import analyze_logs
from agents.correlation import correlate_threat
from agents.investigation import investigate_threat
from agents.risk import assess_risk
from agents.response import generate_response
from agents.evidence_validation import validate_evidence
from agents.tool_failure import check_threat_intelligence


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CyberSentinel AI",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ CyberSentinel AI")
st.subheader("AI-Powered SOC Investigation Dashboard")

st.caption(
    "Simulated Security Operations Center for alert triage, "
    "log analysis, threat correlation, investigation, risk "
    "assessment and response."
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("⚙️ SOC Controls")

scenario = st.sidebar.selectbox(
    "Investigation Scenario",
    [
        "Normal Investigation",
        "Tool Failure",
        "Contradictory Evidence"
    ]
)

run_button = st.sidebar.button(
    "🚀 Run Investigation",
    use_container_width=True
)


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
# RUN INVESTIGATION
# ============================================================

if run_button:

    # ========================================================
    # AGENT 1 - ALERT TRIAGE
    # ========================================================

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


    # ========================================================
    # AGENT 2 - LOG ANALYSIS
    # ========================================================

    log_result = analyze_logs()


    # ========================================================
    # CONTRADICTORY EVIDENCE SIMULATION
    # ========================================================

    if scenario == "Contradictory Evidence":

        # Make a copy of the event list so that we don't
        # modify the original source file.

        log_result["events"] = list(
            log_result.get("events", [])
        )

        # Trusted device evidence
        log_result["events"].append({
            "event": "known_device",
            "user": "admin",
            "device": "KNOWN-DEVICE-01",
            "description": "Previously trusted device"
        })

        # Trusted IP evidence
        log_result["events"].append({
            "event": "known_ip",
            "user": "admin",
            "ip": "185.22.91.44",
            "description": "Previously trusted source IP"
        })

        # Independently verified legitimate login
        log_result["events"].append({
            "event": "verified_legitimate_login",
            "user": "admin",
            "ip": "185.22.91.44",
            "description": "User confirmed the login was legitimate"
        })


    # ========================================================
    # AGENT 3 - THREAT CORRELATION
    # ========================================================

    correlation_result = correlate_threat(
        log_result
    )


    # ========================================================
    # AGENT 4 - SECURITY INVESTIGATION
    # ========================================================

    investigation_result = investigate_threat(
        triage_result,
        log_result,
        correlation_result
    )


    # ========================================================
    # AGENT 5 - RISK ASSESSMENT
    # ========================================================

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


    # ========================================================
    # EVIDENCE VALIDATION
    # ========================================================

    evidence_result = validate_evidence(
        log_result,
        correlation_result
    )


    # ========================================================
    # THREAT INTELLIGENCE
    # ========================================================

    simulate_tool_failure = (
        scenario == "Tool Failure"
    )

    tool_result = check_threat_intelligence(
        triage_result["ip"],
        simulate_failure=simulate_tool_failure
    )


    # ========================================================
    # SAFETY CHECK
    # ========================================================

    evidence_status = evidence_result.get(
        "evidence_status",
        "UNKNOWN"
    )


    # Conflicting evidence
    if evidence_status == "CONFLICTING":

        risk_result["risk_level"] = "UNKNOWN"

        risk_result["confidence"] = "LOW"

        risk_result["risk_factors"].append(
            "Contradictory evidence detected - "
            "attack cannot be confirmed"
        )


    # Mixed evidence
    elif evidence_status == "MIXED":

        risk_result["confidence"] = "MEDIUM"

        risk_result["risk_factors"].append(
            "Mixed evidence detected - "
            "additional investigation required"
        )


    # Tool failure
    if tool_result["status"] == "FAILED":

        risk_result["risk_factors"].append(
            "Threat intelligence unavailable - "
            "IP reputation could not be verified"
        )


    # ========================================================
    # AGENT 6 - RESPONSE RECOMMENDATION
    # ========================================================

    response_result = generate_response(
        triage_result,
        investigation_result,
        risk_result
    )


    # ========================================================
    # INCIDENT OVERVIEW
    # ========================================================

    st.divider()

    st.markdown("### 🚨 Incident Overview")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Risk Level",
            risk_result["risk_level"]
        )

    with col2:
        st.metric(
            "Raw Risk Score",
            risk_result["risk_score"]
        )

    with col3:
        st.metric(
            "Confidence",
            risk_result["confidence"]
        )

    with col4:
        st.metric(
            "Correlation",
            correlation_result["correlation_level"]
        )


    # ========================================================
    # ALERT DETAILS
    # ========================================================

    st.divider()

    st.markdown("### 🔔 Security Alert")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.write("**User**")
        st.info(triage_result["user"])

    with col2:
        st.write("**Source IP**")
        st.info(triage_result["ip"])

    with col3:
        st.write("**Severity**")
        st.warning(triage_result["severity"])

    with col4:
        st.write("**Scenario**")
        st.info(scenario)


    # ========================================================
    # AGENT PIPELINE
    # ========================================================

    st.divider()

    st.markdown("### 🤖 Agent Pipeline")

    pipeline = [
        "Alert Triage",
        "Log Analysis",
        "Threat Correlation",
        "Security Investigation",
        "Risk Assessment",
        "Evidence Validation",
        "Threat Intelligence",
        "Response Recommendation"
    ]

    cols = st.columns(4)

    for index, agent in enumerate(pipeline):

        with cols[index % 4]:

            st.success(
                f"✓ {agent}"
            )


    # ========================================================
    # LOG ANALYSIS
    # ========================================================

    st.divider()

    st.markdown("### 📊 Log Analysis")

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric(
            "Total Events",
            log_result["total_events"]
        )

    with col2:
        st.metric(
            "Failed Logins",
            log_result["failed_logins"]
        )

    with col3:
        st.metric(
            "Successful Logins",
            log_result["successful_logins"]
        )

    with col4:
        st.metric(
            "New Devices",
            log_result["new_devices"]
        )

    with col5:
        st.metric(
            "Privileged Access",
            log_result["privileged_access"]
        )


    # ========================================================
    # THREAT CORRELATION
    # ========================================================

    st.divider()

    st.markdown("### 🔎 Threat Correlation")

    col1, col2 = st.columns(2)

    with col1:

        st.write("**Detected Pattern**")

        st.warning(
            correlation_result["pattern"]
        )

        st.write("**Correlation Score**")

        st.metric(
            "Score",
            correlation_result["score"]
        )

    with col2:

        st.write("**Evidence**")

        for evidence in correlation_result["evidence"]:

            st.write(
                "•",
                evidence
            )


    # ========================================================
    # SECURITY INVESTIGATION
    # ========================================================

    st.divider()

    st.markdown("### 🕵️ Security Investigation")

    st.write(
        investigation_result["summary"]
    )

    with st.expander(
        "📅 Investigation Timeline",
        expanded=True
    ):

        for event in investigation_result["timeline"]:

            st.write(
                "•",
                event
            )


    with st.expander(
        "🔍 Investigation Steps"
    ):

        for step in investigation_result[
            "investigation_steps"
        ]:

            st.write(
                "•",
                step
            )


    # ========================================================
    # EVIDENCE VALIDATION
    # ========================================================

    st.divider()

    st.markdown("### 🧠 Evidence Validation")

    if evidence_status == "SUPPORTS_SUSPICION":

        st.success(
            "✓ Evidence supports the current suspicious activity assessment."
        )

    elif evidence_status == "MIXED":

        st.warning(
            "⚠ Evidence is mixed. Additional investigation is recommended."
        )

    elif evidence_status == "CONFLICTING":

        st.error(
            "⚠ Conflicting evidence detected. "
            "Attack cannot be confirmed."
        )

    else:

        st.info(
            "Evidence status could not be determined."
        )


    col1, col2 = st.columns(2)

    with col1:

        st.write("**Evidence Status**")

        st.write(
            evidence_status
        )

    with col2:

        st.write("**Attack Confirmation**")

        st.write(
            evidence_result[
                "attack_confirmation"
            ]
        )


    if evidence_result["contradictions"]:

        st.write("### ⚠️ Contradictory Evidence")

        for item in evidence_result[
            "contradictions"
        ]:

            st.warning(item)


    # ========================================================
    # THREAT INTELLIGENCE
    # ========================================================

    st.divider()

    st.markdown("### 🌐 Threat Intelligence")

    if tool_result["status"] == "SUCCESS":

        st.success(
            "✓ Threat Intelligence Tool completed successfully."
        )

        st.write(
            tool_result["result"]
        )

    else:

        st.error(
            "✕ Threat Intelligence Tool failed."
        )

        st.warning(
            tool_result["message"]
        )

        st.info(
            tool_result["safe_action"]
        )


    # ========================================================
    # RISK FACTORS
    # ========================================================

    st.divider()

    st.markdown("### ⚠️ Risk Factors")

    for factor in risk_result.get(
        "risk_factors",
        []
    ):

        st.write(
            "•",
            factor
        )


    # ========================================================
    # RESPONSE
    # ========================================================

    st.divider()

    st.markdown("### 🛡️ Recommended Response")

    response_summary = (
        response_result.get(
            "response_summary"
        )
        or response_result.get(
            "summary"
        )
        or response_result.get(
            "response"
        )
        or response_result.get(
            "recommendation"
        )
        or "Response recommendation generated."
    )

    st.info(
        response_summary
    )


    col1, col2 = st.columns(2)

    with col1:

        st.write("**Immediate Actions**")

        for action in response_result.get(
            "immediate_actions",
            []
        ):

            st.write(
                "•",
                action
            )

        st.write("**Investigation Actions**")

        for action in response_result.get(
            "investigation_actions",
            []
        ):

            st.write(
                "•",
                action
            )


    with col2:

        st.write("**Follow-up Actions**")

        for action in response_result.get(
            "follow_up_actions",
            []
        ):

            st.write(
                "•",
                action
            )


    # ========================================================
    # FINAL SOC ASSESSMENT
    # ========================================================

    st.divider()

    st.markdown("### 🎯 Final SOC Assessment")

    if risk_result["risk_level"] == "CRITICAL":

        st.error(
            f"CRITICAL RISK — {correlation_result['pattern']}"
        )

    elif risk_result["risk_level"] == "HIGH":

        st.warning(
            f"HIGH RISK — {correlation_result['pattern']}"
        )

    elif risk_result["risk_level"] == "UNKNOWN":

        st.warning(
            "UNKNOWN RISK — Attack cannot be confirmed "
            "with the current evidence."
        )

    else:

        st.success(
            f"{risk_result['risk_level']} RISK"
        )


else:

    # ========================================================
    # START SCREEN
    # ========================================================

    st.divider()

    st.info(
        "👈 Select an investigation scenario from the sidebar "
        "and click **Run Investigation**."
    )

    st.markdown("### What CyberSentinel AI Does")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.markdown(
            """
            ### 🚨 Detect

            Receives and triages simulated
            security alerts.
            """
        )

    with col2:

        st.markdown(
            """
            ### 🔎 Investigate

            Correlates authentication,
            device and privilege activity.
            """
        )

    with col3:

        st.markdown(
            """
            ### 🛡️ Respond

            Calculates risk and recommends
            appropriate SOC actions.
            """
        )