from pathlib import Path
import json

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agents.triage import triage_alert
from agents.log_analysis import analyze_logs
from agents.correlation import correlate_threat
from agents.investigation import investigate_threat
from agents.risk import assess_risk
from agents.response import generate_response
from agents.evidence_validation import validate_evidence
from agents.tool_failure import check_threat_intelligence


# ============================================================
# CYBERSENTINEL AI API
# ============================================================

app = FastAPI(
    title="CyberSentinel AI API",
    description="Agentic SOC Investigation API",
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# REQUEST MODEL
# ============================================================

class InvestigationRequest(BaseModel):
    scenario: str = "normal"


# ============================================================
# HELPERS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "data" / "security_logs.json"


def load_security_logs():
    """Load the simulated security logs."""
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return []


def normalize_triage(triage_result, alert):
    """Normalize triage output."""
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

    return triage_result


def get_response_summary(response_result):
    """Extract the response summary safely."""
    return (
        response_result.get("response_summary")
        or response_result.get("summary")
        or response_result.get("response")
        or response_result.get("recommendation")
        or "Response recommendation generated."
    )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "name": "CyberSentinel AI",
        "status": "online",
        "message": "SOC Investigation API is running",
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "CyberSentinel AI API",
    }


# ============================================================
# RUN INVESTIGATION
# ============================================================

@app.post("/api/investigate")
def investigate(request: InvestigationRequest):

    scenario = request.scenario.lower().strip()

    # Only allow known demo scenarios
    allowed_scenarios = {
        "normal",
        "tool_failure",
        "contradictory",
    }

    if scenario not in allowed_scenarios:
        scenario = "normal"

    # ========================================================
    # SECURITY ALERT
    # ========================================================

    alert = {
        "type": "authentication",
        "user": "admin",
        "failed_attempts": 8,
        "ip": "185.22.91.44",
    }

    # ========================================================
    # AGENT 1 - ALERT TRIAGE
    # ========================================================

    triage_result = triage_alert(alert)
    triage_result = normalize_triage(
        triage_result,
        alert
    )

    # ========================================================
    # AGENT 2 - LOG ANALYSIS
    # ========================================================

    log_result = analyze_logs()

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
        correlation_result,
    )

    # ========================================================
    # AGENT 5 - RISK ASSESSMENT
    # ========================================================

    risk_result = assess_risk(
        triage_result,
        log_result,
        correlation_result,
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
        correlation_result,
    )

    evidence_status = evidence_result.get(
        "evidence_status",
        "UNKNOWN"
    )

    # ========================================================
    # CONTRADICTORY EVIDENCE DEMO
    # ========================================================
    #
    # This is an explicit hackathon simulation.
    # It demonstrates what the system should do when evidence
    # conflicts instead of automatically confirming an attack.
    #

    if scenario == "contradictory":

        evidence_status = "CONFLICTING"

        evidence_result["evidence_status"] = "CONFLICTING"
        evidence_result["attack_confirmation"] = "REQUIRES_REVIEW"
        evidence_result["confidence"] = "LOW"

        evidence_result["contradictions"] = [
            "Authentication evidence conflicts with available device context.",
            "Attack cannot be confirmed from the available evidence.",
        ]

        risk_result["risk_level"] = "UNKNOWN"
        risk_result["confidence"] = "LOW"

        if "risk_factors" not in risk_result:
            risk_result["risk_factors"] = []

        risk_result["risk_factors"].append(
            "Contradictory evidence detected - attack cannot be confirmed"
        )

    # ========================================================
    # MIXED EVIDENCE
    # ========================================================

    elif evidence_status == "MIXED":

        risk_result["confidence"] = "MEDIUM"

        risk_result["risk_factors"].append(
            "Mixed evidence detected - additional investigation required"
        )

    # ========================================================
    # THREAT INTELLIGENCE TOOL
    # ========================================================

    simulate_tool_failure = (
        scenario == "tool_failure"
    )

    tool_result = check_threat_intelligence(
        triage_result["ip"],
        simulate_failure=simulate_tool_failure,
    )

    # ========================================================
    # TOOL FAILURE SAFETY
    # ========================================================

    if tool_result.get("status") == "FAILED":

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
        risk_result,
    )

    # ========================================================
    # LOAD RAW LOGS
    # ========================================================

    security_logs = load_security_logs()

    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    return {
        "status": "success",

        "scenario": scenario,

        # Alert
        "alert": alert,

        # Agent 1
        "triage": triage_result,

        # Agent 2
        "log_analysis": log_result,

        # Agent 3
        "correlation": correlation_result,

        # Agent 4
        "investigation": investigation_result,

        # Agent 5
        "risk": {
            "risk_level": risk_result.get(
                "risk_level",
                "UNKNOWN"
            ),
            "risk_score": risk_result.get(
                "risk_score",
                0
            ),
            "confidence": risk_result.get(
                "confidence",
                "LOW"
            ),
            "risk_factors": risk_result.get(
                "risk_factors",
                []
            ),
        },

        # Evidence validation
        "evidence_validation": {
            "evidence_status": evidence_result.get(
                "evidence_status",
                "UNKNOWN"
            ),
            "attack_confirmation": evidence_result.get(
                "attack_confirmation",
                "UNKNOWN"
            ),
            "confidence": evidence_result.get(
                "confidence",
                "LOW"
            ),
            "contradictions": evidence_result.get(
                "contradictions",
                []
            ),
            "original_pattern": evidence_result.get(
                "original_pattern",
                correlation_result.get(
                    "pattern",
                    "Unknown"
                ),
            ),
        },

        # Threat intelligence
        "threat_intelligence": tool_result,

        # Agent 6
        "response": {
            "response_level": response_result.get(
                "response_level",
                risk_result.get(
                    "risk_level",
                    "UNKNOWN"
                ),
            ),
            "summary": get_response_summary(
                response_result
            ),
            "immediate_actions": response_result.get(
                "immediate_actions",
                []
            ),
            "investigation_actions": response_result.get(
                "investigation_actions",
                []
            ),
            "follow_up_actions": response_result.get(
                "follow_up_actions",
                []
            ),
        },

        # Raw events for frontend timeline/table
        "security_logs": security_logs,

        # Pipeline
        "pipeline": [
            {
                "agent": "Alert Triage",
                "status": "COMPLETED",
            },
            {
                "agent": "Log Analysis",
                "status": "COMPLETED",
            },
            {
                "agent": "Threat Correlation",
                "status": "COMPLETED",
            },
            {
                "agent": "Security Investigation",
                "status": "COMPLETED",
            },
            {
                "agent": "Evidence Validation",
                "status": "COMPLETED",
            },
            {
                "agent": "Risk Assessment",
                "status": "COMPLETED",
            },
            {
                "agent": "Response Recommendation",
                "status": "COMPLETED",
            },
        ],
    }