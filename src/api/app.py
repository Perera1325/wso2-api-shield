from fastapi import FastAPI
from pydantic import BaseModel, Field
from pathlib import Path
import pandas as pd
import joblib
from datetime import datetime

# Paths
MODEL_FILE = Path("models/attack_model.pkl")
ALERTS_FILE = Path("reports/live_alerts.csv")

app = FastAPI(
    title="WSO2 API Shield",
    description="AI-powered API attack detection (WSO2 API Gateway style)",
    version="1.0.0"
)

# Load model at startup
model = None

# ✅ Features expected by model (must match Day 5)
FEATURE_COLS = [
    "api_name", "http_method", "resource", "status_code",
    "latency_ms", "payload_size",
    "req_count_bucket", "unique_endpoints_bucket", "auth_fails_bucket",
    "burst_flag", "scan_flag", "auth_abuse_flag",
    "attack_risk_score"
]

class DetectRequest(BaseModel):
    api_name: str = Field(..., example="UserAPI")
    http_method: str = Field(..., example="GET")
    resource: str = Field(..., example="/admin/metrics")
    status_code: int = Field(..., example=401)
    latency_ms: int = Field(..., example=900)
    payload_size: int = Field(..., example=1500)

    req_count_bucket: int = Field(..., example=25)
    unique_endpoints_bucket: int = Field(..., example=9)
    auth_fails_bucket: int = Field(..., example=12)

    burst_flag: int = Field(..., example=1)
    scan_flag: int = Field(..., example=1)
    auth_abuse_flag: int = Field(..., example=1)

    attack_risk_score: int = Field(..., example=95)

class DetectResponse(BaseModel):
    attack_probability: float
    predicted_attack: bool
    suggested_action: str
    model_version: str
    timestamp: str

@app.on_event("startup")
def startup_event():
    global model
    if not MODEL_FILE.exists():
        print("❌ Model not found:", MODEL_FILE)
        model = None
        return

    model = joblib.load(MODEL_FILE)
    print("✅ Model loaded:", MODEL_FILE)

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "WSO2 API Shield",
        "model_loaded": model is not None,
        "time": datetime.utcnow().isoformat()
    }

@app.post("/detect", response_model=DetectResponse)
def detect_attack(req: DetectRequest):
    if model is None:
        return {
            "attack_probability": 0.0,
            "predicted_attack": False,
            "suggested_action": "MODEL_NOT_LOADED",
            "model_version": "none",
            "timestamp": datetime.utcnow().isoformat()
        }

    X = pd.DataFrame([req.dict()])[FEATURE_COLS]
    prob = float(model.predict_proba(X)[0][1])
    predicted = prob >= 0.5

    # Suggested action logic (WSO2 style)
    if prob >= 0.95:
        action = "BLOCK_IP_AND_REVOKE_TOKEN"
    elif prob >= 0.85:
        action = "THROTTLE_AND_STEPUP_AUTH"
    elif prob >= 0.70:
        action = "TEMP_RATE_LIMIT_MONITOR"
    else:
        action = "ALLOW"

    return {
        "attack_probability": prob,
        "predicted_attack": bool(predicted),
        "suggested_action": action,
        "model_version": "attack_model.pkl",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/alerts")
def get_alerts(limit: int = 20):
    if not ALERTS_FILE.exists():
        return {"alerts": [], "message": "No live_alerts.csv found. Run Day 6 streaming first."}

    df = pd.read_csv(ALERTS_FILE)
    df = df.tail(limit)
    return {
        "total_alerts": len(df),
        "alerts": df.to_dict(orient="records")
    }

@app.get("/stats")
def stats():
    if not ALERTS_FILE.exists():
        return {"message": "No live_alerts.csv found. Run Day 6 streaming first."}

    df = pd.read_csv(ALERTS_FILE)

    top_ips = df["client_ip"].value_counts().head(10).to_dict()
    top_endpoints = df["resource"].value_counts().head(10).to_dict()
    actions = df["suggested_action"].value_counts().to_dict()

    return {
        "total_alerts": len(df),
        "top_attacker_ips": top_ips,
        "top_attacked_endpoints": top_endpoints,
        "action_distribution": actions
    }
