import streamlit as st
import pandas as pd
from pathlib import Path
import plotly.express as px
import requests
import json

st.set_page_config(
    page_title="WSO2 API Shield - SOC Dashboard",
    layout="wide"
)

ALERTS_FILE = Path("reports/live_alerts.csv")
API_URL = "http://127.0.0.1:8000"

st.title("🛡️ WSO2 API Shield — SOC Dashboard")
st.caption("Real-time AI/ML powered API Attack Detection | WSO2 Gateway Style Logs")

# -----------------------------
# Sidebar
# -----------------------------
st.sidebar.header("Controls")
refresh = st.sidebar.button("🔄 Refresh Dashboard")
limit = st.sidebar.slider("Alerts limit", 10, 500, 100)

use_api = st.sidebar.checkbox("Use FastAPI backend (/alerts, /stats)", value=False)

# -----------------------------
# Load alerts
# -----------------------------
def load_alerts_from_csv():
    if not ALERTS_FILE.exists():
        return pd.DataFrame()
    df = pd.read_csv(ALERTS_FILE)
    return df.tail(limit)

def load_alerts_from_api():
    try:
        r = requests.get(f"{API_URL}/alerts?limit={limit}", timeout=5)
        data = r.json()
        return pd.DataFrame(data.get("alerts", []))
    except Exception:
        return pd.DataFrame()

def load_stats_from_api():
    try:
        r = requests.get(f"{API_URL}/stats", timeout=5)
        return r.json()
    except Exception:
        return {}

alerts_df = load_alerts_from_api() if use_api else load_alerts_from_csv()

# -----------------------------
# If no alerts
# -----------------------------
if alerts_df.empty:
    st.warning("No alerts found. Run Day 6 stream detector to generate reports/live_alerts.csv")
    st.stop()

# -----------------------------
# Summary Metrics
# -----------------------------
col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts Loaded", len(alerts_df))
col2.metric("Unique Attacker IPs", alerts_df["client_ip"].nunique())
col3.metric("Unique Endpoints", alerts_df["resource"].nunique())
col4.metric("Top Action", alerts_df["suggested_action"].mode()[0])

st.divider()

# -----------------------------
# Charts
# -----------------------------
left, right = st.columns(2)

# Top attacker IPs
top_ips = alerts_df["client_ip"].value_counts().head(10).reset_index()
top_ips.columns = ["client_ip", "count"]

fig_ips = px.bar(top_ips, x="client_ip", y="count", title="Top Attacker IPs (Top 10)")
left.plotly_chart(fig_ips, use_container_width=True)

# Top attacked endpoints
top_endpoints = alerts_df["resource"].value_counts().head(10).reset_index()
top_endpoints.columns = ["resource", "count"]

fig_endpoints = px.bar(top_endpoints, x="resource", y="count", title="Top Attacked Endpoints (Top 10)")
right.plotly_chart(fig_endpoints, use_container_width=True)

# Action distribution
actions = alerts_df["suggested_action"].value_counts().reset_index()
actions.columns = ["action", "count"]
fig_actions = px.pie(actions, values="count", names="action", title="Suggested Action Distribution")
st.plotly_chart(fig_actions, use_container_width=True)

# Risk Score distribution
if "risk_score" in alerts_df.columns:
    fig_risk = px.histogram(alerts_df, x="risk_score", nbins=20, title="Risk Score Distribution")
    st.plotly_chart(fig_risk, use_container_width=True)

st.divider()

# -----------------------------
# Alerts Table
# -----------------------------
st.subheader("🚨 Live Alerts")
st.dataframe(alerts_df.sort_values("ml_probability", ascending=False), use_container_width=True)

st.divider()

# -----------------------------
# Detect API Test Panel
# -----------------------------
st.subheader("🧪 Test Attack Detection API")

st.info("If FastAPI is running, you can send a request to /detect and see response here.")

sample_payload = {
    "api_name": "AdminAPI",
    "http_method": "GET",
    "resource": "/admin/metrics",
    "status_code": 401,
    "latency_ms": 1200,
    "payload_size": 1900,
    "req_count_bucket": 35,
    "unique_endpoints_bucket": 9,
    "auth_fails_bucket": 12,
    "burst_flag": 1,
    "scan_flag": 1,
    "auth_abuse_flag": 1,
    "attack_risk_score": 95
}

payload_text = st.text_area("Request JSON", value=json.dumps(sample_payload, indent=2), height=260)

if st.button("▶️ Send to /detect"):
    try:
        payload = json.loads(payload_text)
        resp = requests.post(f"{API_URL}/detect", json=payload, timeout=5)
        st.success("Response received ✅")
        st.json(resp.json())
    except Exception as e:
        st.error(f"Failed to call /detect: {e}")

