import time
import joblib
import pandas as pd
from pathlib import Path
from datetime import datetime
from tqdm import tqdm

DATA_FILE = Path("data/processed/wso2_api_logs_enriched.csv")
MODEL_FILE = Path("models/attack_model.pkl")
OUT_FILE = Path("reports/live_alerts.csv")

# Streaming settings
SLEEP_SECONDS = 0.01   # speed control (0.01 = fast streaming)
ALERT_THRESHOLD = 0.80 # probability threshold for attack alerts

def print_alert(row, prob):
    print(
        f"\n🚨 [ALERT] {row['timestamp']} | IP={row['client_ip']} | API={row['api_name']} "
        f"| {row['http_method']} {row['resource']} | status={row['status_code']} "
        f"| risk={row['attack_risk_score']} | ML_prob={prob:.2f}"
    )

    # WSO2 style mitigation suggestion
    if prob >= 0.95:
        print("   ✅ Suggested Action: BLOCK IP (Firewall/IP blacklisting) + Revoke Token")
    elif prob >= 0.85:
        print("   ✅ Suggested Action: Apply WSO2 Throttling Policy (429) + Step-up Auth")
    else:
        print("   ✅ Suggested Action: Monitor + Rate Limit temporarily")


def main():
    if not DATA_FILE.exists():
        print("❌ Missing enriched dataset:", DATA_FILE)
        print("Run Day 4 first.")
        return

    if not MODEL_FILE.exists():
        print("❌ Missing model:", MODEL_FILE)
        print("Run Day 5 first.")
        return

    print("✅ Loading dataset...")
    df = pd.read_csv(DATA_FILE)

    print("✅ Loading ML model...")
    model = joblib.load(MODEL_FILE)

    # features must match Day 5
    feature_cols = [
        "api_name", "http_method", "resource", "status_code",
        "latency_ms", "payload_size",
        "req_count_bucket", "unique_endpoints_bucket", "auth_fails_bucket",
        "burst_flag", "scan_flag", "auth_abuse_flag",
        "attack_risk_score"
    ]

    # keep only columns we need
    df = df.dropna(subset=feature_cols)

    print("\n🚀 Starting REAL-TIME stream detection...\n")
    print("Press CTRL + C to stop.\n")

    alerts = []

    try:
        for _, row in tqdm(df.iterrows(), total=len(df)):
            X = pd.DataFrame([row[feature_cols].to_dict()])

            # model outputs prob attack
            prob = model.predict_proba(X)[0][1]

            if prob >= ALERT_THRESHOLD:
                print_alert(row, prob)
                alerts.append({
                    "timestamp": row["timestamp"],
                    "client_ip": row["client_ip"],
                    "api_name": row["api_name"],
                    "method": row["http_method"],
                    "resource": row["resource"],
                    "status_code": row["status_code"],
                    "risk_score": row["attack_risk_score"],
                    "ml_probability": prob,
                    "suggested_action": (
                        "BLOCK" if prob >= 0.95 else
                        "THROTTLE" if prob >= 0.85 else
                        "MONITOR"
                    )
                })

            time.sleep(SLEEP_SECONDS)

    except KeyboardInterrupt:
        print("\n\n⏹️ Streaming stopped by user.")

    # Save alerts to CSV
    if alerts:
        alert_df = pd.DataFrame(alerts)
        alert_df.to_csv(OUT_FILE, index=False)
        print(f"\n✅ Live alerts saved to: {OUT_FILE}")
        print(f"✅ Total alerts: {len(alerts)}")
    else:
        print("\n✅ No alerts generated in this run.")

    print("\n✅ Day 6 completed.")

if __name__ == "__main__":
    main()
