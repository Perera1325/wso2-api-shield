import pandas as pd
from pathlib import Path

DATA_FILE = Path("data/processed/wso2_api_logs.csv")
OUT_ENRICHED = Path("data/processed/wso2_api_logs_enriched.csv")
OUT_ALERTS = Path("reports/attack_alerts.csv")

# ✅ Attack thresholds (more realistic for your dataset)
BURST_THRESHOLD = 15          # requests per 10 seconds
SCAN_THRESHOLD = 5            # unique endpoints per 10 seconds
AUTH_FAIL_THRESHOLD = 5       # 401/403 per 10 seconds

def main():
    if not DATA_FILE.exists():
        print("❌ Missing dataset:", DATA_FILE)
        print("Run Day 2 first.")
        return

    df = pd.read_csv(DATA_FILE)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp")

    # ✅ Use 10-second bucket (instead of 1 minute)
    df["time_bucket"] = df["timestamp"].dt.floor("10S")

    # 1) Burst detection: requests per IP per bucket
    req_per_ip = (
        df.groupby(["client_ip", "time_bucket"])
        .size()
        .reset_index(name="req_count_bucket")
    )
    df = df.merge(req_per_ip, on=["client_ip", "time_bucket"], how="left")
    df["burst_flag"] = (df["req_count_bucket"] >= BURST_THRESHOLD).astype(int)

    # 2) Endpoint scanning: unique endpoints per IP per bucket
    uniq_endpoints = (
        df.groupby(["client_ip", "time_bucket"])["resource"]
        .nunique()
        .reset_index(name="unique_endpoints_bucket")
    )
    df = df.merge(uniq_endpoints, on=["client_ip", "time_bucket"], how="left")
    df["scan_flag"] = (df["unique_endpoints_bucket"] >= SCAN_THRESHOLD).astype(int)

    # 3) Auth abuse: 401/403 per IP per bucket
    df["auth_fail"] = df["status_code"].isin([401, 403]).astype(int)

    auth_fails = (
        df.groupby(["client_ip", "time_bucket"])["auth_fail"]
        .sum()
        .reset_index(name="auth_fails_bucket")
    )
    df = df.merge(auth_fails, on=["client_ip", "time_bucket"], how="left")
    df["auth_abuse_flag"] = (df["auth_fails_bucket"] >= AUTH_FAIL_THRESHOLD).astype(int)

    # 4) Risk score (0–100)
    df["attack_risk_score"] = (
        df["burst_flag"] * 40 +
        df["scan_flag"] * 35 +
        df["auth_abuse_flag"] * 25
    ).clip(0, 100)

    # ✅ Attack detected if >= 50
    df["attack_detected"] = (df["attack_risk_score"] >= 50).astype(int)

    # Save enriched dataset
    OUT_ENRICHED.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_ENRICHED, index=False)

    # Build alerts summary
    alerts = df[df["attack_detected"] == 1].copy()

    attack_summary = (
        alerts.groupby(["client_ip", "time_bucket"])
        .agg(
            total_requests=("req_count_bucket", "max"),
            endpoints_hit=("unique_endpoints_bucket", "max"),
            auth_fails=("auth_fails_bucket", "max"),
            avg_latency=("latency_ms", "mean"),
            max_risk=("attack_risk_score", "max"),
        )
        .reset_index()
        .sort_values("max_risk", ascending=False)
    )

    OUT_ALERTS.parent.mkdir(parents=True, exist_ok=True)
    attack_summary.to_csv(OUT_ALERTS, index=False)

    print("✅ Day 4 Attack Pattern Detection Completed (10-second buckets)!")
    print(f"📌 Enriched dataset: {OUT_ENRICHED}")
    print(f"📌 Alerts file: {OUT_ALERTS}")

    print("\n✅ attack_detected distribution:")
    print(df["attack_detected"].value_counts())

    print("\n🔥 Top 10 alerts:")
    print(attack_summary.head(10))

if __name__ == "__main__":
    main()
