import pandas as pd
from pathlib import Path

DATA_FILE = Path("data/processed/wso2_api_logs.csv")
OUT_ENRICHED = Path("data/processed/wso2_api_logs_enriched.csv")
OUT_ALERTS = Path("reports/attack_alerts.csv")

def main():
    if not DATA_FILE.exists():
        print("❌ Missing dataset:", DATA_FILE)
        print("Run Day 2 first.")
        return

    df = pd.read_csv(DATA_FILE)

    # timestamp -> datetime
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp")

    # Create minute bucket for rate features
    df["minute_bucket"] = df["timestamp"].dt.floor("min")

    # -----------------------------
    # 1) Burst detection
    # requests per IP per minute
    # -----------------------------
    req_per_ip_min = (
        df.groupby(["client_ip", "minute_bucket"])
        .size()
        .reset_index(name="req_count_1min")
    )

    df = df.merge(req_per_ip_min, on=["client_ip", "minute_bucket"], how="left")

    # burst_flag if > threshold
    # (adjust later)
    df["burst_flag"] = (df["req_count_1min"] >= 30).astype(int)

    # -----------------------------
    # 2) Endpoint scanning
    # unique endpoints per IP per minute
    # -----------------------------
    uniq_endpoints = (
        df.groupby(["client_ip", "minute_bucket"])["resource"]
        .nunique()
        .reset_index(name="unique_endpoints_1min")
    )

    df = df.merge(uniq_endpoints, on=["client_ip", "minute_bucket"], how="left")
    df["scan_flag"] = (df["unique_endpoints_1min"] >= 8).astype(int)

    # -----------------------------
    # 3) Auth abuse
    # too many 401/403 per IP per minute
    # -----------------------------
    df["auth_fail"] = df["status_code"].isin([401, 403]).astype(int)

    auth_fail_counts = (
        df.groupby(["client_ip", "minute_bucket"])["auth_fail"]
        .sum()
        .reset_index(name="auth_fails_1min")
    )

    df = df.merge(auth_fail_counts, on=["client_ip", "minute_bucket"], how="left")
    df["auth_abuse_flag"] = (df["auth_fails_1min"] >= 10).astype(int)

    # -----------------------------
    # 4) Risk score
    # -----------------------------
    # weights (can tune later)
    df["attack_risk_score"] = (
        df["burst_flag"] * 30 +
        df["scan_flag"] * 40 +
        df["auth_abuse_flag"] * 30
    )

    # Make it 0-100
    df["attack_risk_score"] = df["attack_risk_score"].clip(0, 100)

    # Label attack if high score
    df["attack_detected"] = (df["attack_risk_score"] >= 60).astype(int)

    # Save enriched dataset
    OUT_ENRICHED.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_ENRICHED, index=False)

    # Build alerts table
    alerts = df[df["attack_detected"] == 1].copy()

    # summarize attacks by IP + minute bucket
    attack_summary = (
        alerts.groupby(["client_ip", "minute_bucket"])
        .agg(
            total_requests=("req_count_1min", "max"),
            endpoints_hit=("unique_endpoints_1min", "max"),
            auth_fails=("auth_fails_1min", "max"),
            avg_latency=("latency_ms", "mean"),
            max_risk=("attack_risk_score", "max"),
        )
        .reset_index()
        .sort_values("max_risk", ascending=False)
    )

    OUT_ALERTS.parent.mkdir(parents=True, exist_ok=True)
    attack_summary.to_csv(OUT_ALERTS, index=False)

    print("✅ Day 4 Attack Pattern Detection Completed!")
    print(f"📌 Enriched log dataset saved: {OUT_ENRICHED}")
    print(f"📌 Attack alerts saved: {OUT_ALERTS}")

    print("\n🔥 Top 10 attack alerts:")
    print(attack_summary.head(10))

if __name__ == "__main__":
    main()
