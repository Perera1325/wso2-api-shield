import random
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta

RAW_DIR = Path("data")
OUT_DIR = Path("data/processed")
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUT_DIR / "wso2_api_logs.csv"

# Skip label files
SKIP_FILES = {
    "anomaly_labels.txt",
    "abnormal_label.txt",
    "normal_label.txt",
    "anomaly_label.txt"
}

# Fake APIs (WSO2 API Manager style)
APIS = [
    ("PaymentAPI", "1.0.0"),
    ("UserAPI", "2.1.0"),
    ("OrderAPI", "1.5.2"),
    ("InventoryAPI", "1.2.0"),
    ("AdminAPI", "0.9.0"),
]

METHODS = ["GET", "POST", "PUT", "DELETE"]

ENDPOINTS = [
    "/payment/charge",
    "/payment/refund",
    "/user/login",
    "/user/profile",
    "/order/create",
    "/order/status",
    "/inventory/check",
    "/support/ticket",
    "/admin/health",
    "/admin/metrics"
]

USER_AGENTS = [
    "Mozilla/5.0",
    "PostmanRuntime/7.35.0",
    "curl/8.0.1",
    "python-requests/2.31.0",
    "okhttp/4.10.0",
    "Java/17"
]

def generate_ip():
    return f"{random.randint(10, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def random_timestamp(start_time):
    return start_time + timedelta(seconds=random.randint(0, 60 * 60 * 24))

def read_log_lines(log_file: Path, max_lines=300):
    """Read first N lines from a log file safely."""
    lines = []
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                line = line.strip()
                if line:
                    lines.append(line)
    except Exception:
        pass
    return lines

def is_anomaly(line: str):
    """Simple keyword-based anomaly labeling from raw log text."""
    keys = ["error", "fail", "warn", "exception", "timeout", "denied", "invalid"]
    return 1 if any(k in line.lower() for k in keys) else 0

def build_dataset():
    start_time = datetime.now() - timedelta(days=10)

    # collect log files
    raw_files = []
    for p in RAW_DIR.rglob("*"):
        if p.is_file():
            name = p.name.lower()
            if name in SKIP_FILES:
                continue
            if name.endswith(".log") or name.endswith(".txt"):
                raw_files.append(p)

    if not raw_files:
        print("❌ No log files found inside data/ folder.")
        return None

    print(f"✅ Found {len(raw_files)} log files.")
    all_logs = []

    for file in raw_files:
        lines = read_log_lines(file, max_lines=250)
        if not lines:
            continue

        for line in lines:
            api_name, api_version = random.choice(APIS)
            endpoint = random.choice(ENDPOINTS)
            method = random.choice(METHODS)

            # base values
            latency = max(5, int(random.gauss(250, 80)))
            payload = max(60, int(random.gauss(900, 250)))

            label = is_anomaly(line)

            # anomaly behavior
            if label == 1:
                latency *= random.randint(3, 12)
                payload *= random.randint(2, 8)
                status = random.choice([401, 403, 404, 429, 500, 503])
            else:
                status = random.choice([200, 201, 202, 204])

            ts = random_timestamp(start_time)

            all_logs.append({
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "api_name": api_name,
                "api_version": api_version,
                "http_method": method,
                "resource": endpoint,
                "status_code": status,
                "latency_ms": latency,
                "payload_size": payload,
                "client_ip": generate_ip(),
                "user_agent": random.choice(USER_AGENTS),
                "raw_source": file.name,
                "anomaly_label": label,
                "raw_line": line[:250]
            })

    df = pd.DataFrame(all_logs)
    return df

def main():
    df = build_dataset()
    if df is None:
        return

    df.to_csv(OUTPUT_FILE, index=False)
    print("\n✅ WSO2 API Gateway style dataset created!")
    print(f"📌 Saved: {OUTPUT_FILE}")
    print("\n✅ Sample rows:")
    print(df.head(3))

    print("\n✅ Label distribution:")
    print(df["anomaly_label"].value_counts())

if __name__ == "__main__":
    main()
