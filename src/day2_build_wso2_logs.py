import random
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta

RAW_DIR = Path("data")
OUT_DIR = Path("data/processed")
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUT_DIR / "wso2_api_logs.csv"

SKIP_FILES = {"anomaly_labels.txt", "abnormal_label.txt", "normal_label.txt", "anomaly_label.txt"}

APIS = [
    ("PaymentAPI", "1.0.0"),
    ("UserAPI", "2.1.0"),
    ("OrderAPI", "1.5.2"),
    ("InventoryAPI", "1.2.0"),
    ("AdminAPI", "0.9.0"),
]

METHODS = ["GET", "POST", "PUT", "DELETE"]

ENDPOINTS = [
    "/payment/charge", "/payment/refund",
    "/user/login", "/user/profile",
    "/order/create", "/order/status",
    "/inventory/check", "/support/ticket",
    "/admin/health", "/admin/metrics"
]

USER_AGENTS = [
    "Mozilla/5.0",
    "PostmanRuntime/7.35.0",
    "curl/8.0.1",
    "python-requests/2.31.0",
    "okhttp/4.10.0",
    "Java/17"
]

ATTACKER_IPS = ["91.210.10.4", "91.210.10.5", "185.33.22.1"]
NORMAL_IPS = [f"{random.randint(10, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}" for _ in range(500)]

def random_timestamp(start_time):
    return start_time + timedelta(seconds=random.randint(0, 60 * 60 * 24))

def read_log_lines(log_file: Path, max_lines=200):
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

def generate_normal_record(line, ts, file_name):
    api_name, api_version = random.choice(APIS)
    endpoint = random.choice(ENDPOINTS)
    method = random.choice(METHODS)

    latency = max(10, int(random.gauss(220, 70)))
    payload = max(60, int(random.gauss(900, 250)))

    status = random.choice([200, 201, 202, 204])

    return {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "api_name": api_name,
        "api_version": api_version,
        "http_method": method,
        "resource": endpoint,
        "status_code": status,
        "latency_ms": latency,
        "payload_size": payload,
        "client_ip": random.choice(NORMAL_IPS),
        "user_agent": random.choice(USER_AGENTS),
        "raw_source": file_name,
        "anomaly_label": 0,
        "raw_line": line[:250],
    }

def generate_attack_records(base_ts, file_name, attack_type="burst"):
    """Generate a small attack session from SAME attacker IP in same time window."""
    attacker_ip = random.choice(ATTACKER_IPS)
    api_name, api_version = random.choice(APIS)

    records = []
    session_size = random.randint(30, 80)

    for i in range(session_size):
        ts = base_ts + timedelta(seconds=random.randint(0, 9))  # same 10-sec window
        method = random.choice(["GET", "POST"])

        if attack_type == "scan":
            endpoint = random.choice(ENDPOINTS)  # many unique endpoints
        else:
            endpoint = random.choice(["/user/login", "/admin/metrics", "/admin/health"])

        # bad status for attack
        status = random.choice([401, 403, 429, 500])

        latency = max(50, int(random.gauss(900, 250)))
        payload = max(200, int(random.gauss(1800, 500)))

        records.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "api_name": api_name,
            "api_version": api_version,
            "http_method": method,
            "resource": endpoint,
            "status_code": status,
            "latency_ms": latency,
            "payload_size": payload,
            "client_ip": attacker_ip,
            "user_agent": random.choice(["curl/8.0.1", "python-requests/2.31.0"]),
            "raw_source": file_name,
            "anomaly_label": 1,
            "raw_line": f"[ATTACK:{attack_type}] simulated event",
        })
    return records

def main():
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
        print("❌ No log files found inside data/")
        return

    print(f"✅ Found {len(raw_files)} raw files. Building WSO2 dataset...")

    all_logs = []

    for file in raw_files[:300]:  # limit processing for speed
        lines = read_log_lines(file, max_lines=120)
        if not lines:
            continue

        for line in lines:
            ts = random_timestamp(start_time)

            # 80% normal, 20% attack sessions
            if random.random() < 0.20:
                attack_type = random.choice(["burst", "scan", "auth_abuse"])
                all_logs.extend(generate_attack_records(ts, file.name, attack_type))
            else:
                all_logs.append(generate_normal_record(line, ts, file.name))

    df = pd.DataFrame(all_logs)
    df.to_csv(OUTPUT_FILE, index=False)

    print("\n✅ Created wso2_api_logs.csv with attack sessions!")
    print("📌 Saved:", OUTPUT_FILE)
    print("\n✅ anomaly_label distribution:")
    print(df["anomaly_label"].value_counts())

if __name__ == "__main__":
    main()
