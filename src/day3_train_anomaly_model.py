import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
import joblib

DATA_FILE = Path("data/processed/wso2_api_logs.csv")
MODEL_DIR = Path("models")
REPORT_DIR = Path("reports")

MODEL_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

MODEL_FILE = MODEL_DIR / "isoforest.pkl"
PRED_FILE = REPORT_DIR / "anomaly_predictions.csv"

def main():
    if not DATA_FILE.exists():
        print("❌ Missing dataset:", DATA_FILE)
        print("Run Day 2 first to generate wso2_api_logs.csv")
        return

    df = pd.read_csv(DATA_FILE)

    # Basic cleanup
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    # New engineered features
    df["hour"] = df["timestamp"].dt.hour
    df["dayofweek"] = df["timestamp"].dt.dayofweek
    df["is_weekend"] = (df["dayofweek"] >= 5).astype(int)

    # Convert IP to simple features
    # Example: "120.4.100.9" -> first_octet=120
    df["ip_first_octet"] = df["client_ip"].astype(str).str.split(".").str[0].astype(int)

    # Select features
    feature_cols = [
        "api_name", "http_method", "resource", "status_code",
        "latency_ms", "payload_size", "user_agent",
        "hour", "dayofweek", "is_weekend", "ip_first_octet"
    ]

    # Target label (only for evaluation, IsolationForest is unsupervised)
    y_true = df["anomaly_label"].astype(int).values

    X = df[feature_cols].copy()

    # Define categorical vs numerical
    categorical_features = ["api_name", "http_method", "resource", "user_agent"]
    numerical_features = ["status_code", "latency_ms", "payload_size", "hour", "dayofweek", "is_weekend", "ip_first_octet"]

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
            ("num", "passthrough", numerical_features),
        ]
    )

    # IsolationForest
    model = IsolationForest(
        n_estimators=200,
        contamination=0.10,  # assume 10% anomalies (adjust later)
        random_state=42
    )

    pipe = Pipeline([
        ("prep", preprocessor),
        ("model", model)
    ])

    print("✅ Training IsolationForest model...")
    pipe.fit(X)

    # Predictions: -1 anomaly, +1 normal
    preds = pipe.predict(X)
    y_pred = np.where(preds == -1, 1, 0)

    print("\n✅ Evaluation (compare with anomaly_label from Day2 keyword labeling):")
    print(confusion_matrix(y_true, y_pred))
    print(classification_report(y_true, y_pred, digits=4))

    # Save model
    joblib.dump(pipe, MODEL_FILE)
    print(f"\n✅ Model saved: {MODEL_FILE}")

    # Save predictions report
    out = df.copy()
    out["predicted_anomaly"] = y_pred
    out["anomaly_score"] = pipe.named_steps["model"].score_samples(
        pipe.named_steps["prep"].transform(X)
    )

    out.to_csv(PRED_FILE, index=False)
    print(f"✅ Predictions saved: {PRED_FILE}")

    # Show top suspicious
    print("\n🔥 Top 10 suspicious logs (lowest score):")
    print(out.sort_values("anomaly_score").head(10)[
        ["timestamp", "api_name", "http_method", "resource", "status_code",
         "latency_ms", "payload_size", "client_ip", "anomaly_score", "predicted_anomaly"]
    ])

if __name__ == "__main__":
    main()
