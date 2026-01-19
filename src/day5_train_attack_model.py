import pandas as pd
import numpy as np
from pathlib import Path
import joblib
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.ensemble import RandomForestClassifier

DATA_FILE = Path("data/processed/wso2_api_logs_enriched.csv")

MODEL_DIR = Path("models")
REPORT_DIR = Path("reports")
FIG_DIR = Path("reports/figures")

MODEL_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)
FIG_DIR.mkdir(parents=True, exist_ok=True)

MODEL_FILE = MODEL_DIR / "attack_model.pkl"
PRED_FILE = REPORT_DIR / "ml_attack_predictions.csv"

def save_fig(path: Path):
    plt.tight_layout()
    plt.savefig(path)
    plt.close()

def main():
    if not DATA_FILE.exists():
        print("❌ Missing enriched dataset:", DATA_FILE)
        print("Run Day 4 first.")
        return

    df = pd.read_csv(DATA_FILE)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    # target
    y = df["attack_detected"].astype(int)

    print("✅ attack_detected distribution:")
    print(y.value_counts())

    if y.nunique() < 2:
        print("\n❌ Only ONE class found. Re-run Day 4 (attack generation).")
        return

    # ✅ IMPORTANT: updated feature columns based on Day 4 output
    feature_cols = [
        "api_name", "http_method", "resource", "status_code",
        "latency_ms", "payload_size",
        "req_count_bucket", "unique_endpoints_bucket", "auth_fails_bucket",
        "burst_flag", "scan_flag", "auth_abuse_flag",
        "attack_risk_score"
    ]

    # Make sure columns exist
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        print("❌ Missing columns:", missing)
        print("Please re-run Day 4 to regenerate enriched dataset correctly.")
        return

    X = df[feature_cols].copy()

    categorical = ["api_name", "http_method", "resource"]
    numeric = [c for c in feature_cols if c not in categorical]

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical),
            ("num", "passthrough", numeric),
        ]
    )

    model = RandomForestClassifier(
        n_estimators=250,
        random_state=42,
        class_weight="balanced"
    )

    pipe = Pipeline([
        ("prep", preprocessor),
        ("model", model)
    ])

    # split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print("\n✅ Training ML Attack Model (RandomForest)...")
    pipe.fit(X_train, y_train)

    y_pred = pipe.predict(X_test)

    probas = pipe.predict_proba(X_test)
    y_prob = probas[:, 1] if probas.shape[1] == 2 else np.zeros(len(y_test))

    print("\n✅ Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    print("\n✅ Classification Report:")
    print(classification_report(y_test, y_pred, digits=4))

    try:
        auc = roc_auc_score(y_test, y_prob)
        print(f"✅ ROC-AUC: {auc:.4f}")
    except Exception:
        print("⚠️ ROC-AUC not available")

    # save model
    joblib.dump(pipe, MODEL_FILE)
    print(f"\n✅ Model saved: {MODEL_FILE}")

    # Full dataset predictions
    full_probs = pipe.predict_proba(X)[:, 1]
    out = df.copy()
    out["ml_attack_probability"] = full_probs
    out["ml_attack_predicted"] = (full_probs >= 0.5).astype(int)

    out.to_csv(PRED_FILE, index=False)
    print(f"✅ ML predictions saved: {PRED_FILE}")

    # Plot 1: Risk score distribution
    plt.figure()
    df["attack_risk_score"].hist(bins=30)
    plt.title("Attack Risk Score Distribution")
    plt.xlabel("Risk Score")
    plt.ylabel("Count")
    save_fig(FIG_DIR / "risk_score_distribution.png")

    # Plot 2: Top attacked endpoints (based on ML predicted)
    top_endpoints = (
        out[out["ml_attack_predicted"] == 1]["resource"]
        .value_counts()
        .head(10)
    )

    plt.figure()
    top_endpoints.plot(kind="bar")
    plt.title("Top Endpoints Flagged as Attacked (ML)")
    plt.xlabel("Endpoint")
    plt.ylabel("Count")
    save_fig(FIG_DIR / "top_attacked_endpoints.png")

    print("\n✅ Figures saved to reports/figures/")
    print(" - risk_score_distribution.png")
    print(" - top_attacked_endpoints.png")

    print("\n🔥 Top 10 suspicious events (highest probability):")
    print(out.sort_values("ml_attack_probability", ascending=False).head(10)[
        ["timestamp", "client_ip", "api_name", "http_method", "resource",
         "status_code", "req_count_bucket", "unique_endpoints_bucket", "auth_fails_bucket",
         "attack_risk_score", "ml_attack_probability"]
    ])

if __name__ == "__main__":
    main()
