"""
train_model.py - Model training script for A-HIDS.

Loads sample_data.csv, trains a RandomForestClassifier and an
IsolationForest model, evaluates accuracy, and saves the models to the
models/ directory using joblib.

Usage:
    python models/train_model.py
"""

import logging
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(_SCRIPT_DIR, "sample_data.csv")
RF_MODEL_PATH = os.path.join(_SCRIPT_DIR, "rf_model.pkl")
IF_MODEL_PATH = os.path.join(_SCRIPT_DIR, "isolation_forest.pkl")
ENCODER_PATH = os.path.join(_SCRIPT_DIR, "label_encoder.pkl")

# ── Feature definition (must match ai_engine.py) ──────────────────────────────

FEATURE_COLUMNS = [
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "network_connections",
    "failed_logins",
    "suspicious_processes",
    "file_changes",
    "suspicious_network",
]
LABEL_COLUMN = "label"
LABEL_NAMES = {0: "Normal", 1: "Suspicious", 2: "Malicious"}


def load_data(path: str) -> tuple[np.ndarray, np.ndarray]:
    """
    Load and validate the training CSV.

    Args:
        path: Absolute path to sample_data.csv.

    Returns:
        Tuple (X, y) as numpy arrays.

    Raises:
        SystemExit: If the file is missing or has wrong columns.
    """
    if not os.path.isfile(path):
        logger.error("Training data not found: %s", path)
        sys.exit(1)

    df = pd.read_csv(path)
    logger.info("Loaded %d rows from %s", len(df), path)

    missing = [c for c in FEATURE_COLUMNS + [LABEL_COLUMN] if c not in df.columns]
    if missing:
        logger.error("Missing columns in CSV: %s", missing)
        sys.exit(1)

    X = df[FEATURE_COLUMNS].values.astype(float)
    y = df[LABEL_COLUMN].values.astype(int)

    # Print class distribution
    unique, counts = np.unique(y, return_counts=True)
    for lbl, cnt in zip(unique, counts):
        logger.info("  Class %d (%s): %d samples", lbl, LABEL_NAMES.get(lbl, "?"), cnt)

    return X, y


def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> RandomForestClassifier:
    """
    Train a RandomForestClassifier and print evaluation metrics.

    Args:
        X_train, y_train: Training features and labels.
        X_test, y_test:   Test features and labels.

    Returns:
        Fitted RandomForestClassifier.
    """
    logger.info("Training RandomForestClassifier (n_estimators=100)…")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    logger.info("Test accuracy: %.4f (%.1f%%)", acc, acc * 100)

    report = classification_report(
        y_test,
        y_pred,
        target_names=[LABEL_NAMES[i] for i in sorted(LABEL_NAMES)],
    )
    print("\n── Classification Report ──────────────────────────────")
    print(report)

    return rf


def train_isolation_forest(X: np.ndarray) -> IsolationForest:
    """
    Train an IsolationForest anomaly detector on the full dataset.

    Args:
        X: All feature rows (unlabelled; IsolationForest is unsupervised).

    Returns:
        Fitted IsolationForest.
    """
    logger.info("Training IsolationForest (contamination=0.2)…")
    iso = IsolationForest(
        n_estimators=100,
        contamination=0.2,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X)

    # Quick sanity check
    scores = iso.decision_function(X)
    logger.info(
        "Anomaly scores – min: %.3f, max: %.3f, mean: %.3f",
        scores.min(),
        scores.max(),
        scores.mean(),
    )
    return iso


def save_models(
    rf: RandomForestClassifier,
    iso: IsolationForest,
    le: LabelEncoder,
) -> None:
    """Persist trained models to disk."""
    joblib.dump(rf, RF_MODEL_PATH)
    logger.info("RandomForest saved to %s", RF_MODEL_PATH)

    joblib.dump(iso, IF_MODEL_PATH)
    logger.info("IsolationForest saved to %s", IF_MODEL_PATH)

    joblib.dump(le, ENCODER_PATH)
    logger.info("LabelEncoder saved to %s", ENCODER_PATH)


def main() -> None:
    """Entry point: load data, train models, evaluate, and save."""
    logger.info("A-HIDS model training starting…")

    X, y = load_data(DATA_PATH)

    # Encode labels (already integers, but encoder is useful for inference)
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    # 80/20 train/test split stratified by class
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
    )
    logger.info(
        "Split – train: %d, test: %d", len(X_train), len(X_test)
    )

    rf = train_random_forest(X_train, y_train, X_test, y_test)
    iso = train_isolation_forest(X)

    save_models(rf, iso, le)
    logger.info("Training complete. Models ready for A-HIDS inference.")


if __name__ == "__main__":
    main()
