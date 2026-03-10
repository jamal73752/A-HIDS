"""
ai_engine.py - AI/ML analysis engine for A-HIDS server.

Provides the AIEngine class which extracts features from collected client
data and runs:
  - RandomForestClassifier: multi-class threat classification
    (Normal=0, Suspicious=1, Malicious=2)
  - IsolationForest: unsupervised anomaly detection

Falls back to a deterministic heuristic when no trained model is available.
"""

import logging
import os
from typing import Any, Dict, List

import numpy as np

logger = logging.getLogger(__name__)

# ── Feature definition ────────────────────────────────────────────────────────
#
# Maintain this order exactly when extracting features from a payload and
# when training models – the index positions must match.
#
FEATURE_NAMES: List[str] = [
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "network_connections",
    "failed_logins",
    "suspicious_processes",
    "file_changes",
    "suspicious_network",
]

# Threat level labels
LABELS = {0: "Normal", 1: "Suspicious", 2: "Malicious"}

# File names for persisted models
RF_MODEL_FILE = "rf_model.pkl"
IF_MODEL_FILE = "isolation_forest.pkl"
ENCODER_FILE = "label_encoder.pkl"


class AIEngine:
    """
    Dual-model AI analysis engine.

    Loads pre-trained models from *model_path* on first predict call.
    If no models exist on disk the engine falls back to a simple
    rule-based heuristic so the system remains operational even before
    training data is available.

    Args:
        model_path:          Directory containing .pkl model files.
        anomaly_threshold:   IsolationForest score threshold below which
                             a sample is treated as anomalous (0–1 scale;
                             default 0.7 means top 30 % outliers).
    """

    def __init__(
        self,
        model_path: str = "models/",
        anomaly_threshold: float = 0.7,
    ):
        self._model_path = model_path
        self._anomaly_threshold = anomaly_threshold
        self._rf_model = None
        self._if_model = None
        self._models_loaded = False
        logger.debug(
            "AIEngine initialised – model_path=%s, threshold=%.2f",
            model_path,
            anomaly_threshold,
        )

    # ── Feature extraction ─────────────────────────────────────────────────────

    def extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """
        Convert a collected-data dict to a 1-D feature vector.

        Missing values are replaced with sensible defaults (0).

        Args:
            data: Payload dict from DataCollector.collect().

        Returns:
            numpy array of shape (8,) containing the feature values.
        """
        sys_info = data.get("system_info", {})
        network = data.get("network", {})
        log_events = data.get("log_events", [])
        file_integrity = data.get("file_integrity", {})

        # CPU / memory / disk – prefer top-level convenience keys
        cpu_usage = float(
            data.get("cpu_usage")
            or sys_info.get("cpu_usage")
            or (sys_info.get("cpu") or {}).get("overall_percent", 0)
            or 0
        )
        memory_usage = float(
            data.get("memory_usage")
            or sys_info.get("memory_usage")
            or (sys_info.get("memory") or {}).get("percent", 0)
            or 0
        )
        disk_usage = float(
            data.get("disk_usage")
            or sys_info.get("disk_usage")
            or 0
        )

        # Network connections
        net_conns = int(network.get("total_connections", 0))
        suspicious_net = int(network.get("suspicious_count", 0))

        # Failed login count from log events
        failed_logins = sum(
            1
            for evt in log_events
            if isinstance(evt, dict)
            and evt.get("pattern_matched") == "failed_login"
        )

        # Suspicious process count
        suspicious_procs = len(data.get("suspicious_processes", []))

        # File change count (modified + added + deleted)
        file_changes = (
            len(file_integrity.get("modified", []))
            + len(file_integrity.get("added", []))
            + len(file_integrity.get("deleted", []))
        )

        features = np.array(
            [
                cpu_usage,
                memory_usage,
                disk_usage,
                net_conns,
                failed_logins,
                suspicious_procs,
                file_changes,
                suspicious_net,
            ],
            dtype=float,
        )

        logger.debug("Extracted features: %s", features)
        return features

    # ── Model loading ──────────────────────────────────────────────────────────

    def _load_models(self) -> bool:
        """
        Attempt to load persisted models from disk.

        Returns:
            True if both models loaded successfully.
        """
        try:
            import joblib  # type: ignore

            rf_path = os.path.join(self._model_path, RF_MODEL_FILE)
            if_path = os.path.join(self._model_path, IF_MODEL_FILE)

            if not (os.path.isfile(rf_path) and os.path.isfile(if_path)):
                logger.info("Model files not found – using heuristic fallback")
                return False

            self._rf_model = joblib.load(rf_path)
            self._if_model = joblib.load(if_path)
            self._models_loaded = True
            logger.info("AI models loaded from %s", self._model_path)
            return True
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Could not load AI models: %s", exc)
            return False

    # ── Training ───────────────────────────────────────────────────────────────

    def train(self, csv_path: str | None = None) -> bool:
        """
        Train RandomForest and IsolationForest on labelled sample data.

        Args:
            csv_path: Path to a CSV file with feature columns and a
                      ``label`` column (0=Normal, 1=Suspicious, 2=Malicious).
                      Defaults to ``<model_path>/sample_data.csv``.

        Returns:
            True if training completed and models were saved.
        """
        import pandas as pd  # type: ignore
        import joblib  # type: ignore
        from sklearn.ensemble import RandomForestClassifier, IsolationForest
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import LabelEncoder
        from sklearn.metrics import accuracy_score

        if csv_path is None:
            csv_path = os.path.join(self._model_path, "sample_data.csv")

        if not os.path.isfile(csv_path):
            logger.error("Training data not found: %s", csv_path)
            return False

        try:
            df = pd.read_csv(csv_path)
            X = df[FEATURE_NAMES].values
            y = df["label"].values

            le = LabelEncoder()
            y_enc = le.fit_transform(y)

            X_train, X_test, y_train, y_test = train_test_split(
                X, y_enc, test_size=0.2, random_state=42
            )

            # Random Forest classifier
            rf = RandomForestClassifier(n_estimators=100, random_state=42)
            rf.fit(X_train, y_train)
            acc = accuracy_score(y_test, rf.predict(X_test))
            logger.info("RandomForest accuracy: %.4f", acc)

            # IsolationForest anomaly detector (trained on all data)
            iso = IsolationForest(
                n_estimators=100, contamination=0.2, random_state=42
            )
            iso.fit(X)

            os.makedirs(self._model_path, exist_ok=True)
            joblib.dump(rf, os.path.join(self._model_path, RF_MODEL_FILE))
            joblib.dump(iso, os.path.join(self._model_path, IF_MODEL_FILE))
            joblib.dump(le, os.path.join(self._model_path, ENCODER_FILE))

            self._rf_model = rf
            self._if_model = iso
            self._models_loaded = True
            logger.info("Models saved to %s", self._model_path)
            return True

        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Training failed: %s", exc, exc_info=True)
            return False

    # ── Heuristic fallback ─────────────────────────────────────────────────────

    def _heuristic_predict(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Deterministic rule-based threat assessment used when no model exists.

        Args:
            features: 1-D feature array (same order as FEATURE_NAMES).

        Returns:
            Prediction dict with classification, anomaly_score, confidence,
            and threat_level keys.
        """
        (
            cpu, mem, disk, net_conns,
            failed_logins, susp_procs, file_changes, susp_net
        ) = features

        score = 0

        # Scoring heuristics
        if cpu > 90:
            score += 3
        elif cpu > 70:
            score += 1

        if mem > 90:
            score += 2
        elif mem > 80:
            score += 1

        if failed_logins >= 5:
            score += 4
        elif failed_logins >= 2:
            score += 2

        if susp_procs >= 1:
            score += 3

        if file_changes >= 1:
            score += 3

        if susp_net >= 1:
            score += 3

        # Map score to class
        if score >= 6:
            classification = 2
        elif score >= 2:
            classification = 1
        else:
            classification = 0

        threat_level = LABELS[classification]
        confidence = min(0.5 + score * 0.05, 0.99)

        return {
            "classification": classification,
            "threat_level": threat_level,
            "confidence": round(confidence, 3),
            "anomaly_score": round(min(score / 12.0, 1.0), 3),
            "method": "heuristic",
            "features": dict(zip(FEATURE_NAMES, features.tolist())),
        }

    # ── Public prediction API ──────────────────────────────────────────────────

    def predict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse a collected-data payload and return a threat assessment.

        Attempts to use trained ML models; falls back to the heuristic
        if models are unavailable.

        Args:
            data: Payload dict from DataCollector.collect().

        Returns:
            Dict with keys:
              - ``classification``  – integer label (0/1/2)
              - ``threat_level``    – "Normal" / "Suspicious" / "Malicious"
              - ``confidence``      – float 0–1
              - ``anomaly_score``   – float 0–1 (higher = more anomalous)
              - ``method``          – "ml" or "heuristic"
              - ``features``        – extracted feature values
        """
        features = self.extract_features(data)

        # Lazy model loading on first predict call
        if not self._models_loaded:
            self._load_models()

        if not self._models_loaded or self._rf_model is None:
            return self._heuristic_predict(features)

        try:
            X = features.reshape(1, -1)

            # RF classification
            proba = self._rf_model.predict_proba(X)[0]
            classification = int(np.argmax(proba))
            confidence = float(np.max(proba))

            # Isolation Forest anomaly score
            # score_samples returns negative scores; higher (less negative)
            # = more normal.  We invert and normalise to [0, 1].
            raw_score = float(self._if_model.score_samples(X)[0])
            # Typical range is roughly -0.7 to 0.2; map to [0, 1]
            anomaly_score = float(np.clip((-raw_score - 0.0) / 0.8, 0, 1))

            # If anomaly score is high but RF says Normal, upgrade
            if anomaly_score > self._anomaly_threshold and classification == 0:
                classification = 1
                confidence = max(confidence, anomaly_score)

            return {
                "classification": classification,
                "threat_level": LABELS.get(classification, "Unknown"),
                "confidence": round(confidence, 3),
                "anomaly_score": round(anomaly_score, 3),
                "method": "ml",
                "features": dict(zip(FEATURE_NAMES, features.tolist())),
            }

        except Exception as exc:  # pylint: disable=broad-except
            logger.error("ML predict failed, using heuristic: %s", exc)
            return self._heuristic_predict(features)
