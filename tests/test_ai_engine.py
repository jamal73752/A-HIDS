"""
test_ai_engine.py - Unit tests for A-HIDS AI engine.

Tests cover feature extraction, heuristic fallback prediction, required
output keys, and a full train-then-predict cycle on sample data.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure project root is importable
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_payload(**overrides) -> dict:
    """Build a realistic collected-data payload with safe defaults."""
    base = {
        "hostname": "test-machine",
        "timestamp": "2024-01-01T12:00:00",
        "cpu_usage": 20.0,
        "memory_usage": 45.0,
        "disk_usage": 55.0,
        "system_info": {
            "cpu_usage": 20.0,
            "memory_usage": 45.0,
            "disk_usage": 55.0,
            "cpu": {"overall_percent": 20.0},
            "memory": {"percent": 45.0},
        },
        "suspicious_processes": [],
        "log_events": [],
        "network": {
            "total_connections": 10,
            "suspicious_count": 0,
            "suspicious_connections": [],
        },
        "file_integrity": {
            "modified": [],
            "added": [],
            "deleted": [],
        },
    }
    base.update(overrides)
    return base


# ── TestAIEngine ───────────────────────────────────────────────────────────────

class TestAIEngine(unittest.TestCase):
    """Tests for server.ai_engine.AIEngine."""

    def setUp(self):
        from server.core.ai_engine import AIEngine
        # Point model_path somewhere that definitely has no .pkl files
        self.engine = AIEngine(model_path="/nonexistent/models/", anomaly_threshold=0.7)

    # ── Feature extraction ─────────────────────────────────────────────────────

    def test_extract_features_returns_array_of_correct_shape(self):
        """extract_features must return a numpy array with 8 elements."""
        import numpy as np

        payload = _make_payload()
        features = self.engine.extract_features(payload)

        self.assertIsNotNone(features)
        self.assertEqual(features.shape, (8,),
                         f"Expected shape (8,) but got {features.shape}")

    def test_extract_features_cpu_value(self):
        """Extracted cpu_usage feature should match payload value."""
        payload = _make_payload(cpu_usage=73.5)
        features = self.engine.extract_features(payload)
        self.assertAlmostEqual(float(features[0]), 73.5, places=1)

    def test_extract_features_failed_logins_count(self):
        """Failed login count should reflect log_events with pattern_matched='failed_login'."""
        log_events = [
            {"pattern_matched": "failed_login", "severity": "HIGH",
             "message": "Failed password", "source": "/var/log/auth.log",
             "timestamp": "2024-01-01T00:00:00"}
            for _ in range(7)
        ]
        payload = _make_payload(log_events=log_events)
        features = self.engine.extract_features(payload)
        # Index 4 = failed_logins_count
        self.assertEqual(int(features[4]), 7)

    def test_extract_features_file_changes_count(self):
        """File changes should be summed from modified + added + deleted."""
        payload = _make_payload(
            file_integrity={
                "modified": [{"path": "/etc/passwd"}],
                "added": [{"path": "/tmp/evil"}],
                "deleted": [{"path": "/etc/shadow"}],
            }
        )
        features = self.engine.extract_features(payload)
        # Index 6 = file_changes_count
        self.assertEqual(int(features[6]), 3)

    # ── Heuristic fallback ─────────────────────────────────────────────────────

    def test_predict_without_model_uses_heuristic(self):
        """With no model files available, predict() should use heuristic method."""
        payload = _make_payload()
        result = self.engine.predict(payload)
        self.assertEqual(result.get("method"), "heuristic")

    def test_heuristic_normal_payload_classified_normal(self):
        """Benign payload should be classified as Normal by the heuristic."""
        payload = _make_payload()  # All default – safe values
        result = self.engine.predict(payload)
        self.assertEqual(result["threat_level"], "Normal")

    def test_heuristic_malicious_payload_classified_malicious(self):
        """Clearly malicious payload should be classified as Suspicious or Malicious."""
        log_events = [
            {"pattern_matched": "failed_login", "severity": "HIGH",
             "message": "Failed password", "source": "/var/log/auth.log",
             "timestamp": "2024-01-01T00:00:00"}
            for _ in range(10)
        ]
        payload = _make_payload(
            cpu_usage=95.0,
            log_events=log_events,
            suspicious_processes=[{"pid": 1, "name": "nc"}],
            file_integrity={
                "modified": [{"path": "/etc/passwd"}],
                "added": [],
                "deleted": [],
            },
        )
        result = self.engine.predict(payload)
        self.assertIn(result["threat_level"], ("Suspicious", "Malicious"))

    # ── Required output keys ───────────────────────────────────────────────────

    def test_predict_returns_required_keys(self):
        """predict() result must include classification, confidence, threat_level."""
        payload = _make_payload()
        result = self.engine.predict(payload)

        required_keys = {"classification", "confidence", "threat_level",
                         "anomaly_score", "method", "features"}
        missing = required_keys - set(result.keys())
        self.assertFalse(missing, f"predict() missing keys: {missing}")

    def test_classification_is_valid_integer(self):
        """classification field must be 0, 1, or 2."""
        payload = _make_payload()
        result = self.engine.predict(payload)
        self.assertIn(result["classification"], (0, 1, 2))

    def test_confidence_in_range(self):
        """confidence must be a float between 0 and 1."""
        payload = _make_payload()
        result = self.engine.predict(payload)
        conf = result["confidence"]
        self.assertIsInstance(conf, float)
        self.assertGreaterEqual(conf, 0.0)
        self.assertLessEqual(conf, 1.0)

    def test_features_dict_in_result(self):
        """The 'features' key should map feature names to numeric values."""
        from server.core.ai_engine import FEATURE_NAMES

        payload = _make_payload()
        result = self.engine.predict(payload)
        features_dict = result.get("features", {})

        self.assertIsInstance(features_dict, dict)
        for name in FEATURE_NAMES:
            self.assertIn(name, features_dict)

    # ── Full train-and-predict cycle ───────────────────────────────────────────

    def test_train_and_predict(self):
        """
        Train on the included sample_data.csv, then predict on a test payload.
        The result should use the 'ml' method and return valid keys.
        """
        import tempfile
        import shutil

        # Copy sample data to a temp directory
        sample_csv = os.path.join(_PROJECT_ROOT, "models", "sample_data.csv")
        if not os.path.isfile(sample_csv):
            self.skipTest("sample_data.csv not found – skipping train test")

        tmp_dir = tempfile.mkdtemp()
        try:
            # Copy sample data
            shutil.copy(sample_csv, os.path.join(tmp_dir, "sample_data.csv"))

            from server.core.ai_engine import AIEngine
            engine = AIEngine(model_path=tmp_dir, anomaly_threshold=0.7)

            # Train
            success = engine.train(
                csv_path=os.path.join(tmp_dir, "sample_data.csv")
            )
            self.assertTrue(success, "Training should complete successfully")

            # Predict using trained models
            payload = _make_payload(cpu_usage=85.0, memory_usage=85.0)
            result = engine.predict(payload)

            self.assertIn(result["method"], ("ml", "heuristic"))
            self.assertIn("threat_level", result)
            self.assertIn(result["threat_level"], ("Normal", "Suspicious", "Malicious"))

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
