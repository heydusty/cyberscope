"""
CyberScope — Anomaly Detector
Uses Isolation Forest for unsupervised anomaly detection in logs.

Author: Dusty (Akshat Singh Mehrotra)
GitHub: https://github.com/YOUR_USERNAME/cyberscope
License: MIT
© 2026 Dusty — Built by DUSTY | dusty@dustyhive.com
"""

import os
import pickle
import json
import numpy as np
from typing import List, Dict, Tuple

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.feature_extractor import (
    extract_features_from_entries,
    features_to_matrix,
    get_feature_names,
)


class AnomalyDetector:
    """Isolation Forest-based log anomaly detector."""
    
    def __init__(self, contamination=0.05, n_estimators=200, random_state=42):
        """
        Initialize detector.
        
        Args:
            contamination: Expected proportion of anomalies (0.01 to 0.5)
            n_estimators: Number of trees in the forest
            random_state: Random seed for reproducibility
        """
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples="auto",
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.feature_names = get_feature_names()
    
    def fit_predict(self, entries: List[Dict]) -> List[Dict]:
        """
        Extract features, fit the model, and predict anomalies.
        
        Args:
            entries: List of parsed log entry dictionaries
            
        Returns:
            List of feature dicts with anomaly scores and labels
        """
        # Extract features
        features_list = extract_features_from_entries(entries)
        
        if len(features_list) < 10:
            raise ValueError("Need at least 10 log entries for anomaly detection.")
        
        # Convert to matrix
        X = np.array(features_to_matrix(features_list))
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Fit and predict
        predictions = self.model.fit_predict(X_scaled)  # -1 = anomaly, 1 = normal
        scores = self.model.decision_function(X_scaled)  # Lower = more anomalous
        
        self.is_fitted = True
        
        # Attach results to feature dicts
        for i, feat in enumerate(features_list):
            feat["anomaly_label"] = int(predictions[i] == -1)  # 1 = anomaly
            feat["anomaly_score"] = round(float(scores[i]), 4)
            feat["severity"] = self._classify_severity(scores[i])
        
        return features_list
    
    def _classify_severity(self, score: float) -> str:
        """Classify anomaly severity based on score."""
        if score < -0.4:
            return "CRITICAL"
        elif score < -0.2:
            return "HIGH"
        elif score < -0.1:
            return "MEDIUM"
        elif score < 0:
            return "LOW"
        return "NORMAL"
    
    def get_anomalies(self, results: List[Dict], min_severity: str = "LOW") -> List[Dict]:
        """Filter results to only anomalies at or above given severity."""
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NORMAL": 0}
        min_level = severity_order.get(min_severity, 1)
        
        anomalies = [
            r for r in results
            if r.get("anomaly_label") == 1
            and severity_order.get(r.get("severity", "NORMAL"), 0) >= min_level
        ]
        
        # Sort by anomaly score (most anomalous first)
        anomalies.sort(key=lambda x: x.get("anomaly_score", 0))
        
        return anomalies
    
    def get_stats(self, results: List[Dict]) -> Dict:
        """Get summary statistics from detection results."""
        total = len(results)
        anomalies = sum(1 for r in results if r.get("anomaly_label") == 1)
        
        severity_counts = {}
        for r in results:
            sev = r.get("severity", "NORMAL")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Feature importance (mean absolute contribution)
        feature_importance = {}
        anomaly_entries = [r for r in results if r.get("anomaly_label") == 1]
        normal_entries = [r for r in results if r.get("anomaly_label") == 0]
        
        if anomaly_entries and normal_entries:
            for fname in self.feature_names:
                try:
                    anom_vals = [float(r.get(fname, 0)) for r in anomaly_entries]
                    norm_vals = [float(r.get(fname, 0)) for r in normal_entries]
                    anom_mean = np.mean(anom_vals)
                    norm_mean = np.mean(norm_vals)
                    norm_std = np.std(norm_vals) or 1
                    feature_importance[fname] = round(abs(anom_mean - norm_mean) / norm_std, 4)
                except (ValueError, TypeError):
                    feature_importance[fname] = 0.0
        
        # Sort by importance
        top_features = sorted(
            feature_importance.items(), key=lambda x: x[1], reverse=True
        )[:10]
        
        return {
            "total_entries": total,
            "anomalies_detected": anomalies,
            "anomaly_rate": round(anomalies / max(total, 1) * 100, 2),
            "severity_breakdown": severity_counts,
            "top_contributing_features": top_features,
        }
    
    def save(self, model_dir: str = "models"):
        """Save trained model and scaler."""
        os.makedirs(model_dir, exist_ok=True)
        
        with open(os.path.join(model_dir, "detector_model.pkl"), "wb") as f:
            pickle.dump(self.model, f)
        
        with open(os.path.join(model_dir, "detector_scaler.pkl"), "wb") as f:
            pickle.dump(self.scaler, f)
        
        with open(os.path.join(model_dir, "detector_meta.json"), "w") as f:
            json.dump({
                "tool": "CyberScope — AI Log Anomaly Detector",
                "author": "Dusty (Akshat Singh Mehrotra)",
                "signature": "Built by DUSTY | dusty@dustyhive.com",
                "contamination": self.contamination,
                "feature_names": self.feature_names,
                "n_features": len(self.feature_names),
            }, f, indent=2)
    
    def load(self, model_dir: str = "models"):
        """Load a previously saved model."""
        with open(os.path.join(model_dir, "detector_model.pkl"), "rb") as f:
            self.model = pickle.load(f)
        
        with open(os.path.join(model_dir, "detector_scaler.pkl"), "rb") as f:
            self.scaler = pickle.load(f)
        
        self.is_fitted = True
