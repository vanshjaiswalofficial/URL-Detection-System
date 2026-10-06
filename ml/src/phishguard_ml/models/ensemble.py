"""Ensemble architecture combining LightGBM (M2) and Char-CNN (M3) predictions.

Implements ARCHITECTURE.md §7 and TASK T3.2:
- Combines tabular engineered features model (M2) with raw character deep model (M3).
- Supports logistic stacking and weighted probability blending.
- Serializes ensemble weights and configuration to JSON without pickle.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np


class EnsembleModel:
    """Ensemble combiner for tabular (M2) and sequence (M3) models."""

    def __init__(
        self,
        weight_lgbm: float = 0.5,
        weight_cnn: float = 0.5,
        bias: float = 0.0,
        mode: str = "blend",
    ) -> None:
        self.weight_lgbm = weight_lgbm
        self.weight_cnn = weight_cnn
        self.bias = bias
        self.mode = mode

    def fit_stacking(
        self,
        p_lgbm: np.ndarray,
        p_cnn: np.ndarray,
        y_true: np.ndarray,
    ) -> EnsembleModel:
        """Fit logistic stacking weights on validation predictions."""
        from sklearn.linear_model import LogisticRegression

        # Feature matrix of model predictions
        X = np.column_stack([np.asarray(p_lgbm, dtype=float), np.asarray(p_cnn, dtype=float)])
        y = np.asarray(y_true, dtype=int)

        lr = LogisticRegression(C=1.0, max_iter=200, random_state=42)
        lr.fit(X, y)

        self.weight_lgbm = float(lr.coef_[0][0])
        self.weight_cnn = float(lr.coef_[0][1])
        self.bias = float(lr.intercept_[0])
        self.mode = "stack"
        return self

    def fit_blend(
        self,
        p_lgbm: np.ndarray,
        p_cnn: np.ndarray,
        y_true: np.ndarray,
    ) -> EnsembleModel:
        """Find optimal blending weights w_lgbm, w_cnn via grid search on val PR-AUC."""
        from sklearn.metrics import average_precision_score

        best_score = -1.0
        best_w = 0.5

        for w in np.linspace(0.0, 1.0, 21):
            blended = w * p_lgbm + (1.0 - w) * p_cnn
            score = float(average_precision_score(y_true, blended))
            if score > best_score:
                best_score = score
                best_w = float(w)

        self.weight_lgbm = best_w
        self.weight_cnn = 1.0 - best_w
        self.bias = 0.0
        self.mode = "blend"
        return self

    def predict_proba(self, p_lgbm: np.ndarray, p_cnn: np.ndarray) -> np.ndarray:
        """Generate ensemble prediction probabilities."""
        p1 = np.asarray(p_lgbm, dtype=float)
        p2 = np.asarray(p_cnn, dtype=float)

        if self.mode == "stack":
            # Logistic regression linear combination
            logits = self.weight_lgbm * p1 + self.weight_cnn * p2 + self.bias
            # Sigmoid activation
            probs = 1.0 / (1.0 + np.exp(-np.clip(logits, -20.0, 20.0)))
            return np.clip(probs, 0.0, 1.0)
        else:
            w_total = self.weight_lgbm + self.weight_cnn
            blended = (self.weight_lgbm * p1 + self.weight_cnn * p2) / max(w_total, 1e-6)
            return np.clip(blended, 0.0, 1.0)

    def to_dict(self) -> dict[str, Any]:
        """Convert ensemble parameters to dictionary."""
        return {
            "mode": self.mode,
            "weight_lgbm": round(self.weight_lgbm, 6),
            "weight_cnn": round(self.weight_cnn, 6),
            "bias": round(self.bias, 6),
        }

    def to_json(self) -> str:
        """Serialize ensemble parameters to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnsembleModel:
        """Construct ensemble from dictionary."""
        return cls(
            weight_lgbm=float(data.get("weight_lgbm", 0.5)),
            weight_cnn=float(data.get("weight_cnn", 0.5)),
            bias=float(data.get("bias", 0.0)),
            mode=str(data.get("mode", "blend")),
        )

    @classmethod
    def from_json(cls, json_str: str) -> EnsembleModel:
        """Construct ensemble from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def save(self, file_path: Path | str) -> None:
        """Save ensemble configuration to JSON file."""
        p = Path(file_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    @classmethod
    def load(cls, file_path: Path | str) -> EnsembleModel:
        """Load ensemble configuration from JSON file."""
        with open(file_path, encoding="utf-8") as f:
            return cls.from_json(f.read())
