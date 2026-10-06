"""JSON-serializable probability calibration and reliability curve analysis.

Implements ARCHITECTURE.md §7, §8, DECISION D-009, and TASK T3.2:
- No pickle: calibrator stored as JSON piecewise-linear breakpoints (x_thresholds, y_values).
- Pure numpy piecewise-linear interpolation with boundary clipping.
- Reliability curve analysis (binned empirical accuracy vs mean predicted confidence).
- Expected Calibration Error (ECE) calculation.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np


class IsotonicCalibrator:
    """Piecewise-linear isotonic probability calibrator.

    Serializes to pure JSON without pickle to adhere to security rule D-009.
    """

    def __init__(
        self,
        x_thresholds: Sequence[float] | None = None,
        y_values: Sequence[float] | None = None,
    ) -> None:
        self.x_thresholds: list[float] = list(x_thresholds) if x_thresholds is not None else [0.0, 1.0]
        self.y_values: list[float] = list(y_values) if y_values is not None else [0.0, 1.0]

    def fit(self, raw_probs: Sequence[float] | np.ndarray, y_true: Sequence[int] | np.ndarray) -> IsotonicCalibrator:
        """Fit isotonic regression on calibration split probabilities."""
        from sklearn.isotonic import IsotonicRegression

        x_arr = np.asarray(raw_probs, dtype=float)
        y_arr = np.asarray(y_true, dtype=int)

        ir = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        ir.fit(x_arr, y_arr)

        # Extract isotonic step/threshold points
        self.x_thresholds = [float(x) for x in ir.X_thresholds_]
        self.y_values = [float(y) for y in ir.y_thresholds_]

        # Ensure endpoints cover [0.0, 1.0]
        if not self.x_thresholds or self.x_thresholds[0] > 0.0:
            self.x_thresholds.insert(0, 0.0)
            self.y_values.insert(0, self.y_values[0] if self.y_values else 0.0)

        if self.x_thresholds[-1] < 1.0:
            self.x_thresholds.append(1.0)
            self.y_values.append(self.y_values[-1] if self.y_values else 1.0)

        return self

    def predict(self, raw_probs: Sequence[float] | np.ndarray | float) -> np.ndarray:
        """Map raw probabilities to calibrated probabilities using linear interpolation."""
        arr = np.clip(np.asarray(raw_probs, dtype=float), 0.0, 1.0)
        calibrated = np.interp(
            arr,
            self.x_thresholds,
            self.y_values,
            left=self.y_values[0],
            right=self.y_values[-1],
        )
        return np.clip(calibrated, 0.0, 1.0)

    def to_dict(self) -> dict[str, Any]:
        """Convert calibrator state to dictionary for JSON export."""
        return {
            "method": "isotonic_piecewise_linear",
            "x_thresholds": [round(x, 6) for x in self.x_thresholds],
            "y_values": [round(y, 6) for y in self.y_values],
            "n_points": len(self.x_thresholds),
        }

    def to_json(self) -> str:
        """Serialize calibrator to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IsotonicCalibrator:
        """Reconstruct calibrator from dictionary."""
        return cls(
            x_thresholds=data.get("x_thresholds", [0.0, 1.0]),
            y_values=data.get("y_values", [0.0, 1.0]),
        )

    @classmethod
    def from_json(cls, json_str: str) -> IsotonicCalibrator:
        """Reconstruct calibrator from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def save(self, file_path: Path | str) -> None:
        """Save calibrator JSON file."""
        p = Path(file_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    @classmethod
    def load(cls, file_path: Path | str) -> IsotonicCalibrator:
        """Load calibrator from JSON file."""
        with open(file_path, encoding="utf-8") as f:
            return cls.from_json(f.read())


def compute_reliability_curve(
    y_true: Sequence[int] | np.ndarray,
    y_prob: Sequence[float] | np.ndarray,
    n_bins: int = 10,
) -> dict[str, Any]:
    """Compute reliability diagram bins (mean confidence vs empirical accuracy).

    Returns:
        Dictionary with bin edges, mean predicted confidence, empirical accuracy,
        sample count per bin, and Expected Calibration Error (ECE).
    """
    y_t = np.asarray(y_true, dtype=int)
    y_p = np.clip(np.asarray(y_prob, dtype=float), 0.0, 1.0)
    total_samples = len(y_t)

    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    confidences: list[float] = []
    accuracies: list[float] = []
    bin_counts: list[int] = []
    ece = 0.0

    for i in range(n_bins):
        low, high = bin_edges[i], bin_edges[i + 1]
        mask = (y_p >= low) & (y_p < high if i < n_bins - 1 else y_p <= high)
        count = int(np.sum(mask))
        bin_counts.append(count)

        if count > 0:
            bin_acc = float(np.mean(y_t[mask]))
            bin_conf = float(np.mean(y_p[mask]))
            confidences.append(round(bin_conf, 4))
            accuracies.append(round(bin_acc, 4))
            ece += (count / total_samples) * abs(bin_acc - bin_conf)
        else:
            confidences.append(round((low + high) / 2.0, 4))
            accuracies.append(0.0)

    return {
        "n_bins": n_bins,
        "bin_edges": [round(float(b), 4) for b in bin_edges],
        "confidences": confidences,
        "accuracies": accuracies,
        "counts": bin_counts,
        "ece": round(float(ece), 4),
    }
