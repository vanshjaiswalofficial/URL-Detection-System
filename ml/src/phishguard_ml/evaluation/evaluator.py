"""Comprehensive evaluation harness for PhishGuard AI.

Implements ARCHITECTURE.md §8 and RULES R-ML-4:
- ROC-AUC, PR-AUC, Brier score
- Recall at target FPR levels (1.0%, 0.1%, 0.01%)
- Precision at real-world base rates (0.05%, 0.5%, 5.0%)
- Expected Calibration Error (ECE)
- Optimal threshold calibration based on FPR budget
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import numpy as np
from sklearn.metrics import (
    auc,
    brier_score_loss,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)


@dataclass(frozen=True)
class EvaluationReport:
    roc_auc: float
    pr_auc: float
    brier_score: float
    ece: float
    recall_at_fpr_1pct: float
    recall_at_fpr_0_1pct: float
    recall_at_fpr_0_01pct: float
    precision_at_base_rate_0_05pct: float
    precision_at_base_rate_0_5pct: float
    precision_at_base_rate_5pct: float
    threshold_at_fpr_1pct: float
    threshold_at_fpr_0_1pct: float


def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
    """Calculate Expected Calibration Error (ECE)."""
    bin_limits = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = len(y_true)

    for i in range(n_bins):
        bin_low = bin_limits[i]
        bin_high = bin_limits[i + 1]
        mask = (y_prob >= bin_low) & (y_prob < bin_high if i < n_bins - 1 else y_prob <= bin_high)
        bin_count = np.sum(mask)

        if bin_count > 0:
            bin_acc = np.mean(y_true[mask])
            bin_conf = np.mean(y_prob[mask])
            ece += (bin_count / n) * abs(bin_acc - bin_conf)

    return round(float(ece), 4)


def compute_recall_at_fpr(
    fpr_arr: np.ndarray,
    tpr_arr: np.ndarray,
    thresholds: np.ndarray,
    target_fpr: float,
) -> tuple[float, float]:
    """Find recall (TPR) and score threshold corresponding to a target FPR budget."""
    idx = np.where(fpr_arr <= target_fpr)[0]
    if len(idx) == 0:
        return 0.0, 1.0
    best_idx = idx[-1]
    recall = float(tpr_arr[best_idx])
    thresh = float(thresholds[best_idx]) if best_idx < len(thresholds) else 1.0
    return round(recall, 4), round(thresh, 4)


def compute_base_rate_precision(tpr: float, fpr: float, base_rate: float) -> float:
    """Compute deployment precision at a real-world base rate pi.

    Formula: Precision = (TPR * pi) / (TPR * pi + FPR * (1 - pi))
    """
    numerator = tpr * base_rate
    denominator = numerator + (fpr * (1.0 - base_rate))
    if denominator <= 0:
        return 0.0
    return round(float(numerator / denominator), 4)


def evaluate_predictions(y_true: np.ndarray, y_prob: np.ndarray) -> EvaluationReport:
    """Compute all mandatory PhishGuard evaluation metrics."""
    y_true_arr = np.asarray(y_true, dtype=int)
    y_prob_arr = np.clip(np.asarray(y_prob, dtype=float), 0.0, 1.0)

    # ROC and PR curves
    fpr_arr, tpr_arr, roc_thresholds = roc_curve(y_true_arr, y_prob_arr)
    roc_auc_val = float(roc_auc_score(y_true_arr, y_prob_arr))

    prec_arr, rec_arr, _ = precision_recall_curve(y_true_arr, y_prob_arr)
    pr_auc_val = float(auc(rec_arr, prec_arr))

    brier = round(float(brier_score_loss(y_true_arr, y_prob_arr)), 4)
    ece_val = compute_ece(y_true_arr, y_prob_arr)

    # Recalls at FPR targets
    rec_1pct, thresh_1pct = compute_recall_at_fpr(fpr_arr, tpr_arr, roc_thresholds, 0.01)
    rec_0_1pct, thresh_0_1pct = compute_recall_at_fpr(fpr_arr, tpr_arr, roc_thresholds, 0.001)
    rec_0_01pct, _ = compute_recall_at_fpr(fpr_arr, tpr_arr, roc_thresholds, 0.0001)

    # Precision at realistic base rates (using the FPR 0.1% operating point)
    p_0_05 = compute_base_rate_precision(rec_0_1pct, 0.001, 0.0005)
    p_0_5 = compute_base_rate_precision(rec_0_1pct, 0.001, 0.005)
    p_5 = compute_base_rate_precision(rec_0_1pct, 0.001, 0.05)

    return EvaluationReport(
        roc_auc=round(roc_auc_val, 4),
        pr_auc=round(pr_auc_val, 4),
        brier_score=brier,
        ece=ece_val,
        recall_at_fpr_1pct=rec_1pct,
        recall_at_fpr_0_1pct=rec_0_1pct,
        recall_at_fpr_0_01pct=rec_0_01pct,
        precision_at_base_rate_0_05pct=p_0_05,
        precision_at_base_rate_0_5pct=p_0_5,
        precision_at_base_rate_5pct=p_5,
        threshold_at_fpr_1pct=thresh_1pct,
        threshold_at_fpr_0_1pct=thresh_0_1pct,
    )


def report_to_dict(report: EvaluationReport) -> dict[str, float]:
    return asdict(report)
