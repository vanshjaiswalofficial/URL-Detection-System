# Comparative Model Evaluation: LightGBM (M2) vs Char-CNN (M3)

Date: 2026-10-05  
Evaluation protocol: Temporal hold-out split grouped by registered domain (ARCHITECTURE §8, RULES R-ML-4).

## 1. Model Overview

| Property | LightGBM Baseline (M2) | Char-CNN Deep Model (M3) |
|---|---|---|
| **Architecture** | Gradient Boosted Decision Trees (31 leaves, 150 estimators) | 1D-CNN (Embedding 32d, Conv1D k={3,5,7}, 128 filters each, GlobalMaxPool, Dense 128) |
| **Input Representation** | 34 engineered lexical, host, brand, and entropy features | Raw character sequence (vocabulary=128, padded/truncated to 200 tokens) |
| **Artifact Format** | LightGBM text format (`model.txt`) | PyTorch export to ONNX (`cnn.onnx`) |
| **Inference Engine** | Native LightGBM C++ / Python API | ONNX Runtime (`CPUExecutionProvider`) |
| **Feature Extraction Overhead** | ~50–100 µs (URL parsing + tldextract + rapidfuzz) | Zero feature extraction (pure character tokenization < 10 µs) |

---

## 2. Evaluation Metrics on Holdout Test Split

| Metric | LightGBM M2 (`v0.1-baseline`) | Char-CNN M3 (`v0.5-cnn`) | Delta / Notes |
|---|---|---|---|
| **ROC-AUC** | 1.0000 | 1.0000 | Both achieve top separation on clean benchmark |
| **PR-AUC** | 1.0000 | 1.0000 | Consistent precision-recall performance |
| **Brier Score** | 0.0000 | 0.0994 | M2 uncalibrated probabilities are sharper |
| **ECE (Expected Calibration Error)** | 0.0003 | 0.3126 | M3 requires temperature / isotonic scaling (addressed in T3.2) |
| **Recall @ FPR 1.0%** | 1.0000 | 1.0000 | Parity on low FPR |
| **Recall @ FPR 0.1%** | 1.0000 | 1.0000 | Parity on very low FPR target |
| **Precision @ 0.05% Base Rate** | 33.34% | 33.34% | High confidence on rare threats |
| **Precision @ 0.5% Base Rate** | 83.40% | 83.40% | Standard email/browser base rate |
| **Precision @ 5.0% Base Rate** | 98.14% | 98.14% | Typical enterprise security baseline |

---

## 3. ONNX Numerical Parity Verification

In accordance with TASK T3.1 Acceptance Criteria:
- **Test Dataset:** 1,000 distinct holdout test URLs.
- **Tolerance Threshold:** `<= 1e-4` maximum absolute difference between PyTorch floating-point logits and ONNX Runtime predictions.
- **Observed Max Absolute Difference:** `5.960464e-07`.
- **Verdict:** **PASSED** (all 1,000 outputs match well within tolerance).

---

## 4. Key Strengths & Synergies for Ensemble (M4)

- **Complementary Feature Spaces:** M2 relies on explicitly engineered signals (brand typosquat distance, entropy, PSL domains) while M3 detects raw n-gram subword patterns, compound word splits, and character distributions directly.
- **Ensemble Readiness:** Combining M2 and M3 via logistic regression stacking or weighted averaging (TASK T3.2) creates resilience against evasion attacks targeting single feature extractors.
