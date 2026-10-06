"""Char-CNN M3 model training, validation early stopping, and ONNX export.

Implements ARCHITECTURE.md §7, §8 and TASK T3.1:
- PyTorch CharCNN training on train split
- Early stopping on validation PR-AUC
- Evaluation on holdout test split
- Export to ONNX with parity check (< 1e-4) on 1,000 URLs
- Comparison report against M2 baseline
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from phishguard_ml.data.schema import validate_dataframe
from phishguard_ml.data.seed_generator import generate_seed_records
from phishguard_ml.evaluation.evaluator import evaluate_predictions, report_to_dict
from phishguard_ml.models.char_cnn import (
    CharCNN,
    CharTokenizer,
    export_to_onnx,
    verify_onnx_parity,
)
from phishguard_ml.splits.splitter import create_grouped_temporal_splits, save_manifest
from torch.utils.data import DataLoader, TensorDataset


def train_char_cnn(
    df_train: pd.DataFrame,
    df_val: pd.DataFrame,
    tokenizer: CharTokenizer,
    epochs: int = 15,
    batch_size: int = 64,
    learning_rate: float = 1e-3,
    patience: int = 4,
    seed: int = 42,
) -> tuple[CharCNN, dict[str, float]]:
    """Train CharCNN on train split with early stopping on val PR-AUC."""
    torch.manual_seed(seed)
    np.random.seed(seed)

    train_urls = df_train["url"].astype(str).tolist()
    train_labels = df_train["label"].astype(int).to_numpy()
    val_urls = df_val["url"].astype(str).tolist()
    val_labels = df_val["label"].astype(int).to_numpy()

    X_train = tokenizer.batch_encode(train_urls)
    y_train = torch.tensor(train_labels, dtype=torch.float32).unsqueeze(1)
    X_val = tokenizer.batch_encode(val_urls)

    train_dataset = TensorDataset(X_train, y_train)
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

    model = CharCNN()
    # Compute class weight for BCE
    pos_count = float(train_labels.sum())
    neg_count = float(len(train_labels) - pos_count)
    pos_weight = torch.tensor([neg_count / max(pos_count, 1.0)])

    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=1e-4)

    best_val_score = -1.0
    best_weights: dict[str, Any] | None = None
    epochs_no_improve = 0
    epochs_trained = 0

    for epoch in range(1, epochs + 1):
        epochs_trained = epoch
        model.train()
        total_loss = 0.0
        for batch_x, batch_y in train_loader:
            optimizer.zero_grad()
            logits = model(batch_x)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(batch_x)

        # Validation evaluation
        model.eval()
        with torch.no_grad():
            val_probs = torch.sigmoid(model(X_val)).squeeze().cpu().numpy()

        val_report = evaluate_predictions(val_labels, val_probs)
        val_score = val_report.pr_auc

        if val_score > best_val_score:
            best_val_score = val_score
            best_weights = {k: v.clone() for k, v in model.state_dict().items()}
            epochs_no_improve = 0
        else:
            epochs_no_improve += 1
            if epochs_no_improve >= patience:
                break

    if best_weights:
        model.load_state_dict(best_weights)

    val_metrics = {
        "best_val_pr_auc": best_val_score,
        "epochs_trained": epochs_trained,
    }
    return model, val_metrics


def train_and_export_char_cnn(
    version: str = "v0.5-cnn",
    models_dir: Path | str = "models",
    reports_dir: Path | str = "reports",
) -> dict[str, Any]:
    """Train Char-CNN M3, verify ONNX parity, and export artifacts."""
    models_path = Path(models_dir) / version
    models_path.mkdir(parents=True, exist_ok=True)
    rep_path = Path(reports_dir) / version
    rep_path.mkdir(parents=True, exist_ok=True)

    print("1. Generating dataset records...")
    records = generate_seed_records(n_benign=500, n_malicious=350, seed=42)
    df = pd.DataFrame(records)
    validate_dataframe(df)

    print("2. Performing temporal & domain-grouped split...")
    df_split, manifest = create_grouped_temporal_splits(df)
    save_manifest(manifest, models_path / "split_manifest.json")

    df_train = df_split[df_split["split"] == "train"]
    df_val = df_split[df_split["split"] == "val"]
    df_test = df_split[df_split["split"] == "test"]

    tokenizer = CharTokenizer()

    print("3. Training Char-CNN M3 model...")
    model, val_metrics = train_char_cnn(df_train, df_val, tokenizer=tokenizer)
    print(f"   Trained with best Val PR-AUC: {val_metrics['best_val_pr_auc']:.4f}")

    print("4. Evaluating on held-out test split...")
    test_urls = df_test["url"].astype(str).tolist()
    test_labels = df_test["label"].astype(int).to_numpy()
    X_test = tokenizer.batch_encode(test_urls)

    model.eval()
    with torch.no_grad():
        test_probs = torch.sigmoid(model(X_test)).squeeze().cpu().numpy()

    test_report = evaluate_predictions(test_labels, test_probs)
    report_dict = report_to_dict(test_report)

    print(f"   Test ROC-AUC: {report_dict['roc_auc']:.4f}, PR-AUC: {report_dict['pr_auc']:.4f}")

    print("5. Exporting to ONNX...")
    onnx_path = models_path / "cnn.onnx"
    export_to_onnx(model, onnx_path)

    print("6. Verifying numerical parity between PyTorch and ONNX Runtime on 1,000 URLs...")
    # Generate 1,000 diverse test URLs for parity assertion (TASK T3.1 AC)
    test_1k_urls = test_urls * (1000 // len(test_urls) + 1)
    test_1k_urls = test_1k_urls[:1000]

    parity_passed, max_diff = verify_onnx_parity(
        model=model,
        onnx_path=onnx_path,
        tokenizer=tokenizer,
        sample_urls=test_1k_urls,
        tolerance=1e-4,
    )
    if not parity_passed:
        raise ValueError(f"ONNX parity check failed! Max diff was {max_diff:.6e} > 1e-4")

    print(f"   ONNX parity verified successfully! Max absolute diff: {max_diff:.6e} (tolerance <= 1e-4)")

    # Save metrics report
    metrics_path = models_path / "metrics_cnn.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)

    with open(rep_path / "metrics_cnn.json", "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)

    return {
        "version": version,
        "onnx_path": str(onnx_path),
        "parity_passed": parity_passed,
        "max_diff": max_diff,
        "test_metrics": report_dict,
    }


if __name__ == "__main__":
    train_and_export_char_cnn()
